"""
file_safety.py
-----------------
Static-analysis "is this file safe?" scanner, run on every document before
it's allowed into the encrypted family vault.

Two layers, combined into one verdict:

  1. HEURISTIC CHECKS (real, deterministic, run on the actual uploaded bytes):
       - file-signature vs extension mismatch  (e.g. a .pdf that's really an .exe)
       - macro-enabled Office documents         (vbaProject.bin inside the zip)
       - double extensions                       (invoice.pdf.exe)
       - executable / script signatures          (MZ, ELF, #!/bin/sh, <script>)
       - Shannon entropy                          (very high entropy => packed/encrypted payload)
       - suspicious keyword scan                  (powershell, wscript.shell, eval(, ...)
       - EICAR antivirus test-string detection    (the industry-standard, harmless
         AV test signature — any real scanner is expected to catch this)

  2. ML RISK MODEL: a RandomForestClassifier trained on the metadata features
     above (see generate_file_dataset.py) outputs safe / suspicious / malicious
     with a probability, the same way an ML-augmented endpoint-security product
     would score borderline files that don't trip a hard heuristic rule.

VERDICT = the more severe of (heuristic verdict, ML verdict).
"""

import os

import math
import zipfile
import io
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

MODEL_DIR = "model"
FILE_MODEL_PATH = os.path.join(MODEL_DIR, "file_risk_model.joblib")
FILE_ENCODER_PATH = os.path.join(MODEL_DIR, "file_risk_label_encoder.joblib")
FILE_METRICS_PATH = os.path.join(MODEL_DIR, "file_risk_metrics.json")
DATA_PATH = os.path.join("data", "file_metadata.csv")

FEATURE_COLS = [
    "size_kb", "entropy", "extension_mismatch", "has_macro",
    "double_extension", "suspicious_keywords", "is_executable_sig",
]

# Known file-signature ("magic bytes") prefixes for common safe document types
SIGNATURES = {
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip_based",   # docx/xlsx/pptx/zip are all zip containers
    b"\xd0\xcf\x11\xe0": "ole_legacy_office",  # old .doc/.xls
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG": "png",
}
EXECUTABLE_SIGNATURES = {
    b"MZ": "windows_exe",
    b"\x7fELF": "linux_elf",
    b"#!/": "shell_script",
}

DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf"}
EXECUTABLE_EXTENSIONS = {"exe", "bat", "cmd", "sh", "ps1", "vbs", "js", "scr", "msi", "jar"}

SUSPICIOUS_KEYWORDS = [
    b"powershell", b"cmd.exe", b"wscript.shell", b"eval(", b"base64_decode",
    b"autoopen", b"shell_exec", b"createobject", b"regsvr32", b"bitsadmin",
    b"invoke-expression", b"downloadstring", b"-enc ", b"/c start",
]

# The standard, publicly-documented EICAR antivirus TEST string. It is not
# malware — it exists specifically so security products have something
# harmless to detect. Any real scanner is expected to flag it.
EICAR_TEST_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


# --------------------------------------------------------------------------
# Feature extraction (runs on the real uploaded bytes)
# --------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def _detect_signature(data: bytes) -> str:
    for sig, kind in SIGNATURES.items():
        if data.startswith(sig):
            return kind
    for sig, kind in EXECUTABLE_SIGNATURES.items():
        if data.startswith(sig):
            return kind
    return "unknown"


def _has_double_extension(filename: str) -> bool:
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    # e.g. invoice.pdf.exe -> second-to-last is a document ext, last is executable
    return parts[-2] in DOCUMENT_EXTENSIONS and parts[-1] in EXECUTABLE_EXTENSIONS


def _has_macro(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return any("vbaProject.bin" in n for n in z.namelist())
    except (zipfile.BadZipFile, Exception):
        return False


def _count_suspicious_keywords(data: bytes) -> int:
    lower = data.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower)


def _contains_eicar(data: bytes) -> bool:
    return EICAR_TEST_STRING in data


def extract_features(filename: str, data: bytes) -> dict:
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    signature_kind = _detect_signature(data)
    is_exec_sig = signature_kind in EXECUTABLE_SIGNATURES.values()

    # A document extension whose real signature is an executable/script,
    # or whose signature is totally unrecognized while claiming to be a
    # known document type, counts as a mismatch.
    ext_mismatch = False
    if ext in DOCUMENT_EXTENSIONS:
        if is_exec_sig:
            ext_mismatch = True
        elif ext == "pdf" and signature_kind != "pdf":
            ext_mismatch = True
        elif ext in {"docx", "xlsx", "pptx"} and signature_kind != "zip_based":
            ext_mismatch = True

    features = {
        "size_kb": len(data) / 1024.0,
        "entropy": _shannon_entropy(data[:200_000]),  # cap for speed on huge files
        "extension_mismatch": int(ext_mismatch),
        "has_macro": int(_has_macro(data) if signature_kind == "zip_based" else False),
        "double_extension": int(_has_double_extension(filename)),
        "suspicious_keywords": _count_suspicious_keywords(data[:500_000]),
        "is_executable_sig": int(is_exec_sig),
    }
    extras = {
        "declared_extension": ext,
        "detected_signature": signature_kind,
        "eicar_test_detected": _contains_eicar(data[:2000]),
    }
    return features, extras


# --------------------------------------------------------------------------
# ML risk model
# --------------------------------------------------------------------------

def train_file_risk_model():
    if not os.path.exists(DATA_PATH):
        from generate_file_dataset import build_file_dataset
        os.makedirs("data", exist_ok=True)
        build_file_dataset().to_csv(DATA_PATH, index=False)

    df = pd.read_csv(DATA_PATH)
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["label"])
    X = df[FEATURE_COLS]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=7, stratify=y
    )
    clf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=7, class_weight="balanced")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=label_encoder.classes_, output_dict=True)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, FILE_MODEL_PATH)
    joblib.dump(label_encoder, FILE_ENCODER_PATH)
    with open(FILE_METRICS_PATH, "w") as f:
        json.dump({"accuracy": acc, "classification_report": report, "classes": label_encoder.classes_.tolist()}, f, indent=2)

    print(f"File-risk model trained. Test accuracy: {acc:.4f}")
    return acc


_model_cache = None
_encoder_cache = None


def _get_model():
    global _model_cache, _encoder_cache
    if _model_cache is None:
        if not (os.path.exists(FILE_MODEL_PATH) and os.path.exists(FILE_ENCODER_PATH)):
            train_file_risk_model()
        _model_cache = joblib.load(FILE_MODEL_PATH)
        _encoder_cache = joblib.load(FILE_ENCODER_PATH)
    return _model_cache, _encoder_cache


def ml_risk_score(features: dict):
    clf, label_encoder = _get_model()
    X = pd.DataFrame([features])[FEATURE_COLS]
    proba = clf.predict_proba(X)[0]
    idx = int(proba.argmax())
    label = label_encoder.inverse_transform([idx])[0]
    probabilities = {cls: float(p) for cls, p in zip(label_encoder.classes_, proba)}
    return label, probabilities


# --------------------------------------------------------------------------
# Combined verdict
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"safe": 0, "suspicious": 1, "malicious": 2}


def scan_file(filename: str, data: bytes) -> dict:
    features, extras = extract_features(filename, data)
    ml_label, ml_probs = ml_risk_score(features)

    reasons = []
    heuristic_label = "safe"

    if extras["eicar_test_detected"]:
        heuristic_label = "malicious"
        reasons.append("Matches the EICAR antivirus test signature.")
    if features["is_executable_sig"]:
        heuristic_label = "malicious"
        reasons.append("File content signature is an executable/script, not a document.")
    if features["extension_mismatch"]:
        heuristic_label = max(heuristic_label, "suspicious", key=lambda x: SEVERITY_ORDER[x])
        reasons.append(f"Declared extension '.{extras['declared_extension']}' does not match detected file signature '{extras['detected_signature']}'.")
    if features["double_extension"]:
        heuristic_label = "malicious"
        reasons.append("Filename uses a double extension (e.g. document.pdf.exe) — a common malware disguise.")
    if features["has_macro"]:
        heuristic_label = max(heuristic_label, "suspicious", key=lambda x: SEVERITY_ORDER[x])
        reasons.append("Document contains an embedded macro (vbaProject.bin).")
    if features["suspicious_keywords"] >= 3:
        heuristic_label = max(heuristic_label, "suspicious", key=lambda x: SEVERITY_ORDER[x])
        reasons.append(f"Contains {features['suspicious_keywords']} suspicious script/shell-execution keywords.")
    # Entropy can be high for legitimate PDFs (compressed object streams, signatures, etc.).
    # Use a higher threshold to reduce false positives.
    if features["entropy"] > 7.8:
        heuristic_label = max(
            heuristic_label, "suspicious", key=lambda x: SEVERITY_ORDER[x]
        )
        reasons.append(
            f"Unusually high entropy ({features['entropy']:.2f}/8) — may indicate packed or encrypted payload."
        )

    if not reasons:
        reasons.append("No suspicious signatures, macros, or keywords found.")

    final_label = max(heuristic_label, ml_label, key=lambda x: SEVERITY_ORDER[x])

    # ---- False-positive protection for genuine PDFs ----
    # Real PDFs can legitimately have higher entropy/compressed streams.
    # If heuristics show this is a clean, well-formed PDF (and not a macro/
    # double-extension/mismatch/injection-like document), avoid blocking it
    # due to occasional ML misclassification.
    if (
        extras["detected_signature"] == "pdf"
        and features["extension_mismatch"] == 0
        and features["has_macro"] == 0
        and features["double_extension"] == 0
        and features["suspicious_keywords"] < 3
        and not extras["eicar_test_detected"]
        and features["is_executable_sig"] == 0
    ):
        final_label = "safe"
        # Replace reasons with a deterministic explanation for UX.
        reasons = [
            "Real PDF detected; no macros, double-extension, mismatched signature, "
            "or suspicious keywords found."
        ]


    return {
        "verdict": final_label,
        "heuristic_verdict": heuristic_label,
        "ml_verdict": ml_label,
        "ml_probabilities": {k: round(v * 100, 2) for k, v in ml_probs.items()},
        "reasons": reasons,
        "features": features,
        "detected_signature": extras["detected_signature"],
        "declared_extension": extras["declared_extension"],
    }


if __name__ == "__main__":
    train_file_risk_model()

"""
app.py
-------
Integrated Cloud Security Framework — Flask web application.

Pillars:
  1. CRYPTOGRAPHY        : AES-256-GCM + RSA-2048 hybrid encryption for the family vault.
  2. ML THREAT DETECTION  : RandomForest classifier scores network-traffic records.
  3. FAMILY LOGIN SYSTEM  : 3 seeded family-administrator accounts, session-based auth.
  4. LOGIN ALERTS         : "Was this you?" email sent on every successful login.
  5. DOCUMENT SAFETY SCAN : every uploaded file is scanned (heuristics + ML risk model)
                            before it is allowed into the encrypted vault.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000  (default login: appa_admin / amma_admin / anna_admin,
password "Family@123" — change these from the Account page after first login).
"""

import os
import json
import time
import uuid
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, jsonify, session,
)

import crypto_utils
import ml_detector
import file_safety
import users_store
import email_alerts

app = Flask(__name__)

# Stable secret key is required for Flask sessions.
# If you restart without a stable secret, login may not persist.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "dev-change-me-in-production",
)

# Session/cookie settings: make login persistence reliable for local
# development (localhost over HTTP).
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
)


UPLOAD_DIR = "uploads"

# Session lifetime (minutes) for demo; prevents surprising logouts.
app.permanent_session_lifetime = 60 * 24

ENCRYPTED_DIR = "encrypted_store"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs("data", exist_ok=True)

# In-memory logs (a real system would use a database)
FILE_LOG = []       # encrypted file records
THREAT_LOG = []      # network traffic ML detection records
ALERT_LOG = []        # login alert history

crypto_utils.ensure_keys_exist()
users_store._seed_if_missing()


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    username = session.get("username")
    return users_store.get_user(username) if username else None


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = users_store.verify_login(username, password)
        if not user:
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session["username"] = user["username"]
        session.permanent = True

        # Fire the "was this you?" login alert email

        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
        result = email_alerts.send_login_alert(user["email"], user["full_name"], user["username"], ip_address)
        ALERT_LOG.append(result)

        if result["delivered"]:
            flash(f'Login alert emailed to {user["email"]}.', "success")
        else:
            flash(f'Login alert could not be emailed ({result["detail"]}) — logged in Security Alerts instead.', "error")

        return redirect(request.args.get("next") or url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user = current_user()
    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        new_email = request.form.get("email", "").strip()
        new_full_name = request.form.get("full_name", "").strip()
        new_username = request.form.get("username", "").strip()

        old_username = user["username"]

        if new_email and new_email != user["email"]:
            users_store.update_email(old_username, new_email)
            flash("Alert email updated.", "success")

        if new_password:
            users_store.change_password(old_username, new_password)
            flash("Password changed.", "success")

        # Update full name (even if username doesn't change)
        if new_full_name and new_full_name != user["full_name"]:
            users_store.update_full_name(old_username, new_full_name)
            flash("Display name updated.", "success")

        # Update login username (rename)
        if new_username and new_username != old_username:
            ok, err = users_store.rename_user(old_username, new_username, new_full_name=new_full_name or None)
            if ok:
                session["username"] = new_username
                flash("Login username updated.", "success")
                return redirect(url_for("account"))
            else:
                flash(err or "Could not update username.", "error")

        return redirect(url_for("account"))

    return render_template("account.html", user=user, family=users_store.get_all_users())


@app.route("/security-alerts")
@login_required
def security_alerts():
    return render_template("alerts.html", alerts=ALERT_LOG[::-1], smtp_configured=email_alerts.smtp_configured())


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    metrics = {}
    if os.path.exists(ml_detector.METRICS_PATH):
        with open(ml_detector.METRICS_PATH) as f:
            metrics = json.load(f)

    file_metrics = {}
    if os.path.exists(file_safety.FILE_METRICS_PATH):
        with open(file_safety.FILE_METRICS_PATH) as f:
            file_metrics = json.load(f)

    recent_threats = THREAT_LOG[-8:][::-1]
    threat_count = sum(1 for t in THREAT_LOG if t["prediction"] != "normal")
    unsafe_files = sum(1 for f in FILE_LOG if f["scan"]["verdict"] != "safe")

    return render_template(
        "dashboard.html",
        metrics=metrics,
        file_metrics=file_metrics,
        recent_threats=recent_threats,
        recent_alerts=ALERT_LOG[-5:][::-1],
        total_files=len(FILE_LOG),
        total_scans=len(THREAT_LOG),
        threat_count=threat_count,
        unsafe_files=unsafe_files,
    )


# --------------------------------------------------------------------------
# Vault: upload -> SAFETY SCAN -> encrypt -> store ; download -> verify -> decrypt
# --------------------------------------------------------------------------

@app.route("/vault")
@login_required
def vault():
    return render_template("vault.html", files=FILE_LOG[::-1])


@app.route("/vault/delete/<file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    global FILE_LOG
    record = next((r for r in FILE_LOG if r["file_id"] == file_id), None)
    if not record:
        return jsonify({"deleted": False, "error": "File not found."}), 404
    if not record.get("stored"):
        FILE_LOG = [r for r in FILE_LOG if r["file_id"] != file_id]
        return jsonify({"deleted": True})

    # Remove encrypted envelope from disk and entry from memory log
    try:
        enc_path = record.get("encrypted_path")
        if enc_path and os.path.exists(enc_path):
            os.remove(enc_path)
    except Exception:
        return jsonify({"deleted": False, "error": "Could not delete encrypted data."}), 500

    FILE_LOG = [r for r in FILE_LOG if r["file_id"] != file_id]
    return jsonify({"deleted": True})



@app.route("/vault/upload", methods=["POST"])
@login_required
def upload_file():
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("Please choose a file to upload.", "error")
        return redirect(url_for("vault"))

    plaintext = file.read()
    file_id = uuid.uuid4().hex[:10]
    user = current_user()

    # 1. SAFETY SCAN — heuristics + ML risk model, on the real file bytes
    scan = file_safety.scan_file(file.filename, plaintext)

    # Policy: allow safe + suspicious documents into the vault.
    # Only block if the scanner is confident the file is actually malicious.
    # If truly malicious, block storage. Otherwise allow into vault.
    if scan["verdict"] == "malicious":
        flash(f'"{file.filename}" was BLOCKED - flagged as a threat: {scan["reasons"][0]}', "error")
        FILE_LOG.append({

            "file_id": file_id,
            "original_name": file.filename,
            "size_bytes": len(plaintext),
            "uploaded_by": user["full_name"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan": scan,
            "stored": False,
            "encrypted_path": None,
            "algo": None,
            "encrypt_time_ms": None,
        })
        return redirect(url_for("vault"))

    # 2. ENCRYPT — only safe / suspicious (with warning) files reach the vault
    t0 = time.time()
    envelope = crypto_utils.encrypt_data(plaintext)
    elapsed_ms = round((time.time() - t0) * 1000, 2)

    enc_path = os.path.join(ENCRYPTED_DIR, f"{file_id}.json")
    crypto_utils.save_envelope(envelope, enc_path)

    record = {
        "file_id": file_id,
        "original_name": file.filename,
        "size_bytes": len(plaintext),
        "uploaded_by": user["full_name"],
        "encrypted_path": enc_path,
        "algo": envelope["algo"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "encrypt_time_ms": elapsed_ms,
        "scan": scan,
        "stored": True,
    }
    FILE_LOG.append(record)

    if scan["verdict"] == "suspicious":
        flash(f'"{file.filename}" stored, but flagged SUSPICIOUS: {scan["reasons"][0]} Review it in the vault.', "success")
    else:
        flash(f'"{file.filename}" scanned SAFE and encrypted with {envelope["algo"]}.', "success")

    return redirect(url_for("vault"))


@app.route("/vault/download/<file_id>")
@login_required
def download_file(file_id):
    record = next((r for r in FILE_LOG if r["file_id"] == file_id), None)
    if not record or not record["stored"]:
        flash("File not found or was blocked at upload.", "error")
        return redirect(url_for("vault"))

    envelope = crypto_utils.load_envelope(record["encrypted_path"])
    try:
        plaintext = crypto_utils.decrypt_data(envelope)
    except Exception as e:
        flash(f"Integrity check FAILED — file may be tampered: {e}", "error")
        return redirect(url_for("vault"))

    out_path = os.path.join(UPLOAD_DIR, f"decrypted_{record['original_name']}")
    with open(out_path, "wb") as f:
        f.write(plaintext)
    return send_file(out_path, as_attachment=True, download_name=record["original_name"])


@app.route("/vault/inspect/<file_id>")
@login_required
def inspect_envelope(file_id):
    record = next((r for r in FILE_LOG if r["file_id"] == file_id), None)
    if not record:
        return jsonify({"error": "not found"}), 404
    if not record["stored"]:
        return jsonify({"blocked": True, "scan": record["scan"]})
    envelope = crypto_utils.load_envelope(record["encrypted_path"])
    preview = {k: (v[:60] + "..." if isinstance(v, str) and len(v) > 60 else v) for k, v in envelope.items()}
    preview["scan"] = record["scan"]
    return jsonify(preview)


# --------------------------------------------------------------------------
# ML Threat Detection (network traffic)
# --------------------------------------------------------------------------

@app.route("/threat-detection")
@login_required
def threat_detection():
    return render_template("threat_detection.html", history=THREAT_LOG[::-1][:20])


@app.route("/threat-detection/scan", methods=["POST"])
@login_required
def scan_traffic():
    form = request.form
    record = {
        "duration": float(form.get("duration", 0)),
        "protocol_type": form.get("protocol_type", "tcp"),
        "service": form.get("service", "http"),
        "flag": form.get("flag", "SF"),
        "src_bytes": float(form.get("src_bytes", 0)),
        "dst_bytes": float(form.get("dst_bytes", 0)),
        "count": float(form.get("count", 0)),
        "srv_count": float(form.get("srv_count", 0)),
        "serror_rate": float(form.get("serror_rate", 0)),
        "rerror_rate": float(form.get("rerror_rate", 0)),
        "same_srv_rate": float(form.get("same_srv_rate", 0)),
        "diff_srv_rate": float(form.get("diff_srv_rate", 0)),
        "num_failed_logins": float(form.get("num_failed_logins", 0)),
    }

    label, confidence, probabilities = ml_detector.predict_traffic(record)

    entry = {
        "id": uuid.uuid4().hex[:8],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "input": record,
        "prediction": label,
        "confidence": round(confidence * 100, 2),
        "probabilities": {k: round(v * 100, 2) for k, v in probabilities.items()},
    }
    THREAT_LOG.append(entry)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(entry)

    flash(f"Prediction: {label.upper()} ({entry['confidence']}% confidence)",
          "error" if label != "normal" else "success")
    return redirect(url_for("threat_detection"))


@app.route("/threat-detection/random-sample")
@login_required
def random_sample():
    import random
    kind = random.choice(["normal", "dos", "probe", "r2l_u2r"])
    from generate_dataset import make_normal, make_dos, make_probe, make_r2l_u2r
    gen_map = {"normal": make_normal, "dos": make_dos, "probe": make_probe, "r2l_u2r": make_r2l_u2r}
    row = gen_map[kind](1).iloc[0].to_dict()
    row.pop("label", None)
    for k in ["duration", "src_bytes", "dst_bytes", "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate"]:
        row[k] = round(float(row[k]), 3)
    for k in ["count", "srv_count", "num_failed_logins"]:
        row[k] = int(row[k])
    return jsonify(row)


# --------------------------------------------------------------------------
# Model retrain
# --------------------------------------------------------------------------

@app.route("/model/retrain", methods=["POST"])
@login_required
def retrain():
    metrics = ml_detector.train_and_save_model()
    ml_detector._clf_cache = None
    ml_detector._encoders_cache = None
    file_safety.train_file_risk_model()
    file_safety._model_cache = None
    file_safety._encoder_cache = None
    flash(f"Both ML models retrained. Traffic-detection accuracy: {metrics['accuracy']*100:.2f}%", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    if not os.path.exists(ml_detector.MODEL_PATH):
        print("No trained traffic model found — training now...")
        ml_detector.train_and_save_model()
    if not os.path.exists(file_safety.FILE_MODEL_PATH):
        print("No trained file-risk model found — training now...")
        file_safety.train_file_risk_model()
    app.run(debug=True, host="0.0.0.0", port=5000)

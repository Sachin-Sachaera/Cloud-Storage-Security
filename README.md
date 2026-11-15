# Cloud-Storage-Security
### Using Cryptography and Machine-Learning-Based Threat Detection

A working Flask application for a college project, combining:

1. **Cryptography** — hybrid **AES-256-GCM + RSA-2048** encryption for a shared
   family cloud vault, with RSA-PSS digital signatures for integrity.
2. **ML network threat detection** — a `RandomForestClassifier` that scores
   simulated network traffic as `normal / dos / probe / r2l_u2r`.
3. **Family administrator login system** — 3 seeded accounts, session-based auth.
4. **Login alerts ("Was this you?")** — a real email is sent on every login
   via SMTP, with a graceful local-log fallback if SMTP isn't configured.
5. **Document safety scanner** — every file uploaded to the vault is scanned
   with static-analysis heuristics + a second ML risk model *before* it's
   allowed to be encrypted and stored.

---

## 1. Setup

```bash
cd cloud_security
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**.

### Default login (3 family administrators)

| Username     | Password     | Represents         |
|--------------|--------------|---------------------|
| `appa_admin` | `Family@123` | Appa (Dad)          |
| `amma_admin` | `Family@123` | Amma (Mom)          |
| `anna_admin` | `Family@123` | Anna (Elder sibling) |

Change passwords and alert emails from **Account** after logging in
(`users_store.py` persists them to `data/users.json`).

> **Demo only:** the seeded accounts and shared default password are for local
> demonstrations only. Do not expose this app to the internet or use these
> credentials for a real service. Set a strong `FLASK_SECRET_KEY` and replace
> the demo authentication setup before any deployment.

### Enabling real email login alerts

By default, login alerts are attempted over SMTP and — if that fails or isn't
configured — recorded in the in-app **Security Alerts** log instead, so the
feature is fully demoable without any setup. To send real emails (e.g. via
Gmail):

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=youraddress@gmail.com
export SMTP_PASSWORD=your16charapppassword   # Gmail App Password, not your login password
python app.py
```

Generate a Gmail App Password at https://myaccount.google.com/apppasswords
(requires 2-Step Verification enabled on the Google account).

## 2. Project Structure

```
cloud_security_project/
├── app.py                     # Flask routes: auth, dashboard, vault, threat detection, alerts
├── crypto_utils.py             # AES-256-GCM + RSA-2048 hybrid encryption
├── ml_detector.py               # Network-traffic RandomForest model
├── file_safety.py                # Document safety scanner: heuristics + ML risk model
├── users_store.py                 # 3 seeded family-administrator accounts (JSON-backed)
├── email_alerts.py                 # SMTP "was this you?" login alert emails
├── generate_dataset.py              # Synthetic network-traffic training data
├── generate_file_dataset.py          # Synthetic file-metadata training data
├── requirements.txt
├── templates/                         # login, account, alerts, dashboard, vault, threat_detection
├── static/style.css
├── data/                                # generated datasets + local user data (not committed)
├── model/                                # trained models + metrics (not committed)
├── keys/                                  # generated RSA keypair (not committed)
├── uploads/                                # temporary decrypted files (not committed)
└── encrypted_store/                         # simulated encrypted storage (not committed)
```

These runtime directories are created as needed and are excluded from Git
because they may contain private keys, account data, or user files.

## 3. How Login + Alerts Work

1. A family member signs in with their username/password (hashed with
   Werkzeug's `generate_password_hash`, never stored in plaintext).
2. A Flask session is created (`login_required` decorator protects every
   other route).
3. `email_alerts.send_login_alert()` immediately emails the account holder:
   *"A login to your CloudGuard account was just detected... If this was
   NOT you, please change your password immediately."*
4. Every attempt (delivered or not) is recorded in `ALERT_LOG` and visible
   on the **Security Alerts** page — so even offline/no-SMTP demos show the
   mechanism working end-to-end.

## 4. How the Document Safety Scanner Works

Every uploaded file goes through two layers **before** it is encrypted:

**Heuristics (deterministic, run on the real file bytes):**
- File-signature vs. declared-extension mismatch (e.g. a `.pdf` that's
  really a Windows executable)
- Embedded Office macros (`vbaProject.bin` inside the zip container)
- Double extensions (`invoice.pdf.exe`)
- Executable/script signatures (`MZ`, `ELF`, `#!/...`)
- Shannon entropy (very high entropy ⇒ possibly packed/encrypted payload)
- Suspicious keyword scan (`powershell`, `wscript.shell`, `eval(`, etc.)
- EICAR antivirus test-string detection (the industry-standard, harmless
  string every real antivirus product is expected to catch)

**ML risk model:** a `RandomForestClassifier` trained on file-metadata
features (`generate_file_dataset.py`) scores borderline files as
`safe / suspicious / malicious` with a probability — for the cases that
don't trip a hard heuristic rule.

**Verdict = the more severe of the two.** `malicious` files are blocked
outright (never encrypted/stored); `suspicious` files are stored but
flagged for review; `safe` files proceed straight to AES-256-GCM + RSA-2048
encryption.

## 5. Why This Combination Matters (for your report)

A family cloud system faces three distinct risks: (1) data theft if storage
is breached, (2) malicious files smuggled in disguised as documents, and
(3) account takeover via stolen credentials. Encryption alone addresses
only the first. This project layers all three defenses — hybrid
cryptography for data-at-rest, an ML+heuristic scanner for the upload path,
and login-alert monitoring for the account-access path — which is the same
"defense in depth" principle real cloud-security products (Google
Workspace, Microsoft 365 Family, etc.) are built around.

## 6. Extending the Project

- Swap `data/users.json` for a real database with more than 3 accounts.
- Add SMS alerts via Twilio (needs a paid account + API keys) alongside
  or instead of email.
- Real malware-hash lookups (VirusTotal API) to complement the local
  EICAR/heuristic checks.
- Per-user vault permissions (e.g. a "kids" role with restricted access).

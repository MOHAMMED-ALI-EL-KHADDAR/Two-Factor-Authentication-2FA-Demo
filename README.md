# Two-Factor Authentication (2FA) Demo

A self-contained, CLI-based demonstration of RFC 6238 Time-based One-Time
Password (TOTP) authentication — the same mechanism used by Google
Authenticator, Authy, 1Password, and most "authenticator app" 2FA flows.

It covers the full lifecycle: enrollment with QR provisioning, encrypted
secret storage, drift-tolerant code verification, brute-force rate
limiting, and single-use emergency backup codes.

> **Educational project.** It demonstrates correct security *patterns*
> but is not hardened for production (see [Production Hardening Notes](#production-hardening-notes)).

---

## How TOTP Actually Works

TOTP (RFC 6238) is built on top of HOTP (RFC 4226, HMAC-based OTP). The
core idea: both the server and the user's device share a secret key,
and both independently derive the *same* one-time code from that secret
plus the current time — without ever transmitting the secret again
after enrollment.

### 1. The shared secret

At enrollment, the server generates a random secret, typically 20 bytes
(160 bits), encoded as Base32 (RFC 4648) so it can be typed or embedded
in a QR code — e.g. `VUPZLNLLXPZWDD62FNNICPX5ISAHHIEP`. This script
generates it with `pyotp.random_base32()`, which uses Python's CSPRNG.

### 2. The moving factor: time steps

Instead of an incrementing counter (as in plain HOTP), TOTP derives a
counter from wall-clock time:

```
T = floor((current_unix_time − T0) / X)
```

Where `X` is the time step (default **30 seconds**) and `T0` is the
Unix epoch (0). `T` is encoded as an 8-byte big-endian integer — this
is the "message" that gets HMAC'd.

### 3. HMAC-SHA1

```
HMAC = HMAC-SHA1(key = shared_secret, message = T)
```

This yields a 20-byte HMAC digest. SHA-1 is used here only as a keyed
MAC (not for collision resistance), which is why it remains acceptable
in this construction even though SHA-1 is broken for general hashing —
this is explicitly addressed in RFC 4226 §7.5. Some implementations
now offer SHA-256/SHA-512 variants for defense-in-depth; `pyotp`
supports this via the `digest=` parameter.

### 4. Dynamic truncation

The 20-byte HMAC is compressed into a 6-digit decimal code:

1. Take the low 4 bits of the last byte of the HMAC as an offset
   `(0–15)`.
2. Read 4 bytes starting at that offset.
3. Mask off the top bit (to avoid sign-bit ambiguity), giving a 31-bit
   integer.
4. Take that integer `mod 10^6` to get a 6-digit code (zero-padded).

This "dynamic truncation" is what makes OTPs short and typeable while
still being derived from the full HMAC output.

### 5. Verification with clock drift tolerance

Because the user's phone clock and the server clock are never
perfectly synchronized, verifiers must tolerate a small drift. This
project checks the **previous, current, and next** 30-second window
(`valid_window=1` in `pyotp`), giving roughly ±30 seconds of tolerance
in each direction while keeping the brute-force search space bounded.

### Why it's phishing-resistant *enough*, but not perfect

TOTP codes are short-lived and can't be replayed after their window
closes, which stops password-database leaks from being immediately
useful. However, TOTP is still vulnerable to **real-time phishing**
(a fake login page that relays your code to the real site instantly).
WebAuthn/FIDO2 (hardware keys, passkeys) closes that gap by binding
credentials to the origin domain — worth mentioning as the modern
evolution of MFA.

---

## Features Implemented

| Feature | Implementation |
|---|---|
| TOTP generation & validation | `pyotp.TOTP`, RFC 6238 compliant, 6 digits / 30s step |
| Clock drift tolerance | `valid_window=1` → accepts prev/current/next step |
| QR code provisioning | `qrcode` — renders ASCII QR in-terminal **and** saves a PNG containing a standard `otpauth://totp/...` URI scannable by any real authenticator app |
| Secret generation | `pyotp.random_base32()` (CSPRNG-backed) |
| Secrets at rest | Encrypted with `cryptography.fernet` (AES-128-CBC + HMAC) using a locally-stored master key (0600 permissions) |
| Backup codes | 10 single-use codes generated at enrollment; only **salted SHA-256 hashes** are stored, never the plaintext codes |
| Single-use enforcement | Each backup code entry has a `used` flag flipped atomically on first successful match |
| Brute-force rate limiting | 5 failed attempts (TOTP *or* backup code) → 60-second lockout per user |
| Secure display | Secret and backup codes are shown once, then the terminal is cleared; never written to any log |

---

## Setup

Requires **Python 3.10+**.

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Run without arguments for an interactive menu:

```bash
python3 main.py
```

Or use subcommands directly:

```bash
# Enroll a new user — generates secret, prints/saves a QR code, and
# shows 10 backup codes (shown once only)
python3 main.py enroll --username alice

# Verify a 6-digit code from an authenticator app
python3 main.py verify --username alice

# Authenticate with a one-time backup code instead
python3 main.py backup --username alice

# Regenerate backup codes (invalidates old ones)
python3 main.py regen-codes --username alice

# List enrolled users, remaining backup codes, and lock status
python3 main.py list

# Delete a user's 2FA enrollment entirely
python3 main.py delete --username alice
```

### Linking a real authenticator app

During `enroll`, scan the printed ASCII QR code (or open the saved
`~/.twofa_demo/qrcodes/<username>.png`) with Google Authenticator,
Authy, or 1Password. The QR encodes a standard
`otpauth://totp/2FA-Demo:alice?secret=...&issuer=2FA-Demo` URI, so any
RFC 6238-compliant app will generate matching codes.

### Where data is stored

```
~/.twofa_demo/
├── vault.json        # per-user encrypted secrets + hashed backup codes (0600)
├── master.key         # Fernet key used to encrypt secrets (0600)
└── qrcodes/<user>.png # provisioning QR images (0600)
```

---

## Security Design Notes

- **Secrets are never logged or printed twice.** The plaintext Base32
  secret and plaintext backup codes are shown exactly once, at
  enrollment, then the terminal is cleared. Only ciphertext (secret)
  or salted hashes (backup codes) persist to disk.
- **Constant-time comparison** (`hmac.compare_digest`) is used when
  matching backup code hashes to avoid timing side-channels.
- **Rate limiting** covers both TOTP and backup-code attempts under a
  single per-user counter, so an attacker can't sidestep lockout by
  switching factors.
- **File permissions**: the data directory, database, master key, and
  QR images are all created with owner-only (`0600`/`0700`)
  permissions.

## Production Hardening Notes

This demo intentionally keeps infrastructure minimal (a local JSON
file) to stay runnable anywhere. A real deployment should additionally:

- Store the master encryption key in a managed KMS/HSM (AWS KMS,
  GCP KMS, HashiCorp Vault) rather than a local file.
- Persist user records in a proper database with encrypted columns
  and audited access, not a flat JSON file.
- Rate-limit by IP/device fingerprint in addition to per-account, and
  add exponential backoff / CAPTCHA for repeated lockouts.
- Add structured, secret-redacting audit logging for enrollment and
  auth events (who, when, success/failure — never the code or secret).
- Consider offering WebAuthn/FIDO2 (passkeys/hardware keys) as a
  phishing-resistant alternative or requirement alongside TOTP.
- Enforce re-authentication before allowing `regen-codes` or `delete`,
  and consider notifying the user out-of-band when either occurs.

---

## Project Structure

```
.
├── main.py            # CLI application (all logic)
├── requirements.txt    # pyotp, qrcode, rich, cryptography
└── README.md           # this file
```

#!/usr/bin/env python3
"""
Two-Factor Authentication (2FA) Demo
=====================================
A production-style CLI demonstrating RFC 6238 (TOTP) two-factor
authentication end to end: enrollment with QR provisioning, encrypted
secret storage, drift-tolerant verification, rate-limited brute-force
protection, and single-use emergency backup codes.

Author: Senior Cybersecurity Engineer / Python Developer (demo)
License: MIT (educational use)

SECURITY NOTE
-------------
This is a learning/demo project. It follows real security patterns
(encryption at rest, hashed backup codes, rate limiting, constant-time
comparisons via pyotp) but a production system should additionally use
a hardened secrets vault/HSM, TLS everywhere, structured audit logging
with PII/secret redaction, and ideally phishing-resistant factors
(WebAuthn/FIDO2) alongside or instead of TOTP.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac as hmac_module
import json
import os
import secrets
import stat
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import importlib
    pyotp = importlib.import_module("pyotp")
    import qrcode
    from cryptography.fernet import Fernet
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:  # pragma: no cover
    print(f"Missing dependency: {exc}\nRun: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
APP_NAME = "2FA-Demo"

DATA_DIR = Path.home() / ".twofa_demo"
DB_FILE = DATA_DIR / "vault.json"
KEY_FILE = DATA_DIR / "master.key"
QR_DIR = DATA_DIR / "qrcodes"

TOTP_DIGITS = 6
TOTP_INTERVAL = 30          # seconds per RFC 6238 default
DRIFT_WINDOWS = 1           # +/- 1 step => accepts previous/current/next (30s each side)

MAX_ATTEMPTS = 5            # failed attempts before lockout
LOCKOUT_SECONDS = 60        # lockout duration once MAX_ATTEMPTS is hit

NUM_BACKUP_CODES = 10
BACKUP_CODE_BYTES = 5       # 5 bytes -> 10 hex chars -> formatted as XXXXX-XXXXX


# --------------------------------------------------------------------------
# Storage helpers
# --------------------------------------------------------------------------
def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, stat.S_IRWXU)  # 700: owner-only


def get_or_create_master_key() -> bytes:
    """Master symmetric key used to encrypt TOTP secrets at rest.

    In production this key belongs in a KMS/HSM/secrets manager, not on
    local disk. Here it is stored with 0600 permissions purely to
    demonstrate the encrypt-at-rest pattern.
    """
    ensure_data_dir()
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    os.chmod(KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 600
    return key


def get_fernet() -> Fernet:
    return Fernet(get_or_create_master_key())


def load_db() -> dict:
    ensure_data_dir()
    if not DB_FILE.exists():
        return {"users": {}}
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_db(db: dict) -> None:
    ensure_data_dir()
    tmp = DB_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    tmp.replace(DB_FILE)
    os.chmod(DB_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 600: owner read/write only


# --------------------------------------------------------------------------
# Backup codes
# --------------------------------------------------------------------------
def generate_backup_codes(n: int = NUM_BACKUP_CODES) -> list[str]:
    """Cryptographically secure, human-typeable backup codes."""
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(BACKUP_CODE_BYTES).upper()
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_backup_code(code: str, salt: str) -> str:
    return hashlib.sha256((salt + code).encode()).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac_module.compare_digest(a, b)


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------
def check_lockout(user: dict) -> Optional[float]:
    """Return seconds remaining if locked out, else None."""
    lockout_until = user.get("lockout_until", 0)
    if lockout_until and time.time() < lockout_until:
        return lockout_until - time.time()
    if lockout_until and time.time() >= lockout_until:
        user["lockout_until"] = 0
        user["failed_attempts"] = 0
    return None


def register_failure(db: dict, user: dict) -> None:
    user["failed_attempts"] = user.get("failed_attempts", 0) + 1
    if user["failed_attempts"] >= MAX_ATTEMPTS:
        user["lockout_until"] = time.time() + LOCKOUT_SECONDS
        user["failed_attempts"] = 0
    save_db(db)


def register_success(db: dict, user: dict) -> None:
    user["failed_attempts"] = 0
    user["lockout_until"] = 0
    save_db(db)


# --------------------------------------------------------------------------
# QR provisioning
# --------------------------------------------------------------------------
def generate_qr(uri: str, username: str) -> Path:
    qr = qrcode.QRCode(border=2)
    qr.add_data(uri)
    qr.make(fit=True)

    console.print("\n[bold cyan]Scan this QR code with Google Authenticator / Authy / 1Password:[/bold cyan]\n")
    qr.print_ascii(invert=True)

    QR_DIR.mkdir(parents=True, exist_ok=True)
    img = qr.make_image(fill_color="black", back_color="white")
    path = QR_DIR / f"{username}.png"
    img.save(path)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    console.print(f"[dim]QR image also saved to: {path}[/dim]\n")
    return path


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_enroll(args: argparse.Namespace) -> None:
    username = args.username or Prompt.ask("Enter a username to enroll")
    db = load_db()

    if username in db["users"]:
        if not Confirm.ask(
            f"[yellow]User '{username}' already exists. Re-enrolling invalidates their old secret "
            f"and backup codes. Continue?[/yellow]"
        ):
            console.print("Aborted.")
            return

    # RFC 4648 base32 secret, generated via a CSPRNG (pyotp uses `secrets` internally)
    secret = pyotp.random_base32()
    encrypted_secret = get_fernet().encrypt(secret.encode()).decode()

    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    uri = totp.provisioning_uri(name=username, issuer_name=APP_NAME)

    console.rule(f"[bold green]Enrolling '{username}'[/bold green]")
    generate_qr(uri, username)

    console.print(
        Panel(
            Text(secret, style="bold yellow"),
            title="[bold red]Secret Key (base32) — shown ONCE[/bold red]",
            subtitle="Only needed if you can't scan the QR code. Store it in a password manager.",
        )
    )
    Prompt.ask("[dim]Press Enter once you've saved the secret/QR to continue[/dim]", default="")
    console.clear()

    backup_codes = generate_backup_codes()
    stored_codes = []
    for code in backup_codes:
        salt = secrets.token_hex(8)
        stored_codes.append({"hash": hash_backup_code(code, salt), "salt": salt, "used": False})

    db["users"][username] = {
        "encrypted_secret": encrypted_secret,
        "backup_codes": stored_codes,
        "failed_attempts": 0,
        "lockout_until": 0,
        "created_at": time.time(),
    }
    save_db(db)

    table = Table(title="Emergency Backup Codes — shown ONCE", show_header=False)
    for code in backup_codes:
        table.add_row(code)
    console.print(table)
    console.print("[bold red]Save these offline (printed/password manager). Each code works only once.[/bold red]\n")
    Prompt.ask("[dim]Press Enter to clear the screen and finish[/dim]", default="")
    console.clear()
    console.print(f"[bold green]Enrollment complete for '{username}'.[/bold green]")


def _load_user(db: dict, username: str) -> Optional[dict]:
    user = db["users"].get(username)
    if not user:
        console.print(f"[red]No such user '{username}'. Enroll first with: enroll --username {username}[/red]")
    return user


def cmd_verify(args: argparse.Namespace) -> None:
    username = args.username or Prompt.ask("Username")
    db = load_db()
    user = _load_user(db, username)
    if not user:
        return

    remaining = check_lockout(user)
    if remaining:
        console.print(f"[bold red]Account locked due to repeated failures. Try again in {int(remaining)}s.[/bold red]")
        return

    secret = get_fernet().decrypt(user["encrypted_secret"].encode()).decode()
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)

    token = Prompt.ask("Enter your 6-digit authenticator code").strip()

    # valid_window=1 checks the previous, current, and next 30s step,
    # i.e. +/-30s of clock drift tolerance either side.
    if token.isdigit() and totp.verify(token, valid_window=DRIFT_WINDOWS):
        register_success(db, user)
        console.print("[bold green]TOTP verified successfully.[/bold green]")
    else:
        register_failure(db, user)
        console.print("[bold red]Invalid code.[/bold red]")
        if user["lockout_until"]:
            console.print(f"[bold red]Too many failures — account locked for {LOCKOUT_SECONDS}s.[/bold red]")
        else:
            console.print(f"[yellow]Attempts remaining before lockout: {MAX_ATTEMPTS - user['failed_attempts']}[/yellow]")


def cmd_backup(args: argparse.Namespace) -> None:
    username = args.username or Prompt.ask("Username")
    db = load_db()
    user = _load_user(db, username)
    if not user:
        return

    remaining = check_lockout(user)
    if remaining:
        console.print(f"[bold red]Account locked. Try again in {int(remaining)}s.[/bold red]")
        return

    code = getpass.getpass("Enter backup code (input hidden): ").strip().upper()

    matched = None
    for entry in user["backup_codes"]:
        if entry["used"]:
            continue
        if constant_time_eq(hash_backup_code(code, entry["salt"]), entry["hash"]):
            matched = entry
            break

    if matched:
        matched["used"] = True  # single-use: invalidate immediately
        register_success(db, user)
        left = sum(1 for e in user["backup_codes"] if not e["used"])
        console.print("[bold green]Backup code accepted and invalidated.[/bold green]")
        console.print(f"[yellow]{left} backup codes remaining.[/yellow]")
        if left == 0:
            console.print("[bold red]No backup codes left — regenerate with the 'regen-codes' command.[/bold red]")
    else:
        register_failure(db, user)
        console.print("[bold red]Invalid or already-used backup code.[/bold red]")


def cmd_regen_codes(args: argparse.Namespace) -> None:
    username = args.username or Prompt.ask("Username")
    db = load_db()
    user = _load_user(db, username)
    if not user:
        return
    if not Confirm.ask("[yellow]This invalidates all existing backup codes. Continue?[/yellow]"):
        return

    backup_codes = generate_backup_codes()
    stored = []
    for code in backup_codes:
        salt = secrets.token_hex(8)
        stored.append({"hash": hash_backup_code(code, salt), "salt": salt, "used": False})
    user["backup_codes"] = stored
    save_db(db)

    table = Table(title="New Emergency Backup Codes — shown ONCE", show_header=False)
    for code in backup_codes:
        table.add_row(code)
    console.print(table)
    Prompt.ask("[dim]Press Enter to clear the screen[/dim]", default="")
    console.clear()
    console.print("[bold green]Backup codes regenerated.[/bold green]")


def cmd_list(args: argparse.Namespace) -> None:
    db = load_db()
    if not db["users"]:
        console.print("[dim]No users enrolled yet.[/dim]")
        return
    table = Table(title="Enrolled Users")
    table.add_column("Username")
    table.add_column("Backup codes left")
    table.add_column("Locked?")
    for uname, u in db["users"].items():
        left = sum(1 for e in u["backup_codes"] if not e["used"])
        locked = "Yes" if check_lockout(u) else "No"
        table.add_row(uname, str(left), locked)
    save_db(db)
    console.print(table)


def cmd_delete(args: argparse.Namespace) -> None:
    username = args.username or Prompt.ask("Username to delete")
    db = load_db()
    if username not in db["users"]:
        console.print(f"[red]No such user '{username}'.[/red]")
        return
    if not Confirm.ask(f"[red]Permanently delete '{username}' and all their 2FA data?[/red]"):
        return
    del db["users"][username]
    save_db(db)
    qr_path = QR_DIR / f"{username}.png"
    if qr_path.exists():
        qr_path.unlink()
    console.print(f"[bold green]Deleted '{username}'.[/bold green]")


# --------------------------------------------------------------------------
# Interactive menu (no subcommand given)
# --------------------------------------------------------------------------
def interactive_menu() -> None:
    console.print(Panel.fit(f"[bold]{APP_NAME}[/bold]\nRFC 6238 TOTP Demo", border_style="cyan"))
    actions = {
        "1": ("Enroll a new user", cmd_enroll),
        "2": ("Verify a TOTP code", cmd_verify),
        "3": ("Verify with a backup code", cmd_backup),
        "4": ("Regenerate backup codes", cmd_regen_codes),
        "5": ("List enrolled users", cmd_list),
        "6": ("Delete a user", cmd_delete),
        "0": ("Exit", None),
    }
    while True:
        console.print()
        for key, (label, _) in actions.items():
            console.print(f"  [bold]{key}[/bold]. {label}")
        choice = Prompt.ask("Choose an option", choices=list(actions.keys()), default="0")
        if choice == "0":
            console.print("Goodbye.")
            return
        _, func = actions[choice]
        ns = argparse.Namespace(username=None)
        try:
            func(ns)
        except Exception as exc:  # keep the menu alive on unexpected errors
            console.print(f"[bold red]Error: {exc}[/bold red]")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} — RFC 6238 TOTP CLI")
    sub = parser.add_subparsers(dest="command")

    for name, func, help_text in [
        ("enroll", cmd_enroll, "Enroll a new user (generates secret, QR, backup codes)"),
        ("verify", cmd_verify, "Verify a 6-digit TOTP code"),
        ("backup", cmd_backup, "Authenticate using a one-time backup code"),
        ("regen-codes", cmd_regen_codes, "Regenerate a user's backup codes"),
        ("list", cmd_list, "List enrolled users"),
        ("delete", cmd_delete, "Delete a user and their 2FA data"),
    ]:
        p = sub.add_parser(name, help=help_text)
        if name != "list":
            p.add_argument("--username", "-u", help="Username to operate on")
        p.set_defaults(func=func)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        interactive_menu()
        return

    args.func(args)


if __name__ == "__main__":
    main()

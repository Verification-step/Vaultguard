#!/usr/bin/env python3
"""VaultGuard - a local privacy vault for files and folders.

This tool deliberately does NOT manipulate Windows Search, registry entries,
file attributes, startup entries, or security software. It protects selected
personal files by encrypting them into a vault archive and can restore them.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("Missing dependency: cryptography")
    print("Install it with: python -m pip install cryptography")
    raise SystemExit(1)

APP_DIR = Path.home() / ".vaultguard"
VAULT_FILE = APP_DIR / "vault.vg"
META_FILE = APP_DIR / "metadata.json"


def key_from_password(password: str, salt: bytes) -> bytes:
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, 32)
    return base64.urlsafe_b64encode(key)


def password(prompt="Vault password: ") -> str:
    value = getpass.getpass(prompt)
    if not value:
        raise SystemExit("Password cannot be empty.")
    return value


def load_meta():
    if not META_FILE.exists():
        raise SystemExit("Vault is not initialized. Run: python vaultguard.py init")
    return json.loads(META_FILE.read_text(encoding="utf-8"))


def init_vault():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    if META_FILE.exists():
        print(f"Vault already initialized at {APP_DIR}")
        return
    p1 = password("Create vault password: ")
    p2 = password("Confirm password: ")
    if p1 != p2:
        raise SystemExit("Passwords do not match.")
    salt = os.urandom(16)
    token = Fernet(key_from_password(p1, salt)).encrypt(b"VaultGuard verification")
    META_FILE.write_text(json.dumps({
        "version": 1,
        "salt": base64.b64encode(salt).decode(),
        "check": token.decode(),
    }, indent=2), encoding="utf-8")
    print(f"Vault initialized: {APP_DIR}")


def make_archive(items, archive_path: Path):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "payload"
        root.mkdir()
        manifest = []
        used_names = set()
        for index, item in enumerate(items, 1):
            src = Path(item).expanduser().resolve()
            if not src.exists():
                print(f"Skipping missing path: {src}")
                continue
            name = src.name or f"item-{index}"
            if name in used_names:
                name = f"{index}-{name}"
            used_names.add(name)
            dest = root / name
            if src.is_dir():
                shutil.copytree(src, dest)
            else:
                shutil.copy2(src, dest)
            manifest.append({"original": str(src), "archive_name": name})

        (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in root.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(root))


def encrypt_file(source: Path, password_value: str):
    meta = load_meta()
    salt = base64.b64decode(meta["salt"])
    f = Fernet(key_from_password(password_value, salt))
    check = f.decrypt(meta["check"].encode())
    if check != b"VaultGuard verification":
        raise SystemExit("Incorrect password.")
    data = source.read_bytes()
    encrypted = f.encrypt(data)
    APP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = VAULT_FILE.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    tmp.replace(VAULT_FILE)


def decrypt_file(password_value: str) -> bytes:
    meta = load_meta()
    salt = base64.b64decode(meta["salt"])
    f = Fernet(key_from_password(password_value, salt))
    try:
        return f.decrypt(VAULT_FILE.read_bytes())
    except (InvalidToken, FileNotFoundError):
        raise SystemExit("Unable to unlock vault: wrong password or missing/corrupt vault.")


def add_items(items):
    if not items:
        raise SystemExit("Provide at least one file or folder path.")
    if VAULT_FILE.exists():
        raise SystemExit("Vault already contains an archive. Unlock/restore it first.")
    p = password()
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        make_archive(items, tmp_path)
        encrypt_file(tmp_path, p)
    finally:
        tmp_path.unlink(missing_ok=True)

    # Delete originals only after the encrypted vault was successfully written.
    meta = []
    for raw in items:
        src = Path(raw).expanduser().resolve()
        if src.exists():
            meta.append(str(src))
            if src.is_dir():
                shutil.rmtree(src)
            else:
                src.unlink()
    (APP_DIR / "restore_paths.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Encrypted vault created: {VAULT_FILE}")
    print("Original selected items were removed after successful encryption.")


def unlock(restore=False):
    if not VAULT_FILE.exists():
        raise SystemExit("No encrypted vault exists.")
    data = decrypt_file(password())
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / "vault.zip"
        archive.write_bytes(data)
        with zipfile.ZipFile(archive) as zf:
            if not zf.testzip() is None:
                raise SystemExit("Vault archive is corrupt.")
            names = zf.namelist()
            manifest = json.loads(zf.read("manifest.json"))
            if not restore:
                print("Vault contents:")
                for entry in manifest:
                    print(f"  - {entry['original']}")
                return
            for entry in manifest:
                original = Path(entry["original"])
                source_name = entry["archive_name"]
                if original.exists():
                    print(f"Skipping existing path: {original}")
                    continue
                original.parent.mkdir(parents=True, exist_ok=True)
                if source_name in names:
                    zf.extract(source_name, original.parent)
                    extracted = original.parent / source_name
                    if extracted != original:
                        extracted.rename(original)
    VAULT_FILE.unlink()
    (APP_DIR / "restore_paths.json").unlink(missing_ok=True)
    print("Vault restored successfully.")


def main():
    parser = argparse.ArgumentParser(description="VaultGuard local encrypted file vault")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create a vault password")
    p_add = sub.add_parser("add", help="encrypt files/folders into the vault")
    p_add.add_argument("paths", nargs="+", help="files or folders to protect")
    sub.add_parser("list", help="list encrypted vault contents")
    sub.add_parser("restore", help="decrypt and restore vault contents")
    args = parser.parse_args()

    if args.command == "init":
        init_vault()
    elif args.command == "add":
        add_items(args.paths)
    elif args.command == "list":
        unlock(False)
    elif args.command == "restore":
        unlock(True)


if __name__ == "__main__":
    main()

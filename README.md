# VaultGuard

A small Windows-friendly Python privacy vault for protecting personal files and folders.

## What it does

VaultGuard lets you select files/folders and place encrypted copies into a local vault. After successful encryption, the selected originals are removed so they are no longer sitting in their original locations. The vault can later be listed and restored.

**Important:** VaultGuard does not try to defeat Windows Search, modify the Windows registry, change security settings, hide processes, install persistence, or bypass Defender. It is a file-protection utility, not a stealth tool.

## Requirements

- Windows 10/11
- Python 3.10 or newer
- Internet access only for installing the `cryptography` package

Check Python:

```powershell
python --version
```

## Setup

Clone the repository:

```powershell
git clone https://github.com/Verification-step/Vaultguard.git
cd Vaultguard
```

Install the dependency:

```powershell
python -m pip install -r requirements.txt
```

## Create the vault

Run:

```powershell
python vaultguard.py init
```

Choose a strong password. The password is not stored in plain text.

## Protect files/folders

Example:

```powershell
python vaultguard.py add "C:\Users\YourName\Documents\Private"
```

Multiple paths can be supplied:

```powershell
python vaultguard.py add "C:\Users\YourName\Documents\Private" "C:\Users\YourName\Desktop\notes.txt"
```

VaultGuard first creates and verifies the encrypted archive. Only after successful encryption does it remove the selected originals.

## List vault contents

```powershell
python vaultguard.py list
```

You will be asked for the vault password.

## Restore files

```powershell
python vaultguard.py restore
```

The files are restored to their original paths when those paths are available. Existing files are not overwritten.

## Vault location

The encrypted vault and metadata are stored under:

```text
%USERPROFILE%\.vaultguard\
```

The main encrypted file is:

```text
vault.vg
```

## Security notes

- The encryption key is derived from the password using PBKDF2-HMAC-SHA256 with a 600,000-iteration work factor and a random salt.
- File data is encrypted with Fernet from the `cryptography` package.
- If you forget the password, VaultGuard cannot recover the encrypted contents.
- Do not delete `vault.vg` if you need the protected files.
- Keep a separate backup of important data before testing any file-management utility.

## One-command local launcher

After cloning the repository and installing Python/dependencies, you can invoke the tool directly from the repository directory:

```powershell
python vaultguard.py list
```

For safety, this project intentionally does **not** use a remote one-liner that downloads and executes arbitrary Python code. Downloading code from a repository and executing it automatically makes it harder to inspect what is being run.

## License

MIT

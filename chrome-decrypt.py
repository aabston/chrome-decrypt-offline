#!/usr/bin/env python3
"""Chrome credential/cookie info and decryption tool."""

import argparse
import base64
import getpass
import glob
import hashlib
import json
import os
import readline
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from rich.table import Table
from rich.console import Console
from tabulate import tabulate
from dpapick3 import blob as dpapi_blob_mod
from dpapick3 import masterkey as dpapi_mk_mod
from Crypto.Cipher import AES, ChaCha20_Poly1305


# ---------------------------------------------------------------------------
# Encryption version detection
# ---------------------------------------------------------------------------

def get_encryption_version(encrypted_value: bytes) -> str:
    if not encrypted_value:
        return "plaintext"
    prefix = encrypted_value[:3]
    try:
        tag = prefix.decode("ascii")
        if tag.startswith("v") and tag[1:].isdigit():
            labels = {
                "v10": "v10 (DPAPI/AES-GCM)",
                "v11": "v11 (AES-GCM)",
                "v20": "v20 (App-Bound AES-GCM)",
            }
            return labels.get(tag, tag)
    except Exception:
        pass
    return "DPAPI (legacy)"


# ---------------------------------------------------------------------------
# Table rendering (rich → tabulate → manual fallback)
# ---------------------------------------------------------------------------

def print_table(headers: list, rows: list, title: str = "") -> None:
    console = Console()
    table = Table(title=title, show_header=True, header_style="bold cyan")
    for h in headers:
        table.add_column(h, overflow="fold")
    for row in rows:
        table.add_row(*[str(c) for c in row])
    console.print(table)
    return

    if title:
        print(f"\n{title}")
    print(tabulate(rows, headers=headers))
    return



# ---------------------------------------------------------------------------
# SQLite helper
# ---------------------------------------------------------------------------

def open_sqlite_copy(path: str):
    """Copy the DB to a temp file (Chrome may hold a lock) and open it."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    shutil.copy2(path, tmp.name)
    return sqlite3.connect(tmp.name), tmp.name


# ---------------------------------------------------------------------------
# Interactive prompt helpers with readline + .formdata.json caching
# ---------------------------------------------------------------------------

FORMDATA_PATH = ".formdata.json"


def _load_formdata() -> list:
    try:
        with open(FORMDATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_formdata(entries: list) -> None:
    with open(FORMDATA_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def _get_state_cache(entries: list, state_path: str) -> dict:
    """Return the paths sub-dict for this Local State file, creating it if absent."""
    norm = os.path.normpath(state_path)
    for entry in entries:
        if os.path.normpath(entry.get("state", "")) == norm:
            return entry["paths"]
    new_entry: dict = {"state": state_path, "paths": {}}
    entries.append(new_entry)
    return new_entry["paths"]


def _prompt_text(label: str, key: str, formdata: dict, completions: list | None = None) -> str:
    """Prompt with readline pre-fill and optional tab completion."""
    cached = formdata.get(key, "")

    if completions is not None:
        def _completer(text, state):
            matches = [c for c in completions if c.lower().startswith(text.lower())]
            return matches[state] if state < len(matches) else None
        readline.set_completer(_completer)
    else:
        # Filesystem path completion as default
        def _completer(text, state):
            matches = glob.glob(text + "*")
            return matches[state] if state < len(matches) else None
        readline.set_completer(_completer)

    readline.parse_and_bind("tab: complete")
    if cached:
        readline.set_startup_hook(lambda: readline.insert_text(cached))

    try:
        value = input(f"{label}: ").strip()
    finally:
        readline.set_startup_hook(None)
        readline.set_completer(None)

    value = value or cached
    if value:
        formdata[key] = value
    return value


def _prompt_secret(label: str, key: str, formdata: dict) -> str:
    """Prompt for a secret value; cached value shown as hint, not pre-filled."""
    cached = formdata.get(key, "")
    hint = " [cached — press Enter to reuse]" if cached else ""
    value = getpass.getpass(f"{label}{hint}: ")
    value = value or cached
    if value:
        formdata[key] = value
    return value


def _read_bytes_input(val: str) -> bytes:
    """Accept either a file path (binary read) or a hex string."""
    p = Path(val)
    if p.exists():
        return p.read_bytes()
    try:
        return bytes.fromhex(val.strip())
    except ValueError:
        raise ValueError(f"Cannot read '{val}' as file path or hex string")


# ---------------------------------------------------------------------------
# ChromeDecryptor class
# ---------------------------------------------------------------------------

class ChromeDecryptor:
    def __init__(self, localstate_path: str | None = None, verbose: bool = False):
        self.localstate_path = localstate_path
        self.verbose = verbose
        self.browserkey_v10: bytes | None = None
        self.browserkey_v20: bytes | None = None
        self._user_masterkey: bytes | None = None  # raw dpapick3 masterkey bytes, kept for v20
        self._v20_key_attempted: bool = False

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------

    def load_key_from_localstate(self) -> None:
        """Parse the DPAPI-wrapped AES key from Local State and decrypt it."""
        if not self.localstate_path:
            raise ValueError("--localstate is required for --decrypt")

        with open(self.localstate_path, "r", encoding="utf-8") as f:
            state = json.load(f)

        encrypted_key_b64 = state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            raise ValueError("os_crypt.encrypted_key not found in Local State")

        # Chrome stores: base64("DPAPI" + <raw DPAPI blob>)
        raw_with_prefix = base64.b64decode(encrypted_key_b64)
        if raw_with_prefix[:5] != b"DPAPI":
            raise ValueError("Unexpected encrypted_key format (missing DPAPI prefix)")
        raw_blob = raw_with_prefix[5:]

        dpapi_blob = dpapi_blob_mod.DPAPIBlob(raw_blob)
        mk_guid = str(dpapi_blob.mkguid)
        self._log(f"[*] DPAPI masterkey GUID: {mk_guid}")

        entries = _load_formdata()
        formdata = _get_state_cache(entries, self.localstate_path)

        mk_path = _prompt_text(
            f"  Masterkey file (GUID={mk_guid})",
            "mk_path",
            formdata,
        )
        sid = _prompt_text(
            "  User SID",
            "sid",
            formdata,
            completions=[formdata["sid"]] if "sid" in formdata else [],
        )
        password = _prompt_secret("  Password", "password", formdata)

        _save_formdata(entries)

        # Decrypt the masterkey file
        with open(mk_path, "rb") as _f:
            mkf = dpapi_mk_mod.MasterKeyFile(_f.read())
        mkf.decryptWithPassword(sid, password)
        if not mkf.decrypted:
            raise ValueError("Failed to decrypt masterkey — wrong SID or password?")

        # Unprotect the DPAPI blob with the raw masterkey bytes
        self._user_masterkey = mkf.get_key()
        dpapi_blob.decrypt(self._user_masterkey)
        if not dpapi_blob.decrypted:
            raise ValueError("DPAPI blob decryption failed")

        self.browserkey_v10 = dpapi_blob.cleartext
        self._log(f"[+] v10 browser key loaded ({len(self.browserkey_v10)} bytes)")

    # ------------------------------------------------------------------
    # v20 App-Bound key loading
    # ------------------------------------------------------------------

    def load_v20_key(self) -> None:
        """Derive the v20 browser key from SYSTEM DPAPI + KSP + app_bound_encrypted_key."""
        if self._user_masterkey is None:
            raise ValueError("User masterkey not loaded — call load_key_from_localstate() first")


        # Pre-parse app_bound_encrypted_key to extract the SYSTEM masterkey GUID for the prompt
        with open(self.localstate_path, "r", encoding="utf-8") as _f:
            state = json.load(_f)
        app_bound_b64 = state.get("os_crypt", {}).get("app_bound_encrypted_key")
        if not app_bound_b64:
            raise ValueError("os_crypt.app_bound_encrypted_key not found in Local State")
        app_bound_raw = base64.b64decode(app_bound_b64)
        if app_bound_raw[:4] != b"APPB":
            raise ValueError("Unexpected app_bound_encrypted_key format (missing APPB prefix)")
        sys_mk_guid = str(dpapi_blob_mod.DPAPIBlob(app_bound_raw[4:]).mkguid)

        entries = _load_formdata()
        formdata = _get_state_cache(entries, self.localstate_path)
        print("\n[*] v20 App-Bound encryption detected — SYSTEM DPAPI inputs required")  # always: precedes prompts

        system_userkey_input = _prompt_text(
            "  SYSTEM DPAPI userkey (file path or hex bytes)",
            "system_userkey",
            formdata,
        )
        system_dpapi_key_path = _prompt_text(
            f"  SYSTEM encrypted DPAPI key file (GUID={sys_mk_guid})",
            "system_dpapi_key",
            formdata,
        )
        ksp_key_path = _prompt_text(
            "  KSP key file (<16hex>_<guid>)",
            "ksp_key",
            formdata,
        )
        _save_formdata(entries)

        # 1. Decrypt SYSTEM masterkey using the DPAPI userkey
        system_userkey = _read_bytes_input(system_userkey_input)
        with open(system_dpapi_key_path, "rb") as _f:
            sys_mkf = dpapi_mk_mod.MasterKeyFile(_f.read())
        sys_mkf.decryptWithKey(system_userkey)
        if not sys_mkf.decrypted:
            raise ValueError("Failed to decrypt SYSTEM masterkey with provided userkey")
        system_masterkey = sys_mkf.get_key()
        self._log("[+] SYSTEM masterkey decrypted")

        # 2. Decrypt KSP key blob
        ksp_raw = Path(ksp_key_path).read_bytes()
        DPAPI_MAGIC = bytes([0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF])
        boffset = ksp_raw[::-1].index(DPAPI_MAGIC[::-1]) + len(DPAPI_MAGIC)
        ksp_blob = dpapi_blob_mod.DPAPIBlob(ksp_raw[-boffset:])
        ksp_blob.decrypt(system_masterkey, entropy=b"xT5rZW5qVVbrvpuA\x00")
        if not ksp_blob.decrypted:
            raise ValueError("Failed to decrypt KSP DPAPI blob with SYSTEM masterkey")
        ksp_raw_key = ksp_blob.cleartext
        # BCRYPT_KEY_DATA_BLOB: magic(4b "KDBM") | version(4b) | cbKeyData(4b) | key
        if len(ksp_raw_key) >= 12 and ksp_raw_key[:4] == b"KDBM":
            cb_key = int.from_bytes(ksp_raw_key[8:12], "little")
            ksp_key = ksp_raw_key[12: 12 + cb_key]
        else:
            ksp_key = ksp_raw_key[:32]
        self._log(f"[+] KSP key decrypted ({len(ksp_key)} bytes, from {len(ksp_raw_key)}-byte blob)")

        # 4. Decrypt blob1 (SYSTEM key), then blob2 (user key)
        blob1 = dpapi_blob_mod.DPAPIBlob(app_bound_raw[4:])
        blob1.decrypt(system_masterkey)
        if not blob1.decrypted:
            raise ValueError("Failed to decrypt app_bound blob1 with SYSTEM DPAPI key")

        blob2 = dpapi_blob_mod.DPAPIBlob(blob1.cleartext)
        blob2.decrypt(self._user_masterkey)
        if not blob2.decrypted:
            raise ValueError("Failed to decrypt app_bound blob2 with user DPAPI key")

        # 5. Parse: header_len(4b LE) | header | content_len(4b LE) | content
        data = blob2.cleartext
        header_len = int.from_bytes(data[0:4], "little")
        content_start = 4 + header_len + 4
        content_len = int.from_bytes(data[4 + header_len: content_start], "little")
        content = data[content_start: content_start + content_len]

        # 6. Derive browser key from content flag
        self.browserkey_v20 = self._derive_v20_key(content, ksp_key)
        self._log(f"[+] v20 browser key derived ({len(self.browserkey_v20)} bytes)")

    @staticmethod
    def _derive_v20_key(content: bytes, ksp_key: bytes) -> bytes:
        flag = content[0]

        if flag in (1, 2):
            # flag(1b) | IV(12b) | TAG(16b) | ciphertext
            iv  = content[1:13]
            tag = content[13:29]
            ct  = content[29:]
            if flag == 1:
                key = bytes.fromhex(
                    "B31C6E241AC846728DA9C1FAC4936651"
                    "CFFB944D143AB816276BCC6DA0284787"
                )
                return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
            else:
                key = bytes.fromhex(
                    "E98F37D7F4E1FA433D19304DC2258042"
                    "090E2D1D7EEA7670D41F738D08729660"
                )
                return ChaCha20_Poly1305.new(key=key, nonce=iv).decrypt_and_verify(ct, tag)

        if flag == 3:
            # flag(1b) | encrypted_aes_key(32b) | IV(12b) | ciphertext(32b) | TAG(16b)
            enc_key = content[1:33]
            iv      = content[33:45]
            ct      = content[45:77]
            tag     = content[77:93]
            xor_key = bytes.fromhex(
                "CCF8A1CEC56605B8517552BA1A2D061C"
                "03A29E90274FB2FCF59BA4B75C392390"
            )
            key1 = AES.new(ksp_key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(enc_key)
            key2 = bytes(a ^ b for a, b in zip(key1, xor_key))
            return AES.new(key2, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)

        raise ValueError(f"Unknown app-bound content flag: {flag}")

    # ------------------------------------------------------------------
    # Value decryption
    # ------------------------------------------------------------------

    def decrypt_value(self, encrypted_value: bytes) -> str:
        if not encrypted_value:
            return ""

        prefix = encrypted_value[:3]
        try:
            tag = prefix.decode("ascii")
        except Exception:
            tag = ""

        if tag == "v20":
            if not self._v20_key_attempted and self.browserkey_v20 is None:
                self._v20_key_attempted = True
                try:
                    self.load_v20_key()
                except Exception as exc:
                    print(f"[!] v20 key loading failed: {exc}")
            if self.browserkey_v20 is None:
                return "[v20: key unavailable]"
            try:
                return self._decrypt_aes_gcm(encrypted_value, self.browserkey_v20)
            except Exception as exc:
                return f"[decrypt error: {exc}]"

        if tag in ("v10", "v11"):
            if self.browserkey_v10 is None:
                return "[error: browser key not loaded]"
            try:
                return self._decrypt_aes_gcm(encrypted_value, self.browserkey_v10)
            except Exception as exc:
                return f"[decrypt error: {exc}]"

        return "[unsupported: legacy DPAPI]"

    @staticmethod
    def _decrypt_aes_gcm(encrypted_value: bytes, key: bytes) -> str:
        # Format: version(3b) | IV(12b) | ciphertext | TAG(16b)
        iv = encrypted_value[3:15]
        payload = encrypted_value[15:]
        ciphertext, tag = payload[:-16], payload[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Decryption queries
    # ------------------------------------------------------------------

    def decrypt_logindata(self, path: str) -> None:
        conn, tmp = open_sqlite_copy(path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = []
            for origin_url, username, enc_pw in cur.fetchall():
                if isinstance(enc_pw, str):
                    enc_pw = enc_pw.encode()
                rows.append((
                    origin_url or "",
                    username or "",
                    self.decrypt_value(enc_pw),
                ))
            print_table(
                ["Site", "Login", "Password"],
                rows,
                title="Login Data (decrypted)",
            )
        finally:
            conn.close()
            os.unlink(tmp)

    def decrypt_cookies(self, path: str) -> None:
        conn, tmp = open_sqlite_copy(path)
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(cookies)")
            cols = {row[1] for row in cur.fetchall()}
            enc_col = "encrypted_value" if "encrypted_value" in cols else "value"
            host_col = "host_key" if "host_key" in cols else "host"
            cur.execute(f"SELECT {host_col}, name, {enc_col} FROM cookies")
            rows = []
            for host, name, enc_val in cur.fetchall():
                if isinstance(enc_val, str):
                    enc_val = enc_val.encode()
                rows.append((
                    host or "",
                    name or "",
                    self.decrypt_value(enc_val)
                        if enc_val[:3] != b"v20" else
                            self.decrypt_value(enc_val)[32:],
                ))
            print_table(
                ["Site", "Cookie Name", "Value"],
                rows,
                title="Cookies (decrypted)",
            )
        finally:
            conn.close()
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# --info command (read-only, no decryption)
# ---------------------------------------------------------------------------

def info_logindata(path: str) -> None:
    conn, tmp = open_sqlite_copy(path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        rows = []
        for origin_url, username, enc_pw in cur.fetchall():
            if isinstance(enc_pw, str):
                enc_pw = enc_pw.encode()
            rows.append((origin_url or "", username or "", get_encryption_version(enc_pw)))
        print_table(["Site", "Login", "Password Encryption"], rows, title="Login Data")
    finally:
        conn.close()
        os.unlink(tmp)


def info_cookies(path: str) -> None:
    conn, tmp = open_sqlite_copy(path)
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(cookies)")
        cols = {row[1] for row in cur.fetchall()}
        enc_col = "encrypted_value" if "encrypted_value" in cols else "value"
        host_col = "host_key" if "host_key" in cols else "host"
        cur.execute(f"SELECT {host_col}, name, {enc_col} FROM cookies")
        rows = []
        for host, name, enc_val in cur.fetchall():
            if isinstance(enc_val, str):
                enc_val = enc_val.encode()
            rows.append((host or "", name or "", get_encryption_version(enc_val)))
        print_table(["Site", "Cookie Name", "Encryption Version"], rows, title="Cookies")
    finally:
        conn.close()
        os.unlink(tmp)


def info_localstate(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        state = json.load(f)

    os_crypt = state.get("os_crypt", {})
    rows = []

    encrypted_key = os_crypt.get("encrypted_key")
    if encrypted_key:
        key_bytes = base64.b64decode(encrypted_key)
        source = "DPAPI-wrapped AES key" if key_bytes[:5] == b"DPAPI" else "unknown wrapping"
        rows.append(("os_crypt.encrypted_key", source, base64.b64encode(key_bytes).decode()))

    app_bound_key = os_crypt.get("app_bound_encrypted_key")
    if app_bound_key:
        rows.append(("os_crypt.app_bound_encrypted_key", "App-Bound AES key", app_bound_key))

    if rows:
        print_table(["Field", "Type", "Value (base64)"], rows, title="Local State — Encryption Keys")
    else:
        print("No encrypted key material found in Local State.")


def cmd_info(args: argparse.Namespace) -> None:
    if not any([args.logindata, args.cookies, args.localstate]):
        print("--info requires at least one of --logindata, --cookies, --localstate.")
        sys.exit(1)
    if args.logindata:
        info_logindata(args.logindata)
    if args.cookies:
        info_cookies(args.cookies)
    if args.localstate:
        info_localstate(args.localstate)


# ---------------------------------------------------------------------------
# --decrypt command
# ---------------------------------------------------------------------------

def cmd_decrypt(args: argparse.Namespace) -> None:
    if not args.localstate:
        print("--decrypt requires --localstate (needed to load the browser AES key).")
        sys.exit(1)
    if not args.logindata and not args.cookies:
        print("--decrypt requires --logindata and/or --cookies.")
        sys.exit(1)

    decryptor = ChromeDecryptor(localstate_path=args.localstate, verbose=args.verbose)
    decryptor.load_key_from_localstate()

    if args.logindata:
        decryptor.decrypt_logindata(args.logindata)
    if args.cookies:
        decryptor.decrypt_cookies(args.cookies)


# ---------------------------------------------------------------------------
# Argument parser + entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chrome-decrypt",
        description="Inspect and decrypt Chrome credentials, cookies, and keys.",
    )
    parser.add_argument(
        "-l", "--logindata",
        metavar="PATH",
        help='Path to Chrome "Login Data" SQLite file',
    )
    parser.add_argument(
        "-s", "--localstate",
        metavar="PATH",
        help='Path to Chrome "Local State" JSON file',
    )
    parser.add_argument(
        "-c", "--cookies",
        metavar="PATH",
        help="Path to Chrome Cookies SQLite file",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show encryption metadata (versions, key material) without decrypting",
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help=(
            "Decrypt passwords/cookies. "
            "Requires --localstate AND (--logindata and/or --cookies). "
            "Prompts for DPAPI masterkey path, SID, and password; caches to .formdata.json"
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print debug/progress output (key sizes, decryption steps)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    if args.info:
        cmd_info(args)
        return

    if args.decrypt:
        cmd_decrypt(args)
        return

    print("No action specified. Use --info or --decrypt, or --help for usage.")


if __name__ == "__main__":
    main()

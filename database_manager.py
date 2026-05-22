import os
import sqlite3
from crypto_utils import encrypt_password, decrypt_password

DB_PATH = "vault.db"


def _connect() -> sqlite3.Connection:
    """Open a connection; rows are accessible as dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create vault table if it does not already exist. Call once at startup."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                site               TEXT    NOT NULL,
                username           TEXT    NOT NULL,
                encrypted_password BLOB    NOT NULL,
                iv                 BLOB    NOT NULL,
                salt               BLOB    NOT NULL
            )
        """)


# ── CREATE ─────────────────────────────────────────────────────────────────────

def add_entry(master_password: str, site: str, username: str, password: str) -> None:
    """Encrypt and store a credential. Site is lowercased for consistent lookup."""
    salt = os.urandom(16)
    encrypted_pw, iv = encrypt_password(master_password, salt, password)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO vault (site, username, encrypted_password, iv, salt) VALUES (?, ?, ?, ?, ?)",
            (site.strip().lower(), username.strip(), encrypted_pw, iv, salt),
        )


# ── READ ───────────────────────────────────────────────────────────────────────

def get_all_for_site(master_password: str, site: str) -> list:
    """
    Return ALL entries matching a site name (case-insensitive).
    Each item is a dict: {id, site, username, password}
    password is None if master password is wrong.
    """
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, site, username, encrypted_password, iv, salt "
            "FROM vault WHERE LOWER(site) = ? ORDER BY id",
            (site.strip().lower(),),
        ).fetchall()

    results = []
    for row in rows:
        try:
            plaintext = decrypt_password(
                master_password,
                bytes(row["salt"]),
                bytes(row["iv"]),
                bytes(row["encrypted_password"]),
            )
            results.append({"id": row["id"], "site": row["site"],
                            "username": row["username"], "password": plaintext})
        except Exception:
            results.append({"id": row["id"], "site": row["site"],
                            "username": row["username"], "password": None})
    return results


def get_entry(master_password: str, site: str) -> tuple:
    """
    Single-entry retrieval (first match). Returns (username, password) or (None, error).
    Kept for GUI compatibility.
    """
    entries = get_all_for_site(master_password, site)
    if not entries:
        return None, "No entry found for that site."
    if entries[0]["password"] is None:
        return None, "Error: Incorrect master password."
    return entries[0]["username"], entries[0]["password"]


def search_entries(master_password: str, query: str) -> list:
    """
    Partial-match search on site and username (case-insensitive).
    Returns list of dicts: {id, site, username, password}.
    """
    pattern = f"%{query.strip().lower()}%"
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, site, username, encrypted_password, iv, salt FROM vault "
            "WHERE LOWER(site) LIKE ? OR LOWER(username) LIKE ? ORDER BY site",
            (pattern, pattern),
        ).fetchall()

    results = []
    for row in rows:
        try:
            plaintext = decrypt_password(
                master_password,
                bytes(row["salt"]),
                bytes(row["iv"]),
                bytes(row["encrypted_password"]),
            )
            results.append({"id": row["id"], "site": row["site"],
                            "username": row["username"], "password": plaintext})
        except Exception:
            results.append({"id": row["id"], "site": row["site"],
                            "username": row["username"], "password": "[Wrong master password]"})
    return results


def list_all_sites() -> list:
    """Return all entries without decryption: [{id, site, username}]."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, site, username FROM vault ORDER BY site"
        ).fetchall()
    return [{"id": r["id"], "site": r["site"], "username": r["username"]} for r in rows]


# ── UPDATE ─────────────────────────────────────────────────────────────────────

def update_entry(master_password: str, entry_id: int,
                 new_username: str = None, new_password: str = None) -> bool:
    """
    Update username and/or password for a specific entry by its id.
    Returns True if the entry was found and updated.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, username, encrypted_password, iv, salt FROM vault WHERE id = ?",
            (entry_id,),
        ).fetchone()

        if row is None:
            return False

        username = new_username.strip() if new_username else row["username"]

        if new_password:
            salt = os.urandom(16)
            encrypted_pw, iv = encrypt_password(master_password, salt, new_password)
        else:
            encrypted_pw = bytes(row["encrypted_password"])
            iv           = bytes(row["iv"])
            salt         = bytes(row["salt"])

        conn.execute(
            "UPDATE vault SET username = ?, encrypted_password = ?, iv = ?, salt = ? WHERE id = ?",
            (username, encrypted_pw, iv, salt, row["id"]),
        )
    return True


# ── DELETE ─────────────────────────────────────────────────────────────────────

def delete_entry(entry_id: int) -> bool:
    """Delete a single credential by id. Returns True if deleted."""
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
    return cursor.rowcount > 0

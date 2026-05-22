"""
Secure Vault — CLI Password Manager
=====================================
Commands:
  add    --site SITE --user USER    Add a new credential (choose generate or type)
  get    --site SITE [--show]       Copy password to clipboard (clears in 30s in background)
  search --query QUERY              Partial-match search across sites and usernames
  update --site SITE                Update username or password for a stored entry
  delete --site SITE                Delete a stored credential
  list                              List all stored site names and usernames
"""

import argparse
import getpass
import secrets
import string
import sys
import threading
import time

from database_manager import (
    init_db, add_entry, get_all_for_site,
    search_entries, update_entry, delete_entry, list_all_sites,
)
from hibp_checker import check_password_leak

CLIPBOARD_SECONDS = 30


# ── Clipboard helpers ─────────────────────────────────────────────────────────

def _try_copy(text: str) -> bool:
    """Copy text to clipboard. Returns True on success, False if unavailable."""
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        return False


def _clipboard_clear_worker(seconds: int) -> None:
    """
    Runs in a BACKGROUND THREAD.
    Prints a live countdown then wipes the clipboard.
    The main program keeps running while this counts down.
    """ 
    for i in range(seconds, 0, -1):
        # \r rewrites the same line — looks like a live timer
        print(f"  [Clipboard clears in {i:2d}s]", end="\r", flush=True)
        time.sleep(1)
    _try_copy("")          # wipe clipboard
    # Print on a new line so it doesn't overwrite surrounding output
    print("\n  [INFO] Clipboard cleared automatically.")


def _copy_and_clear_in_background(password: str, show_if_no_clipboard: bool = True) -> None:
    """
    Copy password to clipboard, then launch a daemon thread that
    clears it after CLIPBOARD_SECONDS. The CLI returns immediately.

    show_if_no_clipboard=False: used for generated passwords where
    the value must never be printed to the terminal.
    """
    copied = _try_copy(password)
    if not copied:
        if show_if_no_clipboard:
            # Retrieving an existing password — safe to fall back to printing
            print(f"  Password : {password}")
            print("  [NOTE] Clipboard unavailable on this system — password printed above.")
        else:
            # Generated password — never reveal it on screen
            print("  [WARNING] Clipboard unavailable on this system.")
            print("  The generated password was not copied. Please run the command again.")
        return

    print(f"  Password : [Copied to clipboard — not shown for security]")
    print(f"  [INFO] Clipboard will be cleared in {CLIPBOARD_SECONDS}s (running in background).")

    t = threading.Thread(
        target=_clipboard_clear_worker,
        args=(CLIPBOARD_SECONDS,),
        daemon=False,   # thread dies if the whole program exits
    )
    t.start()
    # ← main thread returns immediately; program is NOT blocked


# ── Password input helper ─────────────────────────────────────────────────────

def _generate_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _ask_for_password() -> str:
    """
    Ask the user whether they want to generate a strong password
    or type their own. Returns the final password string.
    """
    print("\n  How would you like to set the password?")
    print("  [1] Generate a strong password automatically")
    print("  [2] Enter my own password")

    while True:
        choice = input("\n  Enter 1 or 2: ").strip()

        if choice == "1":
            password = _generate_password()
            # Do NOT print the password to the terminal — copy silently instead
            _copy_and_clear_in_background(password, show_if_no_clipboard=False)
            return password

        elif choice == "2":
            while True:
                password = getpass.getpass("  Enter your password: ")
                confirm  = getpass.getpass("  Confirm your password: ")
                if password == confirm:
                    return password
                print("  [ERROR] Passwords do not match. Try again.\n")

        else:
            print("  Please enter 1 or 2.")


# ── Entry picker (multiple accounts per site) ─────────────────────────────────

def _pick_entry(entries: list, action: str = "use") -> dict | None:
    """
    If multiple entries exist for a site, show them and let the user pick.
    Returns the chosen entry dict, or None if the user cancels.
    """
    if len(entries) == 1:
        return entries[0]

    print(f"\n  Multiple accounts found for this site. Choose one to {action}:\n")
    for i, e in enumerate(entries, 1):
        print(f"  [{i}] id={e['id']}  username={e['username']}")
    print("  [0] Cancel\n")

    while True:
        try:
            choice = int(input("  Enter number: "))
        except ValueError:
            print("  Please enter a number.")
            continue
        if choice == 0:
            return None
        if 1 <= choice <= len(entries):
            return entries[choice - 1]
        print(f"  Enter a number between 0 and {len(entries)}.")


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_add(args) -> None:
    """Add a new credential — user chooses to generate or type the password."""
    master = getpass.getpass("Master password: ")

    # Ask: generate or type?
    password = _ask_for_password()

    # Always check for known breaches before saving
    print("\n  Checking for known breaches...")
    leak_result = check_password_leak(password)
    print(f"  {leak_result}")

    # If leaked, give the user a chance to abort
    if "WARNING" in leak_result:
        go = input("\n  This password is leaked. Save it anyway? [y/N]: ").strip().lower()
        if go != "y":
            print("  Cancelled. Nothing was saved.")
            return

    add_entry(master, args.site, args.user, password)
    print(f"\n  [OK] Credentials for '{args.site}' saved successfully.")


def cmd_get(args) -> None:
    """
    Retrieve a password.
    Default: copy to clipboard; background thread clears it after 30s (non-blocking).
    --show: print the password to the terminal instead.
    """
    master  = getpass.getpass("Master password: ")
    entries = get_all_for_site(master, args.site)

    if not entries:
        print(f"\n  [ERROR] No entry found for '{args.site}'.")
        print("  Tip: run 'list' to see all sites, or 'search --query ...' for partial match.")
        sys.exit(1)

    if all(e["password"] is None for e in entries):
        print("\n  [ERROR] Incorrect master password.")
        sys.exit(1)

    valid = [e for e in entries if e["password"] is not None]
    entry = _pick_entry(valid, "retrieve")
    if entry is None:
        print("  Cancelled.")
        return

    print(f"\n  Site     : {entry['site']}")
    print(f"  Username : {entry['username']}")

    if args.show:
        # Print directly — user asked to see it
        print(f"  Password : {entry['password']}\n")
    else:
        # Non-blocking clipboard copy — background thread handles the countdown
        _copy_and_clear_in_background(entry["password"])
        print()


def cmd_search(args) -> None:
    """Partial-match search across all sites and usernames."""
    master  = getpass.getpass("Master password: ")
    results = search_entries(master, args.query)

    if not results:
        print(f"\n  No entries match '{args.query}'.")
        return

    print(f"\n  {'ID':<5} {'Site':<25} {'Username':<28} Password")
    print("  " + "─" * 82)
    for r in results:
        pw = r["password"] if r["password"] else "[Wrong master password]"
        print(f"  {r['id']:<5} {r['site']:<25} {r['username']:<28} {pw}")
    print()


def cmd_update(args) -> None:
    """Update username and/or password for a stored credential."""
    master  = getpass.getpass("Master password: ")
    entries = get_all_for_site(master, args.site)

    if not entries:
        print(f"\n  [ERROR] No entry found for '{args.site}'.")
        sys.exit(1)

    if all(e["password"] is None for e in entries):
        print("\n  [ERROR] Incorrect master password.")
        sys.exit(1)

    valid = [e for e in entries if e["password"] is not None]
    entry = _pick_entry(valid, "update")
    if entry is None:
        print("  Cancelled.")
        return

    print(f"\n  Updating '{entry['site']}' (current username: {entry['username']})")

    new_user  = input("  New username (Enter to keep current): ").strip() or None
    change_pw = input("  Change the password? [y/N]: ").strip().lower() == "y"
    new_pass  = None

    if change_pw:
        new_pass    = _ask_for_password()
        print("\n  Checking for known breaches...")
        leak_result = check_password_leak(new_pass)
        print(f"  {leak_result}")
        if "WARNING" in leak_result:
            go = input("  This password is leaked. Save it anyway? [y/N]: ").strip().lower()
            if go != "y":
                print("  Cancelled. Nothing was changed.")
                return

    if update_entry(master, entry["id"], new_user, new_pass):
        print(f"\n  [OK] Entry for '{args.site}' updated successfully.")
    else:
        print("\n  [ERROR] Update failed.")


def cmd_delete(args) -> None:
    """Delete a stored credential after explicit confirmation."""
    master  = getpass.getpass("Master password: ")
    entries = get_all_for_site(master, args.site)

    if not entries:
        print(f"\n  [ERROR] No entry found for '{args.site}'.")
        sys.exit(1)

    if all(e["password"] is None for e in entries):
        print("\n  [ERROR] Incorrect master password.")
        sys.exit(1)

    valid = [e for e in entries if e["password"] is not None]
    entry = _pick_entry(valid, "delete")
    if entry is None:
        print("  Cancelled.")
        return

    confirm = input(
        f"\n  Delete '{entry['site']}' (user: {entry['username']})?"
        f" This cannot be undone. [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("  Cancelled.")
        return

    if delete_entry(entry["id"]):
        print(f"\n  [OK] Entry for '{entry['site']}' deleted.")
    else:
        print("\n  [ERROR] Delete failed.")


def cmd_list(_args) -> None:
    """List all stored sites and usernames (no decryption needed)."""
    entries = list_all_sites()
    if not entries:
        print("\n  Vault is empty.")
        return

    print(f"\n  {'ID':<5} {'Site':<30} Username")
    print("  " + "─" * 62)
    for e in entries:
        print(f"  {e['id']:<5} {e['site']:<30} {e['username']}")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    # Create vault.db and the vault table if they don't exist yet
    init_db()

    if len(sys.argv) == 1:
        print("  [INFO] No CLI arguments provided. Launching GUI mode...")
        import gui
        gui.SecureVaultApp().mainloop()
        return

    parser = argparse.ArgumentParser(
        description="Secure Vault — Password Manager CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py add    --site github.com --user alice@mail.com
  python main.py get    --site github.com
  python main.py get    --site github.com --show
  python main.py search --query git
  python main.py update --site github.com
  python main.py delete --site github.com
  python main.py list
        """,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add",    help="Add a new credential")
    p_add.add_argument("--site", required=True, help="Website name (e.g. github.com)")
    p_add.add_argument("--user", required=True, help="Username or email")

    p_get = sub.add_parser("get",    help="Retrieve a password (copies to clipboard)")
    p_get.add_argument("--site",  required=True,      help="Website to look up")
    p_get.add_argument("--show",  action="store_true", help="Print password to screen instead of clipboard")

    p_srch = sub.add_parser("search", help="Partial-match search by site or username")
    p_srch.add_argument("--query", required=True, help="Search term (partial ok)")

    p_upd = sub.add_parser("update", help="Update a stored credential")
    p_upd.add_argument("--site", required=True, help="Website to update")

    p_del = sub.add_parser("delete", help="Delete a stored credential")
    p_del.add_argument("--site", required=True, help="Website to delete")

    sub.add_parser("list", help="List all stored sites and usernames")

    args = parser.parse_args()
    dispatch = {
        "add":    cmd_add,
        "get":    cmd_get,
        "search": cmd_search,
        "update": cmd_update,
        "delete": cmd_delete,
        "list":   cmd_list,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
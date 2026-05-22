import secrets
import string
import threading
import time

import customtkinter as ctk
import pyperclip
from tkinter import messagebox

from database_manager import (
    init_db, add_entry, get_all_for_site,
    search_entries, update_entry, delete_entry, list_all_sites,
)
from hibp_checker import check_password_leak

CLIPBOARD_SECONDS = 30

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Palette ───────────────────────────────────────────────────────────────────
BG_DARK      = "#1a1a2e"   # deep navy — window background
BG_CARD      = "#16213e"   # slightly lighter — vault rows
BG_HOVER     = "#0f3460"   # hover state for rows
BG_INPUT     = "#0d0d1a"   # dark input fields
ACCENT       = "#4f8ef7"   # blue accent
ACCENT_HOVER = "#3a7de8"
RED          = "#e05252"
RED_HOVER    = "#c43c3c"
GREEN        = "#4caf82"
TEXT_PRIMARY = "#e8eaf6"
TEXT_MUTED   = "#8892b0"
BORDER       = "#2a2a4a"


def _generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _site_initial(site: str) -> str:
    """Return first character of site name for the avatar circle."""
    clean = site.replace("www.", "").strip()
    return clean[0].upper() if clean else "?"


# ── Login Screen ──────────────────────────────────────────────────────────────

class LoginScreen(ctk.CTkFrame):
    def __init__(self, master, on_unlock):
        super().__init__(master, fg_color=BG_DARK)
        self._on_unlock = on_unlock
        self._build()

    def _build(self):
        self.pack(fill="both", expand=True)

        # Lock icon area
        icon_frame = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=60,
                                   width=90, height=90)
        icon_frame.pack(pady=(80, 16))
        icon_frame.pack_propagate(False)
        ctk.CTkLabel(icon_frame, text="🔐", font=("Segoe UI Emoji", 38)).pack(
            expand=True)

        ctk.CTkLabel(self, text="Secure Vault",
                     font=("Roboto", 28, "bold"), text_color=TEXT_PRIMARY).pack()
        ctk.CTkLabel(self, text="Enter your master password to unlock",
                     font=("Roboto", 13), text_color=TEXT_MUTED).pack(pady=(4, 32))

        card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=16)
        card.pack(padx=120, fill="x")

        self._entry = ctk.CTkEntry(
            card, placeholder_text="Master Password",
            show="*", width=340, height=44,
            fg_color=BG_INPUT, border_color=BORDER,
            font=("Roboto", 14), text_color=TEXT_PRIMARY,
        )
        self._entry.pack(padx=24, pady=(24, 12))
        self._entry.bind("<Return>", lambda _: self._submit())

        ctk.CTkButton(
            card, text="Unlock Vault", height=44,
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            font=("Roboto", 14, "bold"), text_color="white",
            command=self._submit,
        ).pack(padx=24, pady=(0, 24), fill="x")

        self._err = ctk.CTkLabel(self, text="", text_color=RED,
                                  font=("Roboto", 12))
        self._err.pack(pady=8)

    def _submit(self):
        pw = self._entry.get().strip()
        if not pw:
            self._err.configure(text="Please enter your master password.")
            return
        self._on_unlock(pw)


# ── Add / Edit Dialog ─────────────────────────────────────────────────────────

class EntryDialog(ctk.CTkToplevel):
    """
    Reusable modal for both Add (new) and Edit (existing) operations.
    On confirm, calls on_save(site, username, password) or
    on_save(None, new_username, new_password) for edit mode.
    """
    def __init__(self, master, on_save, entry: dict = None):
        super().__init__(master)
        self._on_save = on_save
        self._edit    = entry  # None → add mode, dict → edit mode
        self._pass_visible = False

        title = "Edit Credential" if entry else "Add New Password"
        self.title(title)
        self.geometry("460x460")
        self.resizable(False, False)
        self.configure(fg_color=BG_DARK)
        self.grab_set()
        self._build(title)

    def _build(self, title):
        ctk.CTkLabel(self, text=title,
                     font=("Roboto", 18, "bold"), text_color=TEXT_PRIMARY).pack(
            pady=(24, 16))

        form = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=14)
        form.pack(padx=24, fill="x")

        def field(placeholder, show=""):
            e = ctk.CTkEntry(form, placeholder_text=placeholder,
                             show=show, height=42, fg_color=BG_INPUT,
                             border_color=BORDER, font=("Roboto", 13),
                             text_color=TEXT_PRIMARY)
            e.pack(padx=16, pady=6, fill="x")
            return e

        # Site field — disabled in edit mode
        self._site_entry = field("Website (e.g. google.com)")
        if self._edit:
            self._site_entry.insert(0, self._edit["site"])
            self._site_entry.configure(state="disabled")

        self._user_entry = field("Username / Email")
        if self._edit:
            self._user_entry.insert(0, self._edit["username"])

        # Password row with show/hide toggle
        pw_row = ctk.CTkFrame(form, fg_color="transparent")
        pw_row.pack(padx=16, pady=6, fill="x")

        self._pass_entry = ctk.CTkEntry(
            pw_row, placeholder_text="Password",
            show="*", height=42, fg_color=BG_INPUT,
            border_color=BORDER, font=("Roboto", 13),
            text_color=TEXT_PRIMARY,
        )
        self._pass_entry.pack(side="left", fill="x", expand=True)

        self._eye_btn = ctk.CTkButton(
            pw_row, text="👁", width=42, height=42,
            fg_color=BG_INPUT, hover_color=BG_HOVER,
            border_width=1, border_color=BORDER,
            command=self._toggle_pass,
        )
        self._eye_btn.pack(side="left", padx=(4, 0))

        if self._edit and self._edit.get("password"):
            self._pass_entry.insert(0, self._edit["password"])

        # Generate button
        ctk.CTkButton(
            form, text="⚡  Generate Strong Password", height=38,
            fg_color="#2a2a4a", hover_color=BG_HOVER,
            font=("Roboto", 12), text_color=ACCENT,
            command=self._generate,
        ).pack(padx=16, pady=(2, 14), fill="x")

        self._status = ctk.CTkLabel(self, text="", font=("Roboto", 11),
                                     text_color=TEXT_MUTED, wraplength=400)
        self._status.pack(pady=6)

        # Buttons
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=16, padx=24, fill="x")

        ctk.CTkButton(btn_row, text="Cancel", height=40,
                      fg_color="#2a2a4a", hover_color=BG_HOVER,
                      font=("Roboto", 13), text_color=TEXT_MUTED,
                      command=self.destroy).pack(side="left", expand=True,
                                                  padx=(0, 6))
        ctk.CTkButton(btn_row, text="Save", height=40,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=("Roboto", 13, "bold"),
                      command=self._save).pack(side="left", expand=True,
                                               padx=(6, 0))

    def _toggle_pass(self):
        self._pass_visible = not self._pass_visible
        self._pass_entry.configure(show="" if self._pass_visible else "*")

    def _generate(self):
        pw = _generate_password()
        self._pass_entry.delete(0, "end")
        self._pass_entry.insert(0, pw)
        self._pass_entry.configure(show="")  # show it so user can confirm
        self._pass_visible = True
        self._status.configure(
            text="Strong password generated. It will be hidden when you save.",
            text_color=GREEN,
        )

    def _save(self):
        site = self._site_entry.get().strip() if not self._edit else self._edit["site"]
        user = self._user_entry.get().strip()
        pw   = self._pass_entry.get().strip()

        if not self._edit and not site:
            self._status.configure(text="Website is required.", text_color=RED)
            return
        if not user:
            self._status.configure(text="Username is required.", text_color=RED)
            return
        if not pw:
            self._status.configure(text="Password is required.", text_color=RED)
            return

        self._on_save(site, user, pw)
        self.destroy()


# ── Vault Row ─────────────────────────────────────────────────────────────────

class VaultRow(ctk.CTkFrame):
    """
    One row in the password list — matches the Chrome Passwords style.
    Shows: avatar circle with initial, site name, account count or username,
    and action buttons that appear on hover.
    """
    def __init__(self, master, entries: list, on_open):
        super().__init__(master, fg_color=BG_CARD, corner_radius=0,
                         height=64, cursor="hand2")
        self._entries = entries   # list of dicts for this site
        self._on_open = on_open   # callback(entries)
        self._build()
        self.bind("<Button-1>", lambda _: self._on_open(self._entries))
        self.bind("<Enter>",    self._hover_on)
        self.bind("<Leave>",    self._hover_off)

    def _build(self):
        self.grid_propagate(False)

        # Avatar circle
        site   = self._entries[0]["site"]
        letter = _site_initial(site)
        avatar = ctk.CTkFrame(self, fg_color=ACCENT, corner_radius=22,
                               width=44, height=44)
        avatar.pack(side="left", padx=(18, 14), pady=10)
        avatar.pack_propagate(False)
        ctk.CTkLabel(avatar, text=letter,
                     font=("Roboto", 17, "bold"), text_color="white").pack(
            expand=True)
        avatar.bind("<Button-1>", lambda _: self._on_open(self._entries))

        # Text block
        text_block = ctk.CTkFrame(self, fg_color="transparent")
        text_block.pack(side="left", fill="both", expand=True)
        text_block.bind("<Button-1>", lambda _: self._on_open(self._entries))

        n = len(self._entries)
        sub = f"{n} account{'s' if n > 1 else ''}" if n > 1 else self._entries[0]["username"]

        self._site_lbl = ctk.CTkLabel(
            text_block, text=site,
            font=("Roboto", 15, "bold"), text_color=TEXT_PRIMARY, anchor="w",
        )
        self._site_lbl.pack(fill="x")
        self._site_lbl.bind("<Button-1>", lambda _: self._on_open(self._entries))

        self._sub_lbl = ctk.CTkLabel(
            text_block, text=sub,
            font=("Roboto", 12), text_color=TEXT_MUTED, anchor="w",
        )
        self._sub_lbl.pack(fill="x")
        self._sub_lbl.bind("<Button-1>", lambda _: self._on_open(self._entries))

        # Arrow chevron
        self._arrow = ctk.CTkLabel(self, text="›",
                                    font=("Roboto", 22), text_color=TEXT_MUTED)
        self._arrow.pack(side="right", padx=18)

    def _hover_on(self, _=None):
        self.configure(fg_color=BG_HOVER)

    def _hover_off(self, _=None):
        self.configure(fg_color=BG_CARD)


# ── Site Detail Panel ─────────────────────────────────────────────────────────

class SiteDetailPanel(ctk.CTkToplevel):
    """
    Popup showing all accounts for one site with Copy / Edit / Delete actions.
    """
    def __init__(self, master, entries: list, master_password: str,
                 on_refresh, status_callback):
        super().__init__(master)
        self._entries        = entries
        self._master_password = master_password
        self._on_refresh     = on_refresh
        self._status_cb      = status_callback

        site = entries[0]["site"]
        self.title(site)
        self.geometry("500x420")
        self.resizable(False, False)
        self.configure(fg_color=BG_DARK)
        self.grab_set()
        self._build(site)

    def _build(self, site):
        # Header
        header = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=0, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        avatar = ctk.CTkFrame(header, fg_color=ACCENT, corner_radius=22,
                               width=44, height=44)
        avatar.pack(side="left", padx=16, pady=10)
        avatar.pack_propagate(False)
        ctk.CTkLabel(avatar, text=_site_initial(site),
                     font=("Roboto", 18, "bold"), text_color="white").pack(expand=True)

        ctk.CTkLabel(header, text=site,
                     font=("Roboto", 17, "bold"), text_color=TEXT_PRIMARY).pack(
            side="left")

        # Account rows
        scroll = ctk.CTkScrollableFrame(self, fg_color=BG_DARK)
        scroll.pack(fill="both", expand=True, padx=0, pady=0)

        for entry in self._entries:
            self._build_account_row(scroll, entry)

        # Add another account button
        ctk.CTkButton(
            self, text="＋  Add another account for this site",
            height=40, fg_color="transparent",
            hover_color=BG_HOVER, font=("Roboto", 13),
            text_color=ACCENT, border_width=1, border_color=BORDER,
            command=lambda: self._add_account(site),
        ).pack(fill="x", padx=16, pady=(8, 16))

    def _build_account_row(self, parent, entry):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10)
        card.pack(fill="x", padx=12, pady=5)

        # Username
        ctk.CTkLabel(card, text=entry["username"],
                     font=("Roboto", 13, "bold"), text_color=TEXT_PRIMARY,
                     anchor="w").pack(fill="x", padx=14, pady=(10, 2))

        # Password dots
        ctk.CTkLabel(card, text="••••••••••••",
                     font=("Roboto", 13), text_color=TEXT_MUTED,
                     anchor="w").pack(fill="x", padx=14)

        # Action buttons row
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(6, 10))

        ctk.CTkButton(
            btn_row, text="Copy Password", height=34, width=140,
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            font=("Roboto", 12), text_color="white",
            command=lambda e=entry: self._copy_password(e["password"]),
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row, text="Show", height=34, width=70,
            fg_color="#2a2a4a", hover_color=BG_HOVER,
            font=("Roboto", 12), text_color=TEXT_PRIMARY,
            command=lambda e=entry: self._show_password(e),
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row, text="Edit", height=34, width=70,
            fg_color="#2a2a4a", hover_color=BG_HOVER,
            font=("Roboto", 12), text_color=TEXT_PRIMARY,
            command=lambda e=entry: self._edit_entry(e),
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row, text="Delete", height=34, width=70,
            fg_color=RED, hover_color=RED_HOVER,
            font=("Roboto", 12), text_color="white",
            command=lambda e=entry: self._delete_entry(e),
        ).pack(side="left")

    def _copy_password(self, password: str):
        try:
            pyperclip.copy(password)
            self._status_cb(f"Password copied! Clears in {CLIPBOARD_SECONDS}s.", GREEN)
            threading.Thread(
                target=self._clear_clipboard_bg, daemon=False
            ).start()
        except Exception:
            self._status_cb("Clipboard unavailable on this system.", RED)

    def _clear_clipboard_bg(self):
        for i in range(CLIPBOARD_SECONDS, 0, -1):
            self._status_cb(f"Clipboard clears in {i}s…", TEXT_MUTED)
            time.sleep(1)
        pyperclip.copy("")
        self._status_cb("Clipboard cleared.", TEXT_MUTED)

    def _show_password(self, entry: dict):
        messagebox.showinfo(
            "Password",
            f"Site:     {entry['site']}\n"
            f"Username: {entry['username']}\n"
            f"Password: {entry['password']}",
        )

    def _edit_entry(self, entry: dict):
        def on_save(site, new_user, new_pass):
            # Run HIBP check
            leak = check_password_leak(new_pass)
            if "WARNING" in leak:
                if not messagebox.askyesno("Leaked Password",
                                           f"{leak}\n\nSave anyway?"):
                    return
            update_entry(self._master_password, entry["id"], new_user, new_pass)
            self._status_cb(f"Entry for '{entry['site']}' updated.", GREEN)
            self._on_refresh()
            self.destroy()

        EntryDialog(self, on_save=on_save, entry=entry)

    def _delete_entry(self, entry: dict):
        confirmed = messagebox.askyesno(
            "Delete Credential",
            f"Permanently delete:\n\n"
            f"Site: {entry['site']}\nUser: {entry['username']}\n\n"
            f"This cannot be undone.",
        )
        if not confirmed:
            return
        if delete_entry(entry["id"]):
            self._status_cb(f"Deleted '{entry['username']}' from {entry['site']}.", GREEN)
            self._on_refresh()
            self.destroy()

    def _add_account(self, site: str):
        def on_save(s, user, pw):
            leak = check_password_leak(pw)
            if "WARNING" in leak:
                if not messagebox.askyesno("Leaked Password",
                                           f"{leak}\n\nSave anyway?"):
                    return
            add_entry(self._master_password, s, user, pw)
            self._status_cb(f"New account for '{s}' saved.", GREEN)
            self._on_refresh()
            self.destroy()

        # Pre-fill site, lock it
        dummy_entry = {"site": site, "username": "", "password": ""}
        EntryDialog(self, on_save=on_save, entry=dummy_entry)


# ── Main Vault Screen ─────────────────────────────────────────────────────────

class VaultScreen(ctk.CTkFrame):
    def __init__(self, master, master_password: str):
        super().__init__(master, fg_color=BG_DARK)
        self._master_password = master_password
        self._all_sites       = []   # cached full list
        self.pack(fill="both", expand=True)
        self._build()
        self._load_vault()

    def _build(self):
        # ── Top bar ───────────────────────────────────────────────────────────
        topbar = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=0, height=64)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        ctk.CTkLabel(topbar, text="Passwords",
                     font=("Roboto", 22, "bold"),
                     text_color=TEXT_PRIMARY).pack(side="left", padx=24)

        # Add button (top-right, like Chrome)
        ctk.CTkButton(
            topbar, text="+ Add", width=90, height=38,
            fg_color="transparent", hover_color=BG_HOVER,
            font=("Roboto", 14, "bold"), text_color=ACCENT,
            border_width=2, border_color=ACCENT,
            command=self._open_add_dialog,
        ).pack(side="right", padx=20, pady=12)

        # ── Sub-header with search ────────────────────────────────────────────
        subbar = ctk.CTkFrame(self, fg_color=BG_DARK, height=58)
        subbar.pack(fill="x", padx=24, pady=(14, 0))
        subbar.pack_propagate(False)

        self._subtitle = ctk.CTkLabel(
            subbar,
            text="Create, save, and manage your passwords so you can easily sign in to sites and apps.",
            font=("Roboto", 12), text_color=TEXT_MUTED, wraplength=600, anchor="w",
        )
        self._subtitle.pack(side="left", fill="x", expand=True)

        # Search box
        search_frame = ctk.CTkFrame(subbar, fg_color=BG_INPUT,
                                    corner_radius=20, border_width=1,
                                    border_color=BORDER, height=38)
        search_frame.pack(side="right", ipadx=6)
        search_frame.pack_propagate(False)

        ctk.CTkLabel(search_frame, text="🔍", font=("Segoe UI Emoji", 14),
                     text_color=TEXT_MUTED).pack(side="left", padx=(10, 4))

        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._on_search())
        self._search_entry = ctk.CTkEntry(
            search_frame, textvariable=self._search_var,
            placeholder_text="Search passwords",
            width=210, height=34,
            fg_color="transparent", border_width=0,
            font=("Roboto", 13), text_color=TEXT_PRIMARY,
        )
        self._search_entry.pack(side="left", padx=(0, 8))

        # ── Status bar ────────────────────────────────────────────────────────
        self._status_bar = ctk.CTkLabel(
            self, text="", font=("Roboto", 12),
            text_color=TEXT_MUTED, height=24,
        )
        self._status_bar.pack(fill="x", padx=24)

        # ── Scrollable vault list ─────────────────────────────────────────────
        self._list_frame = ctk.CTkScrollableFrame(
            self, fg_color=BG_DARK, scrollbar_button_color=BORDER,
        )
        self._list_frame.pack(fill="both", expand=True,
                              padx=24, pady=(8, 24))

    # ── Data ──────────────────────────────────────────────────────────────────

    def _load_vault(self):
        """Load all site entries and cache them."""
        self._all_sites = list_all_sites()   # [{id, site, username}]
        self._render_list(self._all_sites)

    def _render_list(self, flat_entries: list):
        """
        Group entries by site and render one VaultRow per site.
        flat_entries: list of {id, site, username}
        """
        # Clear existing rows
        for w in self._list_frame.winfo_children():
            w.destroy()

        if not flat_entries:
            ctk.CTkLabel(
                self._list_frame,
                text="No passwords saved yet.\nClick '+ Add' to store your first credential.",
                font=("Roboto", 14), text_color=TEXT_MUTED,
            ).pack(pady=60)
            return

        # Group by site
        grouped = {}
        for e in flat_entries:
            grouped.setdefault(e["site"], []).append(e)

        # One row per site
        for i, (site, group) in enumerate(sorted(grouped.items())):
            row = VaultRow(
                self._list_frame,
                entries=group,
                on_open=self._open_site_detail,
            )
            row.pack(fill="x", pady=(0, 1))

            # Thin separator (skip last)
            if i < len(grouped) - 1:
                sep = ctk.CTkFrame(self._list_frame,
                                   fg_color=BORDER, height=1)
                sep.pack(fill="x")

    def _on_search(self):
        query = self._search_var.get().strip().lower()
        if not query:
            self._render_list(self._all_sites)
            return
        filtered = [
            e for e in self._all_sites
            if query in e["site"].lower() or query in e["username"].lower()
        ]
        self._render_list(filtered)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _open_add_dialog(self):
        def on_save(site, user, pw):
            leak = check_password_leak(pw)
            if "WARNING" in leak:
                if not messagebox.askyesno("Leaked Password",
                                           f"{leak}\n\nSave anyway?"):
                    return
            add_entry(self._master_password, site, user, pw)
            self._set_status(f"Password for '{site}' saved.", GREEN)
            self._load_vault()

        EntryDialog(self, on_save=on_save)

    def _open_site_detail(self, flat_entries: list):
        """
        Decrypt all entries for this site, then show the detail panel.
        flat_entries come from list_all_sites (no password), so decrypt now.
        """
        site    = flat_entries[0]["site"]
        entries = get_all_for_site(self._master_password, site)
        valid   = [e for e in entries if e["password"] is not None]

        if not entries:
            self._set_status(f"No entries found for '{site}'.", RED)
            return
        if not valid:
            self._set_status("Incorrect master password.", RED)
            return

        SiteDetailPanel(
            self, entries=valid,
            master_password=self._master_password,
            on_refresh=self._load_vault,
            status_callback=self._set_status,
        )

    def _set_status(self, msg: str, color: str = TEXT_MUTED):
        self._status_bar.configure(text=msg, text_color=color)


# ── App Root ──────────────────────────────────────────────────────────────────

class SecureVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Vault")
        self.geometry("780x640")
        self.minsize(700, 500)
        self.configure(fg_color=BG_DARK)

        init_db()
        self._current_screen = None
        self._show_login()

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    def _show_login(self):
        self._clear()
        LoginScreen(self, on_unlock=self._unlock)

    def _unlock(self, master_password: str):
        self._clear()
        self._current_screen = VaultScreen(self, master_password)


if __name__ == "__main__":
    SecureVaultApp().mainloop()
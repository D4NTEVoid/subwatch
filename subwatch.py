
#!/usr/bin/env python3
"""
SubWatch - Automated Subdomain Monitoring

Runs reconnaissance, tracks newly discovered hostnames,
stores historical results in SQLite, and sends notifications.
"""

import os
import re
import sys
import sqlite3
import subprocess
import requests

from pathlib import Path
from urllib.parse import urlsplit
from datetime import datetime, timezone


# --------------------------------------------------
# Configuration
# --------------------------------------------------

DB_PATH = Path(
    os.getenv("RECON_DB_PATH", "/databases/recon.db")
)

TARGETS_DIR = Path(
    os.getenv("TARGETS_DIR", "/targets")
)

RECON_SCRIPT = Path(
    os.getenv("RECON_SCRIPT", "/tools/Recon.sh")
)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

TABLE_NAME = "subdomains"

REQUEST_TIMEOUT = 15


# --------------------------------------------------
# Validation
# --------------------------------------------------

def normalize_domain(value):
    """Validate and normalize a target domain."""

    try:
        domain = value.strip().rstrip(".").encode(
            "idna"
        ).decode("ascii").lower()

        if len(domain) > 253:
            return None

        pattern = (
            r"(?=.{1,253}$)"
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z]{2,63}"
        )

        if not re.fullmatch(pattern, domain):
            return None

        return domain

    except (UnicodeError, ValueError):
        return None


def extract_hostname(value):
    """Extract a normalized hostname from a URL or hostname."""

    try:
        value = value.strip()

        if not value:
            return None

        parsed = urlsplit(
            value if "://" in value else f"//{value}"
        )

        hostname = parsed.hostname

        if not hostname:
            return None

        return normalize_domain(hostname)

    except ValueError:
        return None


def is_in_scope(hostname, domain):
    """Ensure the hostname belongs to the requested target."""

    return (
        hostname == domain
        or hostname.endswith("." + domain)
    )


# --------------------------------------------------
# Database
# --------------------------------------------------

def setup_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH, timeout=30) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                subdomain TEXT,
                date_added TEXT,
                UNIQUE(domain, subdomain)
            )
        """)


def check_and_store(domain, subdomains):
    """Insert unique hostnames and return newly discovered assets."""

    timestamp = datetime.now(timezone.utc).isoformat()

    normalized = {
        hostname
        for item in subdomains
        if (hostname := extract_hostname(item))
        and is_in_scope(hostname, domain)
    }

    with sqlite3.connect(DB_PATH, timeout=30) as conn:

        existing = {
            row[0]
            for row in conn.execute(
                "SELECT subdomain FROM subdomains WHERE domain = ?",
                (domain,)
            )
        }

        new_subdomains = sorted(normalized - existing)

        conn.executemany(
            """
            INSERT OR IGNORE INTO subdomains
            (domain, subdomain, date_added)
            VALUES (?, ?, ?)
            """,
            [
                (domain, subdomain, timestamp)
                for subdomain in new_subdomains
            ]
        )

    return new_subdomains


# --------------------------------------------------
# Reconnaissance
# --------------------------------------------------

def run_recon(domain, target_dir):
    """Execute the reconnaissance pipeline."""

    if not RECON_SCRIPT.is_file():
        raise RuntimeError(
            f"Recon script not found: {RECON_SCRIPT}"
        )

    print(f"[*] Starting reconnaissance for {domain}...")

    subprocess.run(
        ["bash", str(RECON_SCRIPT), domain],
        check=True,
        timeout=None
    )

    output_file = target_dir / "live_subdomains.txt"

    if not output_file.is_file():
        raise RuntimeError(
            f"Recon output not found: {output_file}"
        )

    with output_file.open("r", encoding="utf-8") as file:
        return [
            line.strip()
            for line in file
            if line.strip()
        ]


# --------------------------------------------------
# Notifications
# --------------------------------------------------

def split_messages(message, limit):
    """Split messages without cutting individual lines."""

    chunks = []
    current = ""

    for line in message.splitlines():

        if len(line) > limit:
            line = line[:limit]

        candidate = f"{current}\n{line}" if current else line

        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate

    if current:
        chunks.append(current)

    return chunks


def send_telegram(message):
    """Send notifications through Telegram."""

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Telegram notifications are not configured.")
        return

    url = (
        "https://api.telegram.org/bot"
        f"{TELEGRAM_BOT_TOKEN}/sendMessage"
    )

    try:
        for chunk in split_messages(message, 4000):
            response = requests.post(
                url,
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": chunk
                },
                timeout=REQUEST_TIMEOUT
            )

            response.raise_for_status()

            if not response.json().get("ok"):
                raise RuntimeError("Telegram rejected the message.")

        print("[+] Telegram notification sent.")

    except (requests.RequestException, ValueError, RuntimeError) as exc:
        print(f"[!] Telegram notification failed: {exc}")


def send_discord(message):
    """Send notifications through Discord."""

    if not DISCORD_WEBHOOK_URL:
        print("[!] Discord notifications are not configured.")
        return

    try:
        for chunk in split_messages(message, 1900):
            response = requests.post(
                DISCORD_WEBHOOK_URL,
                json={"content": chunk},
                timeout=REQUEST_TIMEOUT
            )

            response.raise_for_status()

        print("[+] Discord notification sent.")

    except requests.RequestException as exc:
        print(f"[!] Discord notification failed: {exc}")


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <domain.com>")
        sys.exit(1)

    domain = normalize_domain(sys.argv[1])

    if not domain:
        print("[!] Invalid target domain.")
        sys.exit(1)

    TARGETS_DIR.mkdir(parents=True, exist_ok=True)

    root = TARGETS_DIR.resolve()
    target_dir = root / domain

    if target_dir.is_symlink():
        print("[!] Target directory cannot be a symbolic link.")
        sys.exit(1)

    target_dir.mkdir(parents=True, exist_ok=True)

    if target_dir.resolve().parent != root:
        print("[!] Invalid target directory.")
        sys.exit(1)

    lock_dir = target_dir / ".subwatch.lock"

    try:
        lock_dir.mkdir()
    except FileExistsError:
        print("[!] Another SubWatch process may already be running.")
        sys.exit(1)

    try:
        setup_db()

        subdomains = run_recon(domain, target_dir)

        print(f"[+] Retrieved {len(subdomains)} live entries.")

        new_subdomains = check_and_store(
            domain,
            subdomains
        )

        if new_subdomains:

            print(f"[+] Found {len(new_subdomains)} new subdomains.")

            message = (
                f"New subdomains discovered for {domain}:\n\n"
                + "\n".join(new_subdomains)
            )

            send_telegram(message)
            send_discord(message)

        else:
            print("[*] No new subdomains found.")

    except (
        OSError,
        sqlite3.Error,
        subprocess.SubprocessError,
        RuntimeError
    ) as exc:

        print(f"[!] SubWatch failed: {exc}")
        sys.exit(1)

    finally:
        try:
            lock_dir.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    main()

# SubWatch

An automated subdomain monitoring and change-detection utility for bug bounty hunters and penetration testers.

SubWatch integrates with reconnaissance pipelines to periodically discover live subdomains, compare results against historical records, maintain a centralized SQLite database, and notify users when new assets are identified.

## Features

- **Automated Reconnaissance:** Executes an external reconnaissance pipeline to discover subdomains.
- **Change Detection:** Identifies newly discovered hostnames by comparing them against historical records.
- **SQLite Integration:** Maintains persistent records of discovered assets.
- **Hostname Normalization:** Converts URLs and hostnames into normalized hostname records.
- **Duplicate Prevention:** Uses database uniqueness constraints to prevent duplicate entries.
- **Telegram Notifications:** Sends alerts when new subdomains are discovered.
- **Discord Notifications:** Supports Discord webhook-based alerts.
- **Configurable Environment:** Supports custom database, output, and reconnaissance script paths.
- **Target Validation:** Validates domains and ensures discovered hostnames belong to the requested target.

## Requirements

- Python 3.9+
- SQLite3
- Requests
- Bash
- A compatible reconnaissance pipeline

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/subwatch.git
cd subwatch
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Make the script executable:

```bash
chmod +x subwatch.py
```

## Configuration

SubWatch uses environment variables for configuration.

| Variable | Default |
|---|---|
| `RECON_DB_PATH` | `/databases/recon.db` |
| `TARGETS_DIR` | `/targets` |
| `RECON_SCRIPT` | `/tools/Recon.sh` |
| `TELEGRAM_BOT_TOKEN` | Not configured |
| `TELEGRAM_CHAT_ID` | Not configured |
| `DISCORD_WEBHOOK_URL` | Not configured |

Example:

```bash
export RECON_DB_PATH="/databases/recon.db"
export TARGETS_DIR="/targets"
export RECON_SCRIPT="/tools/Recon.sh"
```

### Telegram Notifications

Configure your Telegram bot:

```bash
export TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN"
export TELEGRAM_CHAT_ID="YOUR_CHAT_ID"
```

### Discord Notifications

Configure your Discord webhook:

```bash
export DISCORD_WEBHOOK_URL="YOUR_DISCORD_WEBHOOK"
```

Both notification systems are optional.

## Usage

```bash
python3 subwatch.py <domain>
```

Example:

```bash
python3 subwatch.py example.com
```

SubWatch automatically:

1. Validates the target domain.
2. Initializes the SQLite database.
3. Executes the configured reconnaissance script.
4. Reads discovered live subdomains.
5. Normalizes hostnames and filters out unrelated domains.
6. Compares results with previously recorded assets.
7. Stores newly discovered hostnames.
8. Sends notifications when new assets are found.

## Database Structure

SubWatch uses a SQLite database with the following structure:

| Column | Description |
|---|---|
| `id` | Unique record identifier |
| `domain` | Target root domain |
| `subdomain` | Normalized hostname |
| `date_added` | UTC timestamp of first discovery |

A unique constraint on `(domain, subdomain)` prevents duplicate records.

## Output Structure

```text
targets/
└── example.com/
    ├── subdomains.txt
    ├── bruteforce_result.txt
    ├── live_subdomains.txt
    ├── domains.txt
    └── elapsed_time
```

Database records are maintained separately in the configured SQLite database.

## Monitoring Automation

SubWatch is designed to be executed periodically to identify changes in the target's live subdomain inventory.

For example, it can be scheduled through cron:

```cron
0 */12 * * * /tools/pyenv/bin/python /tools/subwatch.py example.com
```

This example executes reconnaissance every 12 hours.

Each execution compares the newly discovered hostnames against previously stored records.

## Integration

SubWatch is designed to work alongside reconnaissance utilities such as:

- Subfinder
- ShuffleDNS
- MassDNS
- DNSGen
- GAU
- httpx
- Nuclei

It uses an external reconnaissance script to perform discovery and focuses on historical tracking and notifications.

## Responsible Use

This tool is intended for authorized security research, penetration testing, and bug bounty asset monitoring.

- Only monitor domains you are authorized to assess.
- Respect applicable bug bounty program policies.
- Protect database records and notification credentials.
- Avoid excessive reconnaissance frequency and unnecessary traffic.

## Disclaimer

SubWatch is provided for educational and authorized security research purposes. The author is not responsible for misuse or unauthorized activities performed using this software.

## License

MIT License (subject to confirmation of licensing rights and applicable third-party licenses).

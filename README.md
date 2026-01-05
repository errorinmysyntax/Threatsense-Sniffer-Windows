# Threatsense Sniffer (Windows)

Python + Scapy sniffer with alerting, JSON logging, and configurable rules.

## Requirements
- Windows with Npcap installed (WinPcap-compatible mode recommended)
- Python 3.9+

## Install
```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

## Configure
Copy and edit the example config:
```powershell
Copy-Item config.example.json config.json
```

Choose where alerts go:
- File: set `alert_output` to `file` and (optionally) set `log_dir` to a folder.
- Webhook: set `alert_output` to `webhook`, then set `webhook.enabled` to true and set `webhook.url`.
- Both: set `alert_output` to `both`.

Optional upgrades:
- Set `rules_path` to a JSON file to override or extend any config values.
- Use `allowlist`/`denylist` to reduce noise or force alerts.
- Enable `pcap` to save packets that triggered alerts.
- Adjust `log_rotation` and `stats` to control log size and periodic summaries.

## Quickstart
```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
Copy-Item config.example.json config.json
python sniffer.py -c config.json --dry-run
```

## Repo Files
- `CONFIG.md` for configuration tips and examples.
- `rules.example.json` for override settings.

## Run (Admin)
Sniffing usually requires an elevated shell:
```powershell
python sniffer.py -c config.json
```

Dry-run (no alerts, just packet summaries):
```powershell
python sniffer.py -c config.json --dry-run
```

## Notes
- Set `interface` to a specific adapter name if auto-selection fails.
- Set `local_ips` if the auto-detected list is incorrect.

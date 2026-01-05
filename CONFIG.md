# Configuration Guide

This project uses `config.json` (based on `config.example.json`) plus an optional
`rules.json` override file. The override file can change any setting without
modifying your main config.

## Quick Start
```powershell
Copy-Item config.example.json config.json
```

## Core Settings
- `interface`: `auto` or a specific adapter name.
- `bpf_filter`: Packet filter (e.g., `ip`, `tcp`, `udp`).
- `alert_output`: `file`, `webhook`, or `both`.
- `log_dir`: Optional folder for logs (keeps repo clean).
- `rules_path`: Optional override file (relative to `config.json`).

## Example (minimal)
```json
{
  "alert_output": "file",
  "log_dir": "C:\\Users\\f9the\\Documents\\SnifferLogs",
  "rules_path": "rules.json"
}
```

## Example (webhook)
```json
{
  "alert_output": "webhook",
  "webhook": {
    "enabled": true,
    "url": "https://discord.com/api/webhooks/...",
    "timeout_seconds": 5
  }
}
```

## Allow/Deny Lists
Use these to reduce noise or force alerts:
```json
{
  "allowlist": {
    "ips": ["192.168.1.10"],
    "domains": ["example.com"],
    "ports": [443]
  },
  "denylist": {
    "ips": ["10.10.10.10"],
    "domains": ["bad.example"],
    "ports": [4444]
  }
}
```


import argparse
import atexit
import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime

import requests
from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, get_if_addr, get_if_list, sniff
from scapy.utils import PcapWriter


DEFAULTS = {
    "interface": "auto",
    "bpf_filter": "ip",
    "log_path": "alerts.jsonl",
    "alert_console": True,
    "alert_output": "file",
    "alert_file": True,
    "log_dir": "",
    "rules_path": "",
    "webhook": {
        "enabled": False,
        "url": "",
        "timeout_seconds": 5,
    },
    "cooldown_seconds": 30,
    "log_rotation": {
        "enabled": True,
        "max_bytes": 1048576,
        "max_backups": 5,
    },
    "stats": {
        "enabled": True,
        "interval_seconds": 30,
    },
    "allowlist": {
        "ips": [],
        "domains": [],
        "ports": [],
    },
    "denylist": {
        "ips": [],
        "domains": [],
        "ports": [],
    },
    "pcap": {
        "enabled": True,
        "path": "alerts.pcap",
    },
    "local_ips": [],
    "port_scan": {
        "enabled": True,
        "window_seconds": 10,
        "unique_ports_threshold": 20,
    },
    "syn_flood": {
        "enabled": True,
        "window_seconds": 5,
        "syn_threshold": 100,
    },
    "dns_tunnel": {
        "enabled": True,
        "max_domain_length": 60,
        "max_label_length": 20,
        "max_labels": 4,
        "suspicious_entropy_threshold": 0.85,
    },
    "suspicious_ports": {
        "enabled": True,
        "ports": [4444, 1337, 6667, 9001, 8081],
    },
    "basic_auth_leak": {
        "enabled": True,
    },
}


def load_config(path):
    config = json.loads(json.dumps(DEFAULTS))
    if not path:
        return config
    with open(path, "r", encoding="ascii") as handle:
        user = json.load(handle)
    merge_dicts(config, user)
    rules_path = config.get("rules_path") or ""
    if rules_path:
        rules_path = resolve_path(path, rules_path)
        if os.path.exists(rules_path):
            with open(rules_path, "r", encoding="ascii") as handle:
                rules = json.load(handle)
            merge_dicts(config, rules)
    config["_config_path"] = path
    return config


def merge_dicts(base, updates):
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge_dicts(base[key], value)
        else:
            base[key] = value


def resolve_path(config_path, candidate):
    if os.path.isabs(candidate):
        return candidate
    if config_path:
        return os.path.join(os.path.dirname(config_path), candidate)
    return candidate


def resolve_log_path(config, config_path):
    path = config.get("log_path", "alerts.jsonl")
    log_dir = config.get("log_dir") or ""
    if log_dir:
        log_dir = resolve_path(config_path, log_dir)
        path = os.path.join(log_dir, os.path.basename(path))
    return resolve_path(config_path, path)


def utc_now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


class AlertEngine:
    def __init__(self, config, quiet=False):
        self.config = config
        self.quiet = quiet
        self.local_ips = self._resolve_local_ips(config.get("local_ips") or [])
        self.last_alert = {}
        self.syn_scan = defaultdict(lambda: deque())
        self.syn_flood = defaultdict(lambda: deque())
        self.allowlist = config.get("allowlist", {})
        self.denylist = config.get("denylist", {})
        self.stats_cfg = config.get("stats", {})
        self.stats_last = time.time()
        self.packet_count = 0
        self.alert_count = 0
        self.alert_counts = defaultdict(int)
        self.pcap_writer = None
        self._init_pcap_writer()

    def _resolve_local_ips(self, configured):
        if configured:
            return set(configured)
        local_ips = set()
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
            except Exception:
                continue
            if addr and addr != "0.0.0.0":
                local_ips.add(addr)
        return local_ips

    def _init_pcap_writer(self):
        pcap_cfg = self.config.get("pcap", {})
        if not pcap_cfg.get("enabled"):
            return
        path = pcap_cfg.get("path") or "alerts.pcap"
        try:
            self.pcap_writer = PcapWriter(path, append=True, sync=True)
            atexit.register(self.pcap_writer.close)
        except Exception:
            self.pcap_writer = None

    def should_alert(self, key):
        cooldown = self.config.get("cooldown_seconds", 0)
        if cooldown <= 0:
            return True
        now = time.time()
        last = self.last_alert.get(key)
        if last and (now - last) < cooldown:
            return False
        self.last_alert[key] = now
        return True

    def _maybe_print_stats(self):
        if not self.stats_cfg.get("enabled", False):
            return
        interval = self.stats_cfg.get("interval_seconds", 30)
        if interval <= 0:
            return
        now = time.time()
        if (now - self.stats_last) < interval:
            return
        self.stats_last = now
        payload = {
            "timestamp": utc_now(),
            "type": "stats",
            "packets": self.packet_count,
            "alerts": self.alert_count,
            "alerts_by_type": dict(self.alert_counts),
        }
        if self.config.get("alert_console", True) and not self.quiet:
            print(json.dumps(payload, sort_keys=True))

    def _write_pcap(self, pkt):
        if not self.pcap_writer or pkt is None:
            return
        try:
            self.pcap_writer.write(pkt)
        except Exception:
            return

    def _rotate_log(self, path):
        rotate_cfg = self.config.get("log_rotation", {})
        if not rotate_cfg.get("enabled", False):
            return
        max_bytes = rotate_cfg.get("max_bytes", 0)
        if max_bytes <= 0:
            return
        if not os.path.exists(path):
            return
        try:
            if os.path.getsize(path) <= max_bytes:
                return
        except Exception:
            return
        backups = max(0, int(rotate_cfg.get("max_backups", 0)))
        if backups == 0:
            try:
                os.remove(path)
            except Exception:
                return
            return
        for idx in range(backups - 1, 0, -1):
            src = f"{path}.{idx}"
            dst = f"{path}.{idx + 1}"
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except Exception:
                    continue
        try:
            os.replace(path, f"{path}.1")
        except Exception:
            return

    def _domain_matches(self, domain, patterns):
        domain = domain.lower().strip(".")
        for entry in patterns or []:
            candidate = entry.lower().strip(".")
            if domain == candidate:
                return True
            if domain.endswith("." + candidate):
                return True
        return False

    def _is_allowed_ip(self, ip_addr):
        ips = set(self.allowlist.get("ips") or [])
        return ip_addr in ips if ips else False

    def _is_denied_ip(self, ip_addr):
        ips = set(self.denylist.get("ips") or [])
        return ip_addr in ips if ips else False

    def _is_allowed_port(self, port):
        ports = set(self.allowlist.get("ports") or [])
        return port in ports if ports else False

    def _is_denied_port(self, port):
        ports = set(self.denylist.get("ports") or [])
        return port in ports if ports else False

    def emit(self, alert_type, details, pkt=None):
        payload = {
            "timestamp": utc_now(),
            "type": alert_type,
            **details,
        }
        self.alert_count += 1
        self.alert_counts[alert_type] += 1
        if self.config.get("alert_console", True) and not self.quiet:
            print(json.dumps(payload, sort_keys=True))

        output_mode = (self.config.get("alert_output") or "file").lower()
        if output_mode in ("file", "both") and self.config.get("alert_file", True):
            config_path = self.config.get("_config_path")
            log_path = resolve_log_path(self.config, config_path)
            self._rotate_log(log_path)
            with open(log_path, "a", encoding="ascii") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")

        if output_mode in ("webhook", "both"):
            self._send_webhook(payload)
        self._write_pcap(pkt)

    def _send_webhook(self, payload):
        webhook_cfg = self.config.get("webhook", {})
        if not webhook_cfg.get("enabled"):
            return
        url = webhook_cfg.get("url", "")
        if not url:
            return
        body = {
            "content": f"Alert: {payload.get('type')}",
            "embeds": [
                {
                    "title": "Packet Sniffer Alert",
                    "description": json.dumps(payload, indent=2, sort_keys=True),
                    "timestamp": payload.get("timestamp"),
                }
            ],
        }
        try:
            requests.post(url, json=body, timeout=webhook_cfg.get("timeout_seconds", 5))
        except Exception:
            return

    def handle_packet(self, pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        self.packet_count += 1
        self._maybe_print_stats()

        if self._is_denied_ip(src_ip) or self._is_denied_ip(dst_ip):
            key = f"denylist_ip:{src_ip}:{dst_ip}"
            if self.should_alert(key):
                self.emit("denylist_ip", {"src_ip": src_ip, "dst_ip": dst_ip}, pkt=pkt)
            return
        if self._is_allowed_ip(src_ip) or self._is_allowed_ip(dst_ip):
            return

        if TCP in pkt:
            self._handle_tcp(pkt, src_ip, dst_ip)
        if UDP in pkt:
            self._handle_udp(pkt, src_ip, dst_ip)
        if DNS in pkt and pkt[DNS].qd:
            self._handle_dns(pkt, src_ip, dst_ip)

    def _handle_tcp(self, pkt, src_ip, dst_ip):
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        dport = tcp.dport
        sport = tcp.sport

        if self.config["port_scan"]["enabled"]:
            if (flags & 0x02) and not (flags & 0x10):
                self._track_syn_scan(src_ip, dst_ip, dport)

        if self.config["syn_flood"]["enabled"]:
            if (flags & 0x02) and not (flags & 0x10):
                self._track_syn_flood(src_ip, dst_ip, dport)

        if flags == 0:
            key = f"null_scan:{src_ip}:{dst_ip}:{dport}"
            if self.should_alert(key):
                self.emit("null_scan", {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dport})

        if flags == 0x29:
            key = f"xmas_scan:{src_ip}:{dst_ip}:{dport}"
            if self.should_alert(key):
                self.emit("xmas_scan", {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dport})

        if self.config["suspicious_ports"]["enabled"]:
            if dport in self.config["suspicious_ports"]["ports"] and src_ip in self.local_ips:
                key = f"suspicious_port:{src_ip}:{dst_ip}:{dport}"
                if self.should_alert(key):
                    self.emit(
                        "suspicious_port",
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dport,
                            "protocol": "tcp",
                        },
                    )

        if self.config["basic_auth_leak"]["enabled"]:
            if Raw in pkt and b"Authorization: Basic" in bytes(pkt[Raw].load):
                host = self._extract_host(bytes(pkt[Raw].load))
                key = f"basic_auth:{src_ip}:{dst_ip}:{sport}:{dport}"
                if self.should_alert(key):
                    details = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": sport,
                        "dst_port": dport,
                        "protocol": "tcp",
                    }
                    if host:
                        details["host"] = host
                    self.emit("basic_auth_leak", details)

    def _handle_udp(self, pkt, src_ip, dst_ip):
        udp = pkt[UDP]
        dport = udp.dport

        if self.config["suspicious_ports"]["enabled"]:
            if dport in self.config["suspicious_ports"]["ports"] and src_ip in self.local_ips:
                key = f"suspicious_port:{src_ip}:{dst_ip}:{dport}:udp"
                if self.should_alert(key):
                    self.emit(
                        "suspicious_port",
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dport,
                            "protocol": "udp",
                        },
                    )

    def _handle_dns(self, pkt, src_ip, dst_ip):
        dns_cfg = self.config["dns_tunnel"]
        if not dns_cfg["enabled"]:
            return

        qname = pkt[DNSQR].qname
        try:
            domain = qname.decode("ascii").rstrip(".")
        except Exception:
            domain = None
        if not domain:
            return

        labels = domain.split(".")
        if len(domain) >= dns_cfg["max_domain_length"]:
            if self.should_alert(f"dns_tunnel:length:{src_ip}:{domain}"):
                self.emit("dns_tunnel", {"src_ip": src_ip, "dst_ip": dst_ip, "domain": domain})
            return

        if len(labels) >= dns_cfg["max_labels"]:
            if self.should_alert(f"dns_tunnel:labels:{src_ip}:{domain}"):
                self.emit("dns_tunnel", {"src_ip": src_ip, "dst_ip": dst_ip, "domain": domain})
            return

        for label in labels:
            if len(label) >= dns_cfg["max_label_length"]:
                if self.should_alert(f"dns_tunnel:label:{src_ip}:{domain}"):
                    self.emit("dns_tunnel", {"src_ip": src_ip, "dst_ip": dst_ip, "domain": domain})
                return
            if len(label) >= 15:
                ratio = self._base64_ratio(label)
                if ratio >= dns_cfg["suspicious_entropy_threshold"]:
                    if self.should_alert(f"dns_tunnel:entropy:{src_ip}:{domain}"):
                        self.emit("dns_tunnel", {"src_ip": src_ip, "dst_ip": dst_ip, "domain": domain})
                    return

    def _track_syn_scan(self, src_ip, dst_ip, dport):
        scan_cfg = self.config["port_scan"]
        window = scan_cfg["window_seconds"]
        threshold = scan_cfg["unique_ports_threshold"]
        now = time.time()
        queue = self.syn_scan[src_ip]
        queue.append((now, dport))
        while queue and (now - queue[0][0]) > window:
            queue.popleft()
        unique_ports = {entry[1] for entry in queue}
        if len(unique_ports) >= threshold:
            key = f"port_scan:{src_ip}"
            if self.should_alert(key):
                self.emit(
                    "port_scan",
                    {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "unique_ports": len(unique_ports),
                        "window_seconds": window,
                    },
                )

    def _track_syn_flood(self, src_ip, dst_ip, dport):
        flood_cfg = self.config["syn_flood"]
        window = flood_cfg["window_seconds"]
        threshold = flood_cfg["syn_threshold"]
        now = time.time()
        key = (dst_ip, dport)
        queue = self.syn_flood[key]
        queue.append(now)
        while queue and (now - queue[0]) > window:
            queue.popleft()
        if len(queue) >= threshold:
            alert_key = f"syn_flood:{dst_ip}:{dport}"
            if self.should_alert(alert_key):
                self.emit(
                    "syn_flood",
                    {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dport,
                        "syn_count": len(queue),
                        "window_seconds": window,
                    },
                )

    def _base64_ratio(self, label):
        valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
        count = sum(1 for ch in label if ch in valid)
        return count / max(len(label), 1)

    def _extract_host(self, payload):
        try:
            text = payload.decode("ascii", errors="ignore")
        except Exception:
            return None
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
        return None


def parse_args():
    parser = argparse.ArgumentParser(description="Threat-focused packet sniffer with alerting.")
    parser.add_argument("-c", "--config", help="Path to config JSON", required=False)
    parser.add_argument("-i", "--interface", help="Interface name (overrides config)")
    parser.add_argument("-q", "--quiet", help="Disable console output", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    config = load_config(args.config)
    if args.interface:
        config["interface"] = args.interface
    engine = AlertEngine(config, quiet=args.quiet)

    iface = None if config.get("interface") in (None, "auto", "") else config.get("interface")
    sniff(
        iface=iface,
        filter=config.get("bpf_filter", "ip"),
        prn=engine.handle_packet,
        store=False,
    )


if __name__ == "__main__":
    main()

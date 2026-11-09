#!/usr/bin/env python3
"""CTI OSINT -> validate/deduplicate -> VT/AbuseIPDB -> risk -> SQLite -> MISP/Telegram.

Python >=3.10. Supports fully offline validation with --fixture --dry-run.
No external services are contacted when --dry-run is used.
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
import urllib3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any
from urllib.parse import urlsplit, urlunsplit

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)
import requests
from dotenv import load_dotenv

log = logging.getLogger("cti")
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
ALLOWED_TYPES = {"ip-dst", "ip-dst|port", "domain", "url", "md5", "sha1", "sha256"}
HEX_SIZES = {"md5": 32, "sha1": 40, "sha256": 64}
SOURCE_NAMES = {"Feodo", "ThreatFox", "URLhaus", "OTX"}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def envint(name: str, fallback: int, low: int = 0) -> int:
    value = int(os.getenv(name, str(fallback)))
    if value < low:
        raise ValueError(f"{name} must be >= {low}")
    return value


def envfloat(name: str, fallback: float, low: float = 0) -> float:
    value = float(os.getenv(name, str(fallback)))
    if value < low:
        raise ValueError(f"{name} must be >= {low}")
    return value


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def csv_to_list(value: str | None) -> list[str]:
    return [i for i in (value or "").split(",") if i]


def joined(values: Any) -> str:
    return ",".join(sorted(set(str(v).strip() for v in (values or []) if v)))


@dataclass
class Settings:
    db: str = "cti.db"
    output: str = "output"
    timeout: float = 20.0
    max_per_source: int = 3000
    vt_max: int = 4
    vt_min_interval: float = 16.0  # VT Public API: at most 4/min (conservative)
    abuse_max: int = 50
    abuse_daily_limit: int = 900
    cache_hours: float = 24.0
    misp_batch: int = 100
    misp_min_score: int = 40
    threatfox_days: int = 3
    otx_pages: int = 2
    alert_min_score: int = 70
    vt_key: str = ""
    abuse_key: str = ""
    threatfox_key: str = ""
    otx_key: str = ""
    urlhaus_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    misp_verifycert: bool = True
    telegram_token: str = ""
    telegram_chat: str = ""
    dry_run: bool = False
    fixture: str = ""
    no_misp: bool = False
    no_telegram: bool = False

    @classmethod
    def from_env(cls, args: argparse.Namespace) -> Settings:
        return cls(
            db=args.db or os.getenv("CTI_DB", "cti.db"),
            output=args.output or os.getenv("CTI_OUTPUT_DIR", "output"),
            timeout=envfloat("HTTP_TIMEOUT", 20.0, 1.0),
            max_per_source=envint("SOURCE_MAX_RECORDS", 3000, 1),
            vt_max=envint("VIRUSTOTAL_MAX_LOOKUPS", 4),
            vt_min_interval=envfloat("VIRUSTOTAL_MIN_INTERVAL", 16.0),
            abuse_max=envint("ABUSEIPDB_MAX_LOOKUPS", 50),
            abuse_daily_limit=envint("ABUSEIPDB_DAILY_LIMIT", 900, 1),
            cache_hours=envfloat("ENRICH_CACHE_HOURS", 24.0),
            misp_batch=envint("MISP_BATCH_SIZE", 100, 1),
            misp_min_score=envint("MISP_MIN_SCORE", 40),
            threatfox_days=min(7, max(1, envint("THREATFOX_DAYS", 3, 1))),
            otx_pages=envint("OTX_MAX_PAGES", 2, 1),
            alert_min_score=envint("ALERT_MIN_SCORE", 70),
            vt_key=os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
            abuse_key=os.getenv("ABUSEIPDB_API_KEY", "").strip(),
            threatfox_key=os.getenv("THREATFOX_AUTH_KEY", "").strip(),
            otx_key=os.getenv("OTX_API_KEY", "").strip(),
            urlhaus_key=os.getenv("URLHAUS_AUTH_KEY", "").strip(),
            misp_url=os.getenv("MISP_URL", "").strip(),
            misp_key=os.getenv("MISP_KEY", "").strip(),
            misp_verifycert=os.getenv("MISP_VERIFYCERT", "true").lower() == "true",
            telegram_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
            telegram_chat=os.getenv("TELEGRAM_CHAT_ID", "").strip(),
            dry_run=args.dry_run or bool(args.fixture),
            fixture=args.fixture or "",
            no_misp=args.no_misp,
            no_telegram=args.no_telegram,
        )


def normalize_ioc(raw: str, specified_type: str | None = None) -> dict[str, Any] | None:
    """Return canonical value/type/port. Never lowercase a URL path or query."""
    text = str(raw or "").strip()
    if not text or len(text) > 4096 or any(ord(c) < 32 for c in text):
        return None
    st = (specified_type or "").lower()
    # Explicit data source types are validated, not silently reclassified.
    if st in {"ip", "ip-dst", "ipv4", "ipv6"}:
        try:
            ip = ipaddress.ip_address(text)
            return {"type": "ip-dst", "value": ip.compressed.lower(), "port": None}
        except ValueError:
            return None
    if st in {"ip:port", "ip-dst|port"} and text.startswith("[") and "]:" in text:
        try:
            host, porttext = text[1:].rsplit("]:", 1)
            ip = ipaddress.ip_address(host)
            port = int(porttext)
            if 1 <= port <= 65535:
                return {"type": "ip-dst|port", "value": ip.compressed.lower(), "port": port}
        except ValueError:
            return None
    if st in {"ip:port", "ip-dst|port"} or (text.count(":") == 1 and not text.startswith(("http:", "https:"))):
        ip_s, sep, port_s = text.rpartition(":")
        if sep and port_s.isdecimal():
            try:
                ip = ipaddress.ip_address(ip_s.strip("[]"))
                port = int(port_s)
                if 1 <= port <= 65535:
                    return {"type": "ip-dst|port", "value": ip.compressed.lower(), "port": port}
            except ValueError:
                pass
        if st in {"ip:port", "ip-dst|port"}:
            return None
    try:
        ip = ipaddress.ip_address(text)
        return {"type": "ip-dst", "value": ip.compressed.lower(), "port": None}
    except ValueError:
        pass
    lowered = text.lower()
    for kind, length in HEX_SIZES.items():
        if len(text) == length and re.fullmatch(r"[a-fA-F0-9]+", text):
            if st in ("", kind, "filehash-" + kind):
                return {"type": kind, "value": lowered, "port": None}
    if st in HEX_SIZES or st.startswith("filehash-"):
        return None
    if st in ("domain", "hostname", "fqdn") and text.startswith(("http://", "https://")):
        return None
    if st in ("url", "uri", "urlpath") or text.lower().startswith(("http://", "https://")):
        try:
            p = urlsplit(text)
            if p.scheme.lower() not in ("http", "https") or not p.hostname or p.username or p.password:
                return None
            host = p.hostname.encode("idna").decode("ascii").lower()
            ip_literal = False
            try:
                ipaddress.ip_address(host)
                ip_literal = True
            except ValueError:
                pass
            if not ip_literal and not valid_domain(host):
                return None
            if p.port is not None and not 1 <= p.port <= 65535:
                return None
            netloc = ("[" + host + "]") if ":" in host else host
            if p.port and not ((p.scheme.lower() == "http" and p.port == 80) or
                               (p.scheme.lower() == "https" and p.port == 443)):
                netloc += ":" + str(p.port)
            # Preserve path and query: web paths/queries are case-sensitive.
            canon = urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))
            return {"type": "url", "value": canon, "port": None}
        except (ValueError, UnicodeError):
            return None
    if st in ("domain", "hostname", "fqdn", "hostname|port") or "." in text:
        try:
            domain = text.rstrip(".").encode("idna").decode("ascii").lower()
            if valid_domain(domain):
                return {"type": "domain", "value": domain, "port": None}
        except UnicodeError:
            pass
    return None


def valid_domain(domain: str) -> bool:
    if len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    return all(1 <= len(x) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", x)
               for x in labels) and not labels[-1].isdecimal()


def vt_endpoint(item: dict[str, Any]) -> str | None:
    kind, value = item["type"], item["value"]
    if kind in {"ip-dst", "ip-dst|port"}:
        return f"{VT_BASE}/ip_addresses/{value}"
    if kind == "domain":
        return f"{VT_BASE}/domains/{value}"
    if kind == "url":
        urlid = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"{VT_BASE}/urls/{urlid}"
    if kind in HEX_SIZES:
        return f"{VT_BASE}/files/{value}"
    return None


class RequestError(Exception):
    def __init__(self, status: str, message: str = "", code: int | None = None):
        super().__init__(message or status)
        self.status = status
        self.code = code


class Pipeline:
    def __init__(self, cfg: Settings, session: requests.Session | None = None):
        self.cfg = cfg
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "Academic-CTI-Pipeline/4.0"})
        self.db = sqlite3.connect(cfg.db)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self._init_db()
        self.stats: Counter[str] = Counter()
        self.errors: list[str] = []
        self.source_status: dict[str, str] = {}
        self.misp = None
        self._tag_cache: set[str] = set()

    def _init_db(self) -> None:
        # Keep the existing DB table instead of destroying earlier thesis data.
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS iocs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ioc_type TEXT NOT NULL, value TEXT NOT NULL, port INTEGER,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
              sources TEXT NOT NULL, malware TEXT, threat_types TEXT,
              confidence INTEGER DEFAULT 0, abuse_confidence INTEGER DEFAULT 0,
              total_reports INTEGER DEFAULT 0, country TEXT, isp TEXT,
              vt_malicious INTEGER DEFAULT 0, vt_suspicious INTEGER DEFAULT 0,
              vt_harmless INTEGER DEFAULT 0, vt_undetected INTEGER DEFAULT 0,
              vt_total INTEGER DEFAULT 0, vt_reputation INTEGER DEFAULT 0,
              risk_score INTEGER DEFAULT 0, risk_label TEXT DEFAULT 'UNKNOWN',
              pushed_to_misp INTEGER DEFAULT 0, last_pushed_score INTEGER DEFAULT 0,
              misp_event_id TEXT, UNIQUE(ioc_type, value, port)
            );
            CREATE TABLE IF NOT EXISTS cti_runs (
              run_id INTEGER PRIMARY KEY AUTOINCREMENT,
              started_at TEXT, completed_at TEXT, status TEXT, stats_json TEXT
            );
            CREATE TABLE IF NOT EXISTS api_usage (
              service TEXT PRIMARY KEY, last_called TEXT, daily_date TEXT, daily_count INTEGER DEFAULT 0
            );
        """)
        existing = {r["name"] for r in self.db.execute("PRAGMA table_info(iocs)")}
        # Additive migration: existing cti.db remains readable.
        for col, typ in {
            "vt_status": "TEXT", "abuse_status": "TEXT", "vt_checked_at": "TEXT",
            "abuse_checked_at": "TEXT", "enrichment_status": "TEXT", "last_error": "TEXT",
            "vt_threat_label": "TEXT", "last_alerted_at": "TEXT",
        }.items():
            if col not in existing:
                self.db.execute(f"ALTER TABLE iocs ADD COLUMN {col} {typ}")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_ioc_lookup ON iocs(ioc_type,value)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_ioc_risk ON iocs(risk_label,risk_score)")
        self.db.commit()

    def close(self) -> None:
        self.session.close()
        self.db.close()

    def fail(self, message: str) -> None:
        log.warning(message)
        self.errors.append(message)

    def request(self, method: str, url: str, *, service: str, **kwargs: Any) -> requests.Response:
        """Retry temporary failures, but never retry auth errors or 429 indefinitely.
        Avoid logging URLs or exception strings that may contain API credentials.
        """
        for attempt in range(3):
            try:
                response = self.session.request(method, url, timeout=self.cfg.timeout, **kwargs)
            except requests.RequestException as exc:
                if attempt == 2:
                    raise RequestError("NETWORK_ERROR", type(exc).__name__) from exc
                time.sleep(0.5 * (attempt + 1))
                continue
            if response.status_code == 429:
                raise RequestError("RATE_LIMITED", "HTTP 429", 429)
            if response.status_code in (401, 403):
                raise RequestError("AUTH_ERROR", "HTTP authentication/permission error", response.status_code)
            if response.status_code == 404:
                raise RequestError("NOT_FOUND", "HTTP 404", 404)
            if response.status_code >= 500 and attempt < 2 and service != "VirusTotal":
                time.sleep(0.5 * (attempt + 1))
                continue
            if not response.ok:
                raise RequestError("HTTP_ERROR", f"HTTP {response.status_code}", response.status_code)
            return response
        raise RequestError("HTTP_ERROR", f"{service}: retries exhausted")

    def _fetch_json(self, method: str, url: str, service: str, **kwargs: Any) -> dict[str, Any]:
        response = self.request(method, url, service=service, **kwargs)
        try:
            result = response.json()
        except (ValueError, TypeError) as exc:
            raise RequestError("INVALID_JSON") from exc
        if not isinstance(result, dict):
            raise RequestError("INVALID_JSON")
        return result

    @staticmethod
    def make_record(value: str, typ: str | None, source: str, *, confidence: int = 0,
                    malware: str | None = None, threat_type: str | None = None,
                    **context: Any) -> dict[str, Any]:
        return {"value": value, "type": typ, "source": source,
                "confidence": confidence, "malware": malware, "threat_type": threat_type, **context}

    def collect_feodo(self) -> list[dict[str, Any]]:
        data = self.request("GET", FEODO_URL, service="Feodo").text
        result = []
        for line in data.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                result.append(self.make_record(line, "ip", "Feodo", confidence=80,
                                               threat_type="botnet-c2"))
            if len(result) >= self.cfg.max_per_source:
                break
        return result

    def collect_threatfox(self) -> list[dict[str, Any]]:
        if not self.cfg.threatfox_key:
            raise RequestError("MISSING_KEY", "THREATFOX_AUTH_KEY")
        payload = self._fetch_json("POST", THREATFOX_URL, "ThreatFox",
                                   headers={"Auth-Key": self.cfg.threatfox_key},
                                   json={"query": "get_iocs", "days": self.cfg.threatfox_days})
        if payload.get("query_status") not in ("ok", "no_result"):
            raise RequestError("API_ERROR", f"query_status={payload.get('query_status')}")
        result = []
        for item in payload.get("data") or []:
            if not isinstance(item, dict) or not item.get("ioc"):
                continue
            result.append(self.make_record(item["ioc"], item.get("ioc_type"), "ThreatFox",
                                           confidence=as_int(item.get("confidence_level")),
                                           malware=item.get("malware_printable"),
                                           threat_type=item.get("threat_type")))
            if len(result) >= self.cfg.max_per_source:
                break
        return result

    def collect_urlhaus(self) -> list[dict[str, Any]]:
        # URLhaus moved community exports behind Auth-Key-based export URLs.
        if not self.cfg.urlhaus_key:
            raise RequestError("MISSING_KEY", "URLHAUS_AUTH_KEY")
        url = "https://urlhaus-api.abuse.ch/v2/files/exports/" + self.cfg.urlhaus_key + "/recent.csv"
        data = self.request("GET", url, service="URLhaus").text
        result = []
        reader = csv.reader(io.StringIO("\n".join(x for x in data.splitlines()
                                                   if x.strip() and not x.lstrip().startswith("#"))))
        for row in reader:
            # CSV fields can shift with export version: locate URL in any field.
            found = next((x.strip() for x in row if x.strip().lower().startswith(("https://", "http://"))), None)
            if found:
                result.append(self.make_record(found, "url", "URLhaus", confidence=70,
                                               threat_type="malware-url"))
            if len(result) >= self.cfg.max_per_source:
                break
        return result

    def collect_otx(self) -> list[dict[str, Any]]:
        if not self.cfg.otx_key:
            raise RequestError("MISSING_KEY", "OTX_API_KEY")
        result, url, seen = [], OTX_URL, set()
        for _ in range(self.cfg.otx_pages):
            if not url or url in seen:
                break
            seen.add(url)
            # Never follow an untrusted OTX pagination URL to a foreign host.
            if urlsplit(url).hostname != "otx.alienvault.com" or urlsplit(url).scheme != "https":
                raise RequestError("UNSAFE_NEXT_URL")
            data = self._fetch_json("GET", url, "OTX", headers={"X-OTX-API-KEY": self.cfg.otx_key},
                                    params={"limit": 100} if url == OTX_URL else None)
            for pulse in data.get("results", []):
                if not isinstance(pulse, dict):
                    continue
                for item in pulse.get("indicators", []):
                    if isinstance(item, dict) and item.get("indicator"):
                        result.append(self.make_record(item["indicator"], item.get("type"),
                                                       "OTX", confidence=60,
                                                       pulse=pulse.get("name", "")))
                    if len(result) >= self.cfg.max_per_source:
                        break
                if len(result) >= self.cfg.max_per_source:
                    break
            if len(result) >= self.cfg.max_per_source:
                break
            next_url = data.get("next")
            url = requests.compat.urljoin(OTX_URL, next_url) if next_url else ""
        return result

    def collect(self) -> list[dict[str, Any]]:
        if self.cfg.fixture:
            feed = json.loads(Path(self.cfg.fixture).read_text(encoding="utf-8"))
            if not isinstance(feed, dict):
                raise ValueError("Fixture must be a JSON object of sources")
            records = []
            for name in ("Feodo", "ThreatFox", "URLhaus", "OTX"):
                source_data = feed.get(name, [])[:self.cfg.max_per_source]
                self.source_status[name] = "OFFLINE_FIXTURE"
                self.stats[f"source_{name}"] = len(source_data)
                for item in source_data:
                    if isinstance(item, dict):
                        records.append({**item, "source": name})
            return records
        result = []
        for name, collector in (("Feodo", self.collect_feodo),
                                ("ThreatFox", self.collect_threatfox),
                                ("URLhaus", self.collect_urlhaus), ("OTX", self.collect_otx)):
            try:
                found = collector()
                self.source_status[name] = "OK" if found else "EMPTY"
                self.stats[f"source_{name}"] = len(found)
                result.extend(found)
                log.info("%s: %s IOC", name, len(found))
            except (RequestError, ValueError, OSError) as exc:
                self.source_status[name] = exc.status if isinstance(exc, RequestError) else "ERROR"
                self.fail(f"{name}: {self.source_status[name]} ({str(exc)[:100]})")
        return result

    def normalize(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: dict[tuple[str, str, int | None], dict[str, Any]] = {}
        for item in raw:
            parsed = normalize_ioc(item.get("value", ""), item.get("type"))
            if not parsed:
                self.stats["invalid"] += 1
                continue
            key = (parsed["type"], parsed["value"], parsed["port"])
            if key in merged:
                self.stats["duplicates"] += 1
            else:
                merged[key] = {**parsed, "sources": set(), "malware": set(),
                               "threat_types": set(), "confidence": [], "pulses": set()}
            rec = merged[key]
            rec["sources"].add(str(item.get("source", "Unknown")))
            for source_field, target in (("malware", "malware"), ("threat_type", "threat_types"),
                                         ("pulse", "pulses")):
                if item.get(source_field):
                    rec[target].add(str(item[source_field]).replace(",", " ")[:200])
            conf = as_int(item.get("confidence"))
            if 0 < conf <= 100:
                rec["confidence"].append(conf)
        rows = []
        for rec in merged.values():
            for col in ("sources", "malware", "threat_types", "pulses"):
                rec[col] = sorted(rec[col])
            rows.append(rec)
        self.stats["unique"] = len(rows)
        return rows

    def _existing(self, item: dict[str, Any]) -> sqlite3.Row | None:
        # Using IS for port makes NULL = NULL work, unlike the old UNIQUE/upsert.
        return self.db.execute(
            "SELECT * FROM iocs WHERE ioc_type=? AND value=? AND port IS ? ORDER BY id LIMIT 1",
            (item["type"], item["value"], item["port"]),
        ).fetchone()

    def persist(self, records: list[dict[str, Any]]) -> None:
        """Idempotent DB update across runs; retain all historical sources & enrichment."""
        now = utcnow()
        with self.db:
            for item in records:
                prev = self._existing(item)
                if prev:
                    item["sources"] = sorted(set(item["sources"]) | set(csv_to_list(prev["sources"])))
                    item["malware"] = sorted(set(item["malware"]) | set(csv_to_list(prev["malware"])))
                    item["threat_types"] = sorted(set(item["threat_types"]) | set(csv_to_list(prev["threat_types"])))
                    item["confidence"] = [max([as_int(prev["confidence"])] + item["confidence"])]
                    item["id"] = prev["id"]
                    self.db.execute("""
                        UPDATE iocs SET last_seen=?,sources=?,malware=?,threat_types=?,confidence=?
                        WHERE id=?
                    """, (now, joined(item["sources"]), joined(item["malware"]),
                          joined(item["threat_types"]), max(item["confidence"]), item["id"]))
                else:
                    cursor = self.db.execute("""
                        INSERT INTO iocs (ioc_type,value,port,first_seen,last_seen,sources,
                                          malware,threat_types,confidence)
                        VALUES (?,?,?,?,?,?,?,?,?)
                    """, (item["type"], item["value"], item["port"], now, now,
                          joined(item["sources"]), joined(item["malware"]),
                          joined(item["threat_types"]), max(item["confidence"], default=0)))
                    item["id"] = cursor.lastrowid
                # Reuse successful prior lookups; keep old data when services are unavailable.
                dbitem = self.db.execute("SELECT * FROM iocs WHERE id=?", (item["id"],)).fetchone()
                for name in ("vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected",
                             "vt_total", "vt_reputation", "abuse_confidence", "total_reports"):
                    item[name] = as_int(dbitem[name])
                for name in ("country", "isp", "vt_threat_label", "vt_status", "abuse_status",
                             "vt_checked_at", "abuse_checked_at"):
                    item[name] = dbitem[name]

    def _cache_fresh(self, item: dict[str, Any], service: str) -> bool:
        stamp = item.get(service + "_checked_at")
        if not stamp or item.get(service + "_status") != "OK":
            return False
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(stamp)
            return age < timedelta(hours=self.cfg.cache_hours)
        except (ValueError, TypeError):
            return False

    def _reserve_vt_quota(self) -> bool:
        """Persist VT cadence across cron invocations. Return False if max per-day reached."""
        row = self.db.execute("SELECT * FROM api_usage WHERE service='VirusTotal'").fetchone()
        today = datetime.now(timezone.utc).date().isoformat()
        if row and row["daily_date"] == today and as_int(row["daily_count"]) >= 500:
            return False
        if row and row["last_called"]:
            try:
                elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(row["last_called"])).total_seconds()
                delay = max(0.0, self.cfg.vt_min_interval - elapsed)
                if delay:
                    log.info("Waiting %.1fs for VirusTotal rate limit", delay)
                    time.sleep(delay)
            except ValueError:
                pass
        new_date = datetime.now(timezone.utc).date().isoformat()
        cnt = (as_int(row["daily_count"]) if row and row["daily_date"] == new_date else 0) + 1
        with self.db:
            self.db.execute("""INSERT INTO api_usage (service,last_called,daily_date,daily_count)
                VALUES ('VirusTotal',?,?,?) ON CONFLICT(service) DO UPDATE SET
                last_called=excluded.last_called,daily_date=excluded.daily_date,daily_count=excluded.daily_count
            """, (utcnow(), new_date, cnt))
        return True

    def _reserve_abuse_quota(self) -> bool:
        """Conservative daily quota shared between cron executions."""
        row = self.db.execute("SELECT * FROM api_usage WHERE service='AbuseIPDB'").fetchone()
        today = datetime.now(timezone.utc).date().isoformat()
        cnt = as_int(row["daily_count"]) if row and row["daily_date"] == today else 0
        if cnt >= self.cfg.abuse_daily_limit:
            return False
        with self.db:
            self.db.execute("""INSERT INTO api_usage(service,last_called,daily_date,daily_count)
                VALUES('AbuseIPDB',?,?,?) ON CONFLICT(service) DO UPDATE SET
                last_called=excluded.last_called,daily_date=excluded.daily_date,daily_count=excluded.daily_count
            """, (utcnow(), today, cnt + 1))
        return True

    def enrich(self, records: list[dict[str, Any]]) -> None:
        if self.cfg.dry_run:
            simulated = json.loads(Path(self.cfg.fixture).read_text(encoding="utf-8")).get("_enrichment", {}) if self.cfg.fixture else {}
            for item in records:
                item["vt_status"] = "DRY_RUN" if not self._cache_fresh(item, "vt") else "OK"
                item["abuse_status"] = "DRY_RUN" if not self._cache_fresh(item, "abuse") else "OK"
                fake_data = simulated.get(f"{item['type']}|{item['value']}", {})
                if fake_data:
                    for field in ("vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected",
                                  "vt_total", "abuse_confidence", "total_reports"):
                        if field in fake_data:
                            item[field] = as_int(fake_data[field])
                    item["vt_status"] = "SIMULATED"
                    item["abuse_status"] = "SIMULATED" if item["type"] in ("ip-dst", "ip-dst|port") else "NOT_APPLICABLE"
                    self.stats["simulated_enrichment"] += 1
            return
        # Highest source-supported confidence first: avoids wasting scarce API quota
        # on random early elements. Do not treat unqueried IOC as clean.
        priority = sorted(records, key=lambda r: (len(r["sources"]),
                                                 max(r["confidence"], default=0),
                                                 bool(r["malware"])), reverse=True)
        if self.cfg.vt_key and self.cfg.vt_max > 0:
            vt_limit = self.cfg.vt_max
            log.info("VirusTotal: tối đa %d lượt tra cứu mới cho chu kỳ này (chờ >= %.1fs giữa các lượt)", vt_limit, self.cfg.vt_min_interval)
            for item in priority:
                if not vt_limit:
                    break
                if not vt_endpoint(item):
                    continue
                if item["type"] in ("ip-dst", "ip-dst|port") and not ipaddress.ip_address(item["value"]).is_global:
                    item["vt_status"] = "NOT_PUBLIC_IP"
                    continue
                if self._cache_fresh(item, "vt"):
                    self.stats["vt_cached"] += 1
                    continue
                if not self._reserve_vt_quota():
                    self.fail("VirusTotal: daily public-API quota reached")
                    break
                vt_limit -= 1
                self.stats["vt_queries"] += 1
                try:
                    resp = self._fetch_json("GET", vt_endpoint(item), "VirusTotal",
                                            headers={"x-apikey": self.cfg.vt_key,
                                                     "Accept": "application/json"})
                    attrs = (resp.get("data") or {}).get("attributes") or {}
                    stats = attrs.get("last_analysis_stats") or {}
                    for category in ("malicious", "suspicious", "harmless", "undetected"):
                        item["vt_" + category] = as_int(stats.get(category))
                    # All reported engine categories count in the denominator.
                    item["vt_total"] = sum(max(0, as_int(v)) for v in stats.values())
                    item["vt_reputation"] = as_int(attrs.get("reputation"))
                    item["vt_threat_label"] = ((attrs.get("popular_threat_classification") or {})
                                                .get("suggested_threat_label"))
                    item["vt_status"] = "OK"
                    item["vt_checked_at"] = utcnow()
                    self.stats["vt_ok"] += 1
                except RequestError as exc:
                    item["vt_status"] = exc.status
                    self.fail(f"VirusTotal ({item['value'][:70]}): {exc.status}")
                    if exc.status in {"RATE_LIMITED", "AUTH_ERROR"}:
                        break
        else:
            log.info("VirusTotal: skipped (no API key or lookup limit = 0)")
        if self.cfg.abuse_key and self.cfg.abuse_max > 0:
            abuse_limit = self.cfg.abuse_max
            log.info("AbuseIPDB: tối đa %d lượt tra cứu IP trong chu kỳ này", abuse_limit)
            for item in priority:
                if not abuse_limit:
                    break
                if item["type"] not in ("ip-dst", "ip-dst|port"):
                    continue
                # Never send private/test/reserved addresses to public reputation APIs.
                if not ipaddress.ip_address(item["value"]).is_global:
                    item["abuse_status"] = "NOT_PUBLIC_IP"
                    continue
                if self._cache_fresh(item, "abuse"):
                    self.stats["abuse_cached"] += 1
                    continue
                if not self._reserve_abuse_quota():
                    self.fail("AbuseIPDB: configured daily request limit reached")
                    break
                abuse_limit -= 1
                self.stats["abuse_queries"] += 1
                try:
                    body = self._fetch_json("GET", ABUSE_URL, "AbuseIPDB",
                                            headers={"Key": self.cfg.abuse_key, "Accept": "application/json"},
                                            params={"ipAddress": item["value"], "maxAgeInDays": 90})
                    info = body.get("data") or {}
                    item["abuse_confidence"] = as_int(info.get("abuseConfidenceScore"))
                    item["total_reports"] = as_int(info.get("totalReports"))
                    item["country"] = info.get("countryCode")
                    item["isp"] = info.get("isp")
                    item["abuse_status"] = "OK"
                    item["abuse_checked_at"] = utcnow()
                    self.stats["abuse_ok"] += 1
                except RequestError as exc:
                    item["abuse_status"] = exc.status
                    self.fail(f"AbuseIPDB ({item['value'][:70]}): {exc.status}")
                    if exc.status in ("RATE_LIMITED", "AUTH_ERROR"):
                        break
        else:
            log.info("AbuseIPDB: skipped (no API key or lookup limit = 0)")

    @staticmethod
    def score(item: dict[str, Any]) -> dict[str, Any]:
        """Preserve scoring weights/thresholds from the user's original 4(2).py."""
        source_count = len(item["sources"])
        source_score = 25 if source_count >= 4 else 20 if source_count == 3 else 15 if source_count == 2 else 8
        conf = max(item.get("confidence", []), default=0)
        conf_score = min(20, int(conf * .20))
        malware_score = 10 if item["malware"] else 0
        type_score = 10 if item["threat_types"] else 0
        abuse_score = min(15, int(as_int(item.get("abuse_confidence")) * .15))
        total = as_int(item.get("vt_total"))
        vt_score = (min(20, int((as_int(item.get("vt_malicious")) +
                                 0.5 * as_int(item.get("vt_suspicious"))) / total * 20))
                    if total > 0 else 0)
        item["score_parts"] = {"source": source_score, "confidence": conf_score,
                               "malware": malware_score, "threat_type": type_score,
                               "abuseipdb": abuse_score, "virustotal": vt_score}
        item["risk_score"] = min(100, sum(item["score_parts"].values()))
        has_evidence = bool(conf or item["malware"] or item["threat_types"] or
                            item.get("vt_status") == "OK" or item.get("abuse_status") == "OK")
        label = ("UNKNOWN" if not has_evidence else
                 "HIGH" if item["risk_score"] >= 70 else
                 "MEDIUM" if item["risk_score"] >= 40 else "LOW")
        item["risk_label"] = label
        item["enrichment_status"] = (
            "SIMULATED" if item.get("vt_status") == "SIMULATED"
            else "ENRICHED" if (item.get("vt_status") == "OK" or item.get("abuse_status") == "OK")
            else "STALE_CACHE" if (item.get("vt_checked_at") or item.get("abuse_checked_at"))
            else "SOURCE_ONLY"
        )
        return item

    def persist_analysis(self, records: list[dict[str, Any]]) -> None:
        fields = ["abuse_confidence", "total_reports", "country", "isp", "vt_malicious",
                  "vt_suspicious", "vt_harmless", "vt_undetected", "vt_total", "vt_reputation",
                  "vt_status", "abuse_status", "vt_checked_at", "abuse_checked_at",
                  "vt_threat_label", "enrichment_status", "risk_score", "risk_label"]
        set_sql = ", ".join(f"{c}=?" for c in fields)
        with self.db:
            for item in records:
                self.db.execute(f"UPDATE iocs SET {set_sql} WHERE id=?",
                                [item.get(c) for c in fields] + [item["id"]])

    def candidates(self) -> list[dict[str, Any]]:
        """Only previously unsent IOC; rerunning a cron job does not create repeats."""
        rows = self.db.execute("""SELECT * FROM iocs WHERE pushed_to_misp=0 AND
            risk_label IN ('HIGH','MEDIUM','LOW') AND risk_score>=?
            ORDER BY risk_score DESC,id ASC""", (self.cfg.misp_min_score,)).fetchall()
        result = []
        for r in rows:
            obj = dict(r)
            obj["type"] = obj["ioc_type"]
            obj["sources"] = csv_to_list(obj["sources"])
            obj["malware"] = csv_to_list(obj["malware"])
            obj["threat_types"] = csv_to_list(obj["threat_types"])
            result.append(obj)
        return result

    def _misp_connect(self) -> bool:
        if not self.cfg.misp_url or not self.cfg.misp_key:
            self.fail("MISP: missing MISP_URL/MISP_KEY; synchronization skipped")
            return False
        try:
            from pymisp import PyMISP
        except ImportError:
            self.fail("MISP: PyMISP is not installed. Run pip install -r requirements.txt")
            return False
        try:
            self.misp = PyMISP(self.cfg.misp_url, self.cfg.misp_key, self.cfg.misp_verifycert)
            return True
        except Exception as exc:
            self.fail(f"MISP: connection failed ({type(exc).__name__})")
            return False

    @staticmethod
    def _attribute_value(item: dict[str, Any]) -> str:
        if item["type"] == "ip-dst|port":
            return f"{item['value']}|{item['port']}"
        return str(item["value"])

    @staticmethod
    def _tags(item: dict[str, Any]) -> list[str]:
        tags = ["cti:automated", "risk:" + item["risk_label"].lower()]
        for src in item["sources"]:
            safe = re.sub(r"[^a-z0-9_-]", "-", src.lower())[:60]
            tags.append("source:" + safe)
        return sorted(set(tags))

    def _ensure_tag(self, name: str) -> bool:
        if name in self._tag_cache:
            return True
        try:
            existing = self.misp.search_tags(tagname=name, strict_tagname=True, pythonify=True)
            if not existing:
                from pymisp import MISPTag
                tag = MISPTag()
                tag.name = name
                result = self.misp.add_tag(tag, pythonify=True)
                if isinstance(result, dict) and (result.get("errors") or result.get("error")):
                    raise RuntimeError("tag creation denied")
            self._tag_cache.add(name)
            return True
        except Exception as exc:
            self.fail(f"MISP: cannot register tag {name} ({type(exc).__name__}); comments are retained")
            return False

    def _create_event(self, batch: list[dict[str, Any]]):
        from pymisp import MISPEvent
        event = MISPEvent()
        event.info = "Automated CTI Collection - " + datetime.now().strftime("%Y-%m-%d %H:%M")
        event.distribution = 0  # organization only; do not publish automatically
        event.analysis = 1  # initial analysis; no premature claim of completion
        maximum = max(i["risk_score"] for i in batch)
        event.threat_level_id = 1 if maximum >= 70 else 2 if maximum >= 40 else 3
        items_by_key = {}
        for item in batch:
            val = self._attribute_value(item)
            comment = (f"Sources: {', '.join(item['sources'])} | Risk: {item['risk_label']} "
                       f"({item['risk_score']}/100) | Enrichment: {item.get('enrichment_status') or 'n/a'} "
                       f"| VT: {item.get('vt_malicious',0)}/{item.get('vt_total',0)} "
                       f"| AbuseIPDB: {item.get('abuse_confidence',0)}")
            attr = event.add_attribute(type=item["type"], value=val, comment=comment[:1000], to_ids=True)
            for tag in self._tags(item):
                if self._ensure_tag(tag):
                    attr.add_tag(tag)
            items_by_key[(item["type"], val)] = item
        created = self.misp.add_event(event, pythonify=True)
        if not created or isinstance(created, dict):
            raise RuntimeError("MISP did not acknowledge a valid event")
        eid = getattr(created, "id", None)
        if not eid:
            raise RuntimeError("MISP did not return event ID")
        attrs = getattr(created, "attributes", None) or []
        if not attrs:
            try:
                refreshed = self.misp.get_event(eid, pythonify=True)
                attrs = getattr(refreshed, "attributes", []) or []
            except Exception:
                pass
        # Count only successfully created/returned attributes, not the entire batch.
        acknowledged = {}
        for attr in attrs:
            key = (getattr(attr, "type", None), getattr(attr, "value", None))
            if key in items_by_key:
                item = items_by_key[key]
                acknowledged[item["id"]] = item
                # Explicit server-side attachment for MISP versions that ignore embedded tags.
                for tag in self._tags(item):
                    if tag in self._tag_cache:
                        try:
                            self.misp.tag(getattr(attr, "uuid", getattr(attr, "id", "")), tag)
                        except Exception:
                            pass  # tag remains in comment when unavailable
        return str(eid), list(acknowledged.values())

    def push_misp(self) -> None:
        candidates = self.candidates()
        self.stats["misp_candidates"] = len(candidates)
        if not candidates or self.cfg.no_misp:
            return
        if self.cfg.dry_run:
            log.info("DRY RUN: would send %s IOC to MISP", len(candidates))
            return
        if not self._misp_connect():
            return
        for pos in range(0, len(candidates), self.cfg.misp_batch):
            batch = candidates[pos:pos + self.cfg.misp_batch]
            try:
                event_id, acknowledged = self._create_event(batch)
                if not acknowledged:
                    self.fail(f"MISP: event {event_id} created but attributes not verified")
                    continue
                with self.db:
                    for item in acknowledged:
                        self.db.execute("""UPDATE iocs SET pushed_to_misp=1,
                                last_pushed_score=?,misp_event_id=? WHERE id=?""",
                                        (item["risk_score"], event_id, item["id"]))
                self.stats["misp_events"] += 1
                self.stats["misp_attributes"] += len(acknowledged)
                if len(acknowledged) < len(batch):
                    self.fail(f"MISP: only {len(acknowledged)}/{len(batch)} attributes acknowledged")
            except Exception as exc:
                self.fail(f"MISP: batch failed ({type(exc).__name__}: {str(exc)[:120]})")

    def send_telegram(self, current: list[dict[str, Any]] | None = None) -> None:
        # Notifications are independent of MISP availability; only HIGH and
        # never already alerted rows are included. Count always matches the DB.
        rows = self.db.execute("""SELECT * FROM iocs WHERE risk_label='HIGH'
            AND risk_score>=? AND last_alerted_at IS NULL ORDER BY risk_score DESC,id""",
                               (self.cfg.alert_min_score,)).fetchall()
        if current is not None:
            # Do not accidentally alert for stale HIGH from previous runs.
            current_ids = {r["id"] for r in current if r.get("risk_label") == "HIGH"}
            rows = [r for r in rows if r["id"] in current_ids]
        self.stats["alerts_pending"] = len(rows)
        if not rows or self.cfg.no_telegram:
            return
        if self.cfg.dry_run:
            log.info("DRY RUN: would alert for %d HIGH IOC", len(rows))
            return
        if not self.cfg.telegram_token or not self.cfg.telegram_chat:
            self.fail("Telegram: missing bot token or chat ID; alert skipped")
            return
        # Send in bounded chunks to satisfy Telegram's 4096-character message limit.
        for offset in range(0, len(rows), 15):
            batch = rows[offset:offset + 15]
            lines = [f"🚨 CTI HIGH RISK ALERT | New HIGH {offset + 1}-{offset + len(batch)}/{len(rows)}"]
            for item in batch:
                lines.append(f"- {str(item['value'])[:125]} | {item['ioc_type']} | "
                             f"score={item['risk_score']}/100 | sources={item['sources']} | "
                             f"VT={item['vt_malicious']}/{item['vt_total']}")
            message = "\n".join(lines)[:3900]
            # URL contains bot token: never log the URL or response body.
            url = "https://api.telegram.org/bot" + self.cfg.telegram_token + "/sendMessage"
            try:
                response = self._fetch_json("POST", url, "Telegram",
                                            json={"chat_id": self.cfg.telegram_chat, "text": message})
                if not response.get("ok"):
                    raise RequestError("API_ERROR", "Telegram ok=false")
                with self.db:
                    self.db.executemany("UPDATE iocs SET last_alerted_at=? WHERE id=?",
                                        [(utcnow(), r["id"]) for r in batch])
                self.stats["alerts_sent"] += len(batch)
            except RequestError as exc:
                self.fail("Telegram: " + exc.status + ". Check bot membership/chat permissions")
                break

    def write_report(self, started: str, status: str, records: list[dict[str, Any]]) -> Path:
        folder = Path(self.cfg.output)
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        for field in ("raw", "invalid", "duplicates", "unique", "vt_queries", "vt_ok",
                      "abuse_queries", "abuse_ok", "misp_candidates", "misp_events",
                      "misp_attributes", "alerts_pending", "alerts_sent",
                      "risk_high", "risk_medium", "risk_low", "risk_unknown"):
            self.stats.setdefault(field, 0)
        report = {
            "started_at": started, "completed_at": utcnow(), "status": status,
            "dry_run": self.cfg.dry_run, "sources": self.source_status,
            "stats": dict(self.stats), "risk_distribution": dict(Counter(r["risk_label"] for r in records)),
            "errors": self.errors,
            "notes": "SOURCE_ONLY is NOT a clean/safe verdict. Scoring is rule-based, not proof of compromise."
        }
        path = folder / f"cti_report_{stamp}.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        csvpath = folder / f"cti_iocs_{stamp}.csv"
        fields = ["type", "value", "port", "sources", "risk_score", "risk_label",
                  "enrichment_status", "vt_status", "abuse_status", "vt_malicious", "vt_total",
                  "abuse_confidence", "score_parts"]
        with csvpath.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for item in records:
                w.writerow({k: json.dumps(item[k], ensure_ascii=False) if isinstance(item.get(k), (list, dict))
                            else item.get(k, "") for k in fields})
        with self.db:
            self.db.execute("""INSERT INTO cti_runs(started_at,completed_at,status,stats_json)
                VALUES(?,?,?,?)""", (started, utcnow(), status,
                                       json.dumps(report, ensure_ascii=False)))
        log.info("Report JSON: %s | IOC CSV: %s", path, csvpath)
        return path

    def run(self) -> dict[str, Any]:
        started = utcnow()
        began = time.monotonic()
        records: list[dict[str, Any]] = []
        try:
            raw = self.collect()
            self.stats["raw"] = len(raw)
            records = self.normalize(raw)
            self.persist(records)
            self.enrich(records)
            for item in records:
                self.score(item)
            self.persist_analysis(records)
            self.stats.update({"risk_" + k.lower(): v for k, v in
                               Counter(r["risk_label"] for r in records).items()})
            self.push_misp()
            self.send_telegram(records)
            status = "PARTIAL" if self.errors else "SUCCESS"
            if not raw and self.errors:
                status = "FAILED"
        except Exception as exc:
            self.fail(f"Pipeline fatal: {type(exc).__name__}: {str(exc)[:120]}")
            status = "FAILED"
        self.stats["duration_seconds"] = round(time.monotonic() - began, 2)
        self.write_report(started, status, records)
        log.info("DONE | status=%s raw=%d unique=%d high=%d medium=%d low=%d unknown=%d misp=%d alert=%d",
                 status, self.stats["raw"], self.stats["unique"], self.stats["risk_high"],
                 self.stats["risk_medium"], self.stats["risk_low"], self.stats["risk_unknown"],
                 self.stats["misp_attributes"], self.stats["alerts_sent"])
        return {"status": status, "stats": dict(self.stats), "errors": self.errors}


def main() -> int:
    p = argparse.ArgumentParser(description="Academic CTI OSINT pipeline. Use --fixture for offline tests.")
    p.add_argument("--dry-run", action="store_true", help="Never contact external sources/APIs or send alerts")
    p.add_argument("--fixture", default="", help="Local JSON input; implies --dry-run")
    p.add_argument("--db", default="", help="SQLite database path")
    p.add_argument("--output", default="", help="Report directory")
    p.add_argument("--vt-max", type=int, default=None, help="Tối đa lượt VirusTotal trong chu kỳ (khuyến nghị 4)")
    p.add_argument("--abuse-max", type=int, default=None, help="Tối đa lượt AbuseIPDB trong chu kỳ")
    p.add_argument("--no-vt", action="store_true", help="Bỏ qua VirusTotal trong chu kỳ này")
    p.add_argument("--no-abuse", action="store_true", help="Bỏ qua AbuseIPDB trong chu kỳ này")
    p.add_argument("--no-misp", action="store_true")
    p.add_argument("--no-telegram", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    load_dotenv()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s | %(levelname)-7s | %(message)s")
    cfg = Settings.from_env(args)
    if args.vt_max is not None:
        cfg.vt_max = args.vt_max
    if args.abuse_max is not None:
        cfg.abuse_max = args.abuse_max
    if args.no_vt:
        cfg.vt_max = 0
    if args.no_abuse:
        cfg.abuse_max = 0
    if cfg.vt_max < 0 or cfg.abuse_max < 0:
        p.error("--vt-max và --abuse-max phải >= 0")
    # Keep VT cadence >=15s under public API, even if .env is older.
    if cfg.vt_max > 0 and cfg.vt_min_interval < 15.0:
        log.warning("VIRUSTOTAL_MIN_INTERVAL quá thấp; nâng lên 16 giây")
        cfg.vt_min_interval = 16.0
    log.info("Configuration: VT max=%s | AbuseIPDB max=%s | MISP=%s | Telegram=%s",
             cfg.vt_max, cfg.abuse_max, "off" if cfg.no_misp else "on",
             "off" if cfg.no_telegram else "on")
    Path(cfg.output).mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(Path(cfg.output) / "cti_pipeline.log",
                                  maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s"))
    log.addHandler(handler)
    if cfg.dry_run and not cfg.fixture:
        p.error("--dry-run requires --fixture (no external collection in dry-run mode)")
    # Prevent overlapping cron jobs to avoid duplicate Event creation.
    lock = Path(cfg.db + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        log.error("Another run may be active (%s). Remove stale lock only after verifying.", lock)
        return 2
    try:
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
        pipeline = Pipeline(cfg)
        try:
            try:
                outcome = pipeline.run()
            except KeyboardInterrupt:
                log.warning("Dừng chương trình theo yêu cầu Ctrl+C. Chu kỳ chưa hoàn tất.")
                return 130
        finally:
            pipeline.close()
    finally:
        lock.unlink(missing_ok=True)
    return 0 if outcome["status"] == "SUCCESS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

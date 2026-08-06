#!/usr/bin/env python3
"""
Read-only website health checker.
Focus: uptime + malware detection. No logins, credentials, or client device access.
"""

from __future__ import annotations

import json
import os
import smtplib
import socket
import ssl
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

from checks import analyze_malware, check_dmarc, check_domain_authority

ROOT = Path(__file__).resolve().parent
SITES_FILE = ROOT / "config" / "sites.json"
RESULTS_DIR = ROOT / "results"
DASHBOARD_DATA = ROOT / "dashboard" / "data.json"

TIMEOUT_SECONDS = 20
SLOW_THRESHOLD_MS = 3000
SSL_WARNING_DAYS = 14
HTTP_RETRIES = 3

# Real browser UA — some hosts/WAFs block custom bot strings, especially from datacenter IPs.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
FALLBACK_USER_AGENT = "WebsiteHealthMonitor/1.0 (read-only; +internal)"


def load_sites() -> list[dict]:
    with open(SITES_FILE, encoding="utf-8") as f:
        return json.load(f)


def check_ssl_expiry(hostname: str, port: int = 443) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure:
                cert = secure.getpeercert()
                expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y GMT")
                expires = expires.replace(tzinfo=timezone.utc)
                days_left = (expires - datetime.now(timezone.utc)).days
                return {
                    "valid": days_left > 0,
                    "expires": expires.isoformat(),
                    "days_left": days_left,
                }
    except Exception as exc:
        return {"valid": False, "expires": None, "days_left": None, "error": str(exc)}


def check_site(site: dict) -> dict:
    url = site["url"]
    name = site["name"]
    expected = site.get("expected_status", [200])
    parsed = urlparse(url)
    hostname = parsed.hostname or url

    result = {
        "name": name,
        "url": url,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": "down",
        "http_status": None,
        "response_time_ms": None,
        "final_url": None,
        "ssl": None,
        "malware": None,
        "dmarc": None,
        "authority": None,
        "issues": [],
    }

    load_dotenv(ROOT / ".env")

    ssl_info = check_ssl_expiry(hostname)
    result["ssl"] = ssl_info
    result["dmarc"] = check_dmarc(hostname)
    result["authority"] = check_domain_authority(hostname)

    if not ssl_info.get("valid"):
        result["issues"].append("SSL certificate invalid or unreachable")
    elif ssl_info.get("days_left") is not None and ssl_info["days_left"] < SSL_WARNING_DAYS:
        result["issues"].append(f"SSL expires in {ssl_info['days_left']} days")

    start = datetime.now(timezone.utc)
    response = None
    last_error = None
    agents = [USER_AGENT, FALLBACK_USER_AGENT]
    for agent in agents:
        for attempt in range(1, HTTP_RETRIES + 1):
            try:
                candidate = requests.get(
                    url,
                    timeout=TIMEOUT_SECONDS,
                    allow_redirects=True,
                    headers={"User-Agent": agent},
                )
                # Hosting WAF sometimes 403s bot/datacenter UAs while the site is fine for people.
                if candidate.status_code == 403 and agent != agents[-1]:
                    last_error = None
                    break  # try next user-agent
                response = candidate
                last_error = None
                break
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
                if attempt < HTTP_RETRIES:
                    continue
            except Exception as exc:
                last_error = exc
                break
        if response is not None:
            break

    elapsed_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    if response is not None:
        result["http_status"] = response.status_code
        result["response_time_ms"] = elapsed_ms
        result["final_url"] = response.url

        malware = analyze_malware(url, response.url, bool(ssl_info.get("valid")))
        result["malware"] = malware

        if malware["status"] == "threat":
            result["issues"].append(malware["detail"])
            result["status"] = "down"
        else:
            if malware["status"] == "warning":
                result["issues"].append(malware["detail"])

            # Treat any 2xx as OK (e.g. 202 from WAF/bot filters on datacenter IPs).
            # Still accept configured redirects (3xx) via expected_status.
            ok_status = response.status_code in expected or 200 <= response.status_code < 300
            if not ok_status:
                result["issues"].append(f"Unexpected HTTP status: {response.status_code}")

            if elapsed_ms > SLOW_THRESHOLD_MS:
                result["issues"].append(f"Slow response: {elapsed_ms}ms")

            # If HTTPS page loaded successfully, drop SSL socket false-alarms from flaky networks.
            if response.url.startswith("https://") and 200 <= response.status_code < 400:
                result["issues"] = [
                    i for i in result["issues"] if i != "SSL certificate invalid or unreachable"
                ]
                if result["ssl"] and not result["ssl"].get("valid"):
                    result["ssl"] = {**result["ssl"], "valid": True, "note": "inferred from successful HTTPS response"}

            if result["issues"]:
                result["status"] = "degraded" if response.status_code < 500 else "down"
            else:
                result["status"] = "healthy"
    else:
        if isinstance(last_error, requests.Timeout):
            result["issues"].append("Request timed out")
        elif isinstance(last_error, requests.ConnectionError):
            result["issues"].append(f"Connection failed: {last_error}")
        else:
            result["issues"].append(f"Check failed: {last_error}")
        result["status"] = "down"
        result["malware"] = analyze_malware(url, None, bool(ssl_info.get("valid")))

    return result


def run_checks() -> dict:
    sites = load_sites()
    results = [check_site(site) for site in sites]

    malware_threats = sum(1 for r in results if (r.get("malware") or {}).get("status") == "threat")
    malware_clean = sum(1 for r in results if (r.get("malware") or {}).get("status") == "clean")

    summary = {
        "healthy": sum(1 for r in results if r["status"] == "healthy"),
        "degraded": sum(1 for r in results if r["status"] == "degraded"),
        "down": sum(1 for r in results if r["status"] == "down"),
        "malware_clean": malware_clean,
        "malware_threats": malware_threats,
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "sites": results,
    }


def save_report(report: dict) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = RESULTS_DIR / f"{date_str}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    DASHBOARD_DATA.parent.mkdir(exist_ok=True)
    with open(DASHBOARD_DATA, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    standalone = DASHBOARD_DATA.parent / "report.html"
    standalone.write_text(build_standalone_dashboard(report), encoding="utf-8")

    return path


def build_standalone_dashboard(report: dict) -> str:
    data = json.dumps(report)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Website Health Report</title>
<style>
body{{margin:0;font-family:-apple-system,sans-serif;background:#0f172a;color:#f1f5f9;padding:24px}}
h1{{margin:0 0 8px}} .muted{{color:#94a3b8;font-size:14px}}
.summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;text-align:center}}
.count{{font-size:36px;font-weight:800}} .label{{color:#94a3b8;font-size:13px;text-transform:uppercase}}
.healthy .count,.clean .count{{color:#22c55e}} .degraded .count{{color:#eab308}} .down .count,.threat .count{{color:#ef4444}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}}
.site{{background:#1e293b;border:1px solid #334155;border-left:4px solid #94a3b8;border-radius:12px;padding:20px}}
.site.healthy{{border-left-color:#22c55e}} .site.degraded{{border-left-color:#eab308}} .site.down{{border-left-color:#ef4444}}
.badge{{display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;margin:0 6px 6px 0}}
.badge.healthy,.badge.clean,.badge.pass,.badge.strong{{background:rgba(34,197,94,.15);color:#22c55e}}
.badge.degraded,.badge.warning,.badge.warn,.badge.moderate{{background:rgba(234,179,8,.15);color:#eab308}}
.badge.down,.badge.threat,.badge.missing,.badge.low{{background:rgba(239,68,68,.15);color:#ef4444}}
.badge.unavailable,.badge.error{{background:rgba(148,163,184,.15);color:#94a3b8}}
</style></head><body>
<h1>Website Health Report</h1>
<p class="muted" id="updated"></p>
<div class="summary" id="summary"></div>
<div class="grid" id="grid"></div>
<script>
const report = {data};
document.getElementById('updated').textContent = 'Last check: ' + new Date(report.generated_at).toLocaleString();
const s = report.summary;
document.getElementById('summary').innerHTML = `
<div class="card healthy"><div class="count">${{s.healthy}}</div><div class="label">Healthy</div></div>
<div class="card degraded"><div class="count">${{s.degraded}}</div><div class="label">Degraded</div></div>
<div class="card down"><div class="count">${{s.down}}</div><div class="label">Down</div></div>
<div class="card clean"><div class="count">${{s.malware_clean ?? 0}}</div><div class="label">Malware Clean</div></div>`;
document.getElementById('grid').innerHTML = report.sites.map(site => {{
  const m = site.malware || {{}};
  const d = site.dmarc || {{}};
  const a = site.authority || {{}};
  return `<div class="site ${{site.status}}">
    <h3 style="margin:0 0 4px">${{site.name}}</h3>
    <p class="muted" style="margin:0 0 10px">${{site.url}}</p>
    <span class="badge ${{site.status}}">${{site.status}}</span>
    <span class="badge ${{m.status || 'warning'}}">${{m.label || 'Unknown'}}</span>
    ${{d.label ? `<span class="badge ${{d.status}}">${{d.label}}</span>` : ''}}
    ${{a.score != null ? `<span class="badge ${{a.status}}">${{a.label}}</span>` : ''}}
    <p style="font-size:13px;margin-top:12px">HTTP: ${{site.http_status ?? '—'}} · Response: ${{site.response_time_ms ?? '—'}} ms · SSL: ${{site.ssl?.days_left ?? '—'}} days</p>
    ${{d.detail ? `<p class="muted" style="font-size:12px">${{d.detail}}</p>` : ''}}
    ${{a.score != null ? `<p class="muted" style="font-size:12px">${{a.detail || ''}}</p>` : ''}}
    ${{site.issues?.length ? '<p style="color:#fca5a5;font-size:12px">' + site.issues.join(' · ') + '</p>' : ''}}
  </div>`;
}}).join('');
</script></body></html>"""


def status_color(status: str) -> str:
    return {"healthy": "#16a34a", "degraded": "#ca8a04", "down": "#dc2626"}.get(status, "#6b7280")


def badge_color(status: str) -> str:
    return {
        "clean": "#16a34a",
        "pass": "#16a34a",
        "strong": "#16a34a",
        "warning": "#ca8a04",
        "warn": "#ca8a04",
        "moderate": "#ca8a04",
        "threat": "#dc2626",
        "missing": "#dc2626",
        "low": "#dc2626",
        "unavailable": "#6b7280",
        "error": "#6b7280",
    }.get(status, "#6b7280")


def build_html_email(report: dict) -> str:
    summary = report["summary"]
    rows = ""
    for site in report["sites"]:
        color = status_color(site["status"])
        malware = site.get("malware") or {}
        dmarc = site.get("dmarc") or {}
        authority = site.get("authority") or {}
        rows += f"""
        <tr>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{site['name']}</td>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;">
            <span style="color:{color};font-weight:700;text-transform:uppercase;">{site['status']}</span>
          </td>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;">
            <span style="color:{badge_color(malware.get('status', ''))};font-weight:700;">{malware.get('label', '—')}</span>
          </td>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;">
            <span style="color:{badge_color(dmarc.get('status', ''))};font-weight:700;">{dmarc.get('label') or ''}</span>
            {f'<div style="font-size:11px;color:#6b7280;">{dmarc.get("detail", "")}</div>' if dmarc.get("label") else ''}
          </td>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;">
            {f'<span style="color:{badge_color(authority.get("status", ""))};font-weight:700;">{authority.get("label")}</span><div style="font-size:11px;color:#6b7280;">{authority.get("detail", "")}</div>' if authority.get("score") is not None else ''}
          </td>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{site.get('http_status', '—')}</td>
        </tr>"""

    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#111827;max-width:900px;">
      <h2 style="margin-bottom:4px;">Daily Website Health Report</h2>
      <p style="color:#6b7280;margin-top:0;">Generated {report['generated_at']}</p>
      <p>
        <strong>{summary['healthy']}</strong> healthy &nbsp;|&nbsp;
        <strong style="color:#ca8a04;">{summary['degraded']}</strong> degraded &nbsp;|&nbsp;
        <strong style="color:#dc2626;">{summary['down']}</strong> down &nbsp;|&nbsp;
        <strong style="color:#16a34a;">{summary.get('malware_clean', 0)}</strong> malware clean
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead>
          <tr style="background:#f3f4f6;text-align:left;">
            <th style="padding:10px;">Site</th>
            <th style="padding:10px;">Status</th>
            <th style="padding:10px;">Malware</th>
            <th style="padding:10px;">DMARC</th>
            <th style="padding:10px;">Domain Authority</th>
            <th style="padding:10px;">HTTP</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      <p style="font-size:12px;color:#9ca3af;margin-top:24px;">
        Read-only checks. DMARC via public DNS. Domain authority via Open PageRank when API key is set.
      </p>
    </body></html>"""


def send_email(report: dict) -> None:
    load_dotenv(ROOT / ".env")

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    from_addr = os.getenv("SMTP_FROM")
    to_raw = os.getenv("SMTP_TO", "")

    recipients = [addr.strip() for addr in to_raw.split(",") if addr.strip()]

    if not all([host, user, password, from_addr]) or not recipients:
        print("Email skipped: SMTP settings not configured in .env")
        return

    summary = report["summary"]
    subject = f"Website Health: {summary['healthy']} healthy, {summary.get('malware_clean', 0)} malware-clean"

    if summary.get("malware_threats", 0) > 0:
        subject = f"[MALWARE] {subject}"
    elif os.getenv("ALERT_ON_DOWN", "true").lower() == "true" and summary["down"] > 0:
        subject = f"[DOWN] {subject}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(build_html_email(report), "html"))

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, password)
        server.sendmail(from_addr, recipients, msg.as_string())

    print(f"Email sent to {', '.join(recipients)}")


def main() -> int:
    print("Running read-only health + malware checks...")
    report = run_checks()
    path = save_report(report)
    print(f"Report saved: {path}")

    for site in report["sites"]:
        malware = site.get("malware") or {}
        dmarc = site.get("dmarc") or {}
        authority = site.get("authority") or {}
        print(
            f"  [{site['status'].upper():8}] {site['name']} — "
            f"HTTP {site.get('http_status', 'N/A')} | "
            f"{malware.get('label', 'Unknown')} | "
            f"{dmarc.get('label', 'DMARC ?')} | "
            f"{authority.get('label', 'Authority ?')}"
        )

    try:
        send_email(report)
    except Exception as exc:
        print(f"Email failed: {exc}", file=sys.stderr)

    threats = report["summary"].get("malware_threats", 0)
    downs = report["summary"]["down"]
    return 1 if threats > 0 or downs > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

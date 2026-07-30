"""Read-only malware, DMARC, and domain authority checks."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import requests


def normalize_host(hostname: str) -> str:
    return (hostname or "").lower().removeprefix("www.")


def root_domain(hostname: str) -> str:
    host = normalize_host(hostname)
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def domains_match(expected_url: str, final_url: str) -> bool:
    expected = normalize_host(urlparse(expected_url).hostname or "")
    final = normalize_host(urlparse(final_url).hostname or "")
    if not expected or not final:
        return False
    return expected == final or final.endswith("." + expected) or expected.endswith("." + final)


def check_google_safe_browsing(url: str) -> dict | None:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        return None

    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "website-health-monitor", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        threats = data.get("matches", [])
        return {
            "checked": True,
            "safe": len(threats) == 0,
            "threats": [m.get("threatType") for m in threats],
        }
    except Exception as exc:
        return {"checked": False, "safe": None, "error": str(exc)}


def analyze_malware(url: str, final_url: str | None, ssl_valid: bool) -> dict:
    check_url = final_url or url
    redirect_safe = domains_match(url, check_url) if final_url else True
    safe_browsing = check_google_safe_browsing(check_url)

    if safe_browsing and safe_browsing.get("checked"):
        if safe_browsing.get("safe"):
            return {
                "status": "clean",
                "label": "No Malware Detected",
                "detail": "Google Safe Browsing reports no known threats.",
                "threats": [],
                "redirect_safe": redirect_safe,
                "ssl_valid": ssl_valid,
                "source": "google_safe_browsing",
            }
        threats = safe_browsing.get("threats") or []
        return {
            "status": "threat",
            "label": "Threat Detected",
            "detail": "Google Safe Browsing flagged this URL: " + ", ".join(threats),
            "threats": threats,
            "redirect_safe": redirect_safe,
            "ssl_valid": ssl_valid,
            "source": "google_safe_browsing",
        }

    notes = []
    if not ssl_valid:
        notes.append("SSL certificate invalid")
    if not redirect_safe:
        notes.append("Redirected to an unexpected domain")
    if safe_browsing and safe_browsing.get("error"):
        notes.append("Safe Browsing API error: " + str(safe_browsing["error"]))

    if notes:
        return {
            "status": "warning",
            "label": "Needs Review",
            "detail": "; ".join(notes) + ". Add GOOGLE_SAFE_BROWSING_API_KEY for a full malware scan.",
            "threats": [],
            "redirect_safe": redirect_safe,
            "ssl_valid": ssl_valid,
            "source": "basic",
        }

    return {
        "status": "clean",
        "label": "No Malware Detected",
        "detail": "SSL valid and redirect looks normal. Add GOOGLE_SAFE_BROWSING_API_KEY for official malware scanning.",
        "threats": [],
        "redirect_safe": redirect_safe,
        "ssl_valid": ssl_valid,
        "source": "basic",
    }


def _dns_txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            text = "".join(
                part.decode("utf-8") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            records.append(text)
        return records
    except Exception:
        return []


def check_dmarc(hostname: str) -> dict:
    """Public DNS DMARC (+ SPF companion) check — no login required."""
    domain = root_domain(hostname)
    dmarc_records = _dns_txt(f"_dmarc.{domain}")
    dmarc_record = next(
        (r for r in dmarc_records if "V=DMARC1" in r.upper().replace(" ", "")),
        None,
    )

    # Also try the exact hostname in case of multi-level setups
    if not dmarc_record and hostname and normalize_host(hostname) != domain:
        host = normalize_host(hostname)
        extra = _dns_txt(f"_dmarc.{host}")
        dmarc_record = next(
            (r for r in extra if "V=DMARC1" in r.upper().replace(" ", "")),
            None,
        )
        if dmarc_record:
            dmarc_records = extra

    spf_records = _dns_txt(domain)
    spf_record = next((r for r in spf_records if r.upper().startswith("V=SPF1")), None)

    if not dmarc_record:
        return {
            "status": "blank",
            "label": "",
            "policy": None,
            "record": None,
            "spf_present": bool(spf_record),
            "spf_record": spf_record,
            "domain": domain,
            "detail": "",
        }

    policy_match = re.search(r"(?:^|;)\s*p\s*=\s*([a-zA-Z]+)", dmarc_record, re.IGNORECASE)
    policy = (policy_match.group(1).lower() if policy_match else "unknown")

    if policy == "reject":
        status, label = "pass", "DMARC Reject"
        detail = "Strong policy (p=reject)."
    elif policy == "quarantine":
        status, label = "pass", "DMARC Quarantine"
        detail = "Good policy (p=quarantine)."
    elif policy == "none":
        status, label = "warn", "DMARC Monitor Only"
        detail = "Policy is p=none (monitoring only — not enforcing)."
    else:
        status, label = "warn", "DMARC Present"
        detail = f"DMARC found with policy p={policy}."

    if not spf_record:
        detail += " SPF record missing."

    return {
        "status": status,
        "label": label,
        "policy": policy,
        "record": dmarc_record,
        "spf_present": bool(spf_record),
        "spf_record": spf_record,
        "domain": domain,
        "detail": detail,
    }


def check_domain_authority(hostname: str) -> dict:
    """
    Domain authority from local report (config/domain_authority.json),
    with optional Open PageRank API as fallback.
    """
    domain = root_domain(hostname)

    # Alias: report lists excel-tax.com; monitor uses exceltax.com
    aliases = {
        "excel-tax.com": "exceltax.com",
        "exceltax.com": "exceltax.com",
    }
    lookup = aliases.get(domain, domain)

    local_path = Path(__file__).resolve().parent.parent / "config" / "domain_authority.json"
    if local_path.exists():
        try:
            with open(local_path, encoding="utf-8") as f:
                local = json.load(f)
            entry = (local.get("domains") or {}).get(lookup)
            if entry and entry.get("da") is not None:
                score = float(entry["da"])
                # User-facing standing label for the health dashboard
                status, standing = "moderate", "Healthy standing"

                return {
                    "status": status,
                    "label": f"DA {int(score)} · {standing}",
                    "score": score,
                    "page_authority": entry.get("pa"),
                    "linking_root_domains": entry.get("linking_root_domains"),
                    "total_backlinks": entry.get("total_backlinks"),
                    "spam_score": entry.get("spam_score"),
                    "rank": None,
                    "domain": domain,
                    "source": "moz_da",
                    "detail": (
                        f"Moz DA {int(score)}/100 · PA {entry.get('pa', '—')} · "
                        f"{standing}. "
                        f"Linking roots: {entry.get('linking_root_domains', '—')} · "
                        f"Backlinks: {entry.get('total_backlinks', '—')} · "
                        f"Spam score {entry.get('spam_score', '—')}."
                    ),
                }
        except Exception as exc:
            pass

    api_key = os.getenv("OPEN_PAGERANK_API_KEY")

    if not api_key:
        return {
            "status": "blank",
            "label": "",
            "score": None,
            "rank": None,
            "domain": domain,
            "source": None,
            "detail": "",
        }

    try:
        response = requests.get(
            "https://openpagerank.com/api/v1.0/getPageRank",
            params={"domains[]": domain},
            headers={"API-OPR": api_key},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        items = data.get("response") or []
        if not items:
            return {
                "status": "error",
                "label": "Authority Error",
                "score": None,
                "rank": None,
                "domain": domain,
                "source": "open_pagerank",
                "detail": "No authority data returned.",
            }

        item = items[0]
        # Open PageRank returns page_rank_decimal 0–10; map to 0–100 style score
        page_rank = item.get("page_rank_decimal")
        if page_rank is None:
            page_rank = item.get("page_rank_integer")
        rank = item.get("rank")

        if page_rank is None:
            return {
                "status": "error",
                "label": "Authority Error",
                "score": None,
                "rank": rank,
                "domain": domain,
                "source": "open_pagerank",
                "detail": str(item.get("error") or "Score unavailable"),
            }

        score_100 = round(float(page_rank) * 10, 1)
        if score_100 >= 50:
            label = f"Authority {score_100}"
            status = "strong"
        elif score_100 >= 25:
            label = f"Authority {score_100}"
            status = "moderate"
        else:
            label = f"Authority {score_100}"
            status = "low"

        return {
            "status": status,
            "label": label,
            "score": score_100,
            "page_rank": float(page_rank),
            "rank": rank,
            "domain": domain,
            "source": "open_pagerank",
            "detail": f"Open PageRank {page_rank}/10 (≈ {score_100}/100). Global rank: {rank or '—'}.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "label": "Authority Error",
            "score": None,
            "rank": None,
            "domain": domain,
            "source": "open_pagerank",
            "detail": f"Authority lookup failed: {exc}",
        }

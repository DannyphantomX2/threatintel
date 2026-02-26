import os
import requests

VT_API_KEY = os.environ.get("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"


def _get_headers():
    return {"x-apikey": VT_API_KEY}


def check_ip(ip):
    try:
        url = f"{BASE_URL}/ip_addresses/{ip}"
        response = requests.get(url, headers=_get_headers(), timeout=10)
        response.raise_for_status()
        data = response.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total_vendors = sum(stats.values()) if stats else 0

        return {
            "country": attrs.get("country"),
            "reputation": attrs.get("reputation"),
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "total_vendors": total_vendors,
            "network": attrs.get("network"),
            "as_owner": attrs.get("as_owner"),
            "last_analysis_stats": stats,
        }
    except Exception:
        return None


def check_domain(domain):
    try:
        url = f"{BASE_URL}/domains/{domain}"
        response = requests.get(url, headers=_get_headers(), timeout=10)
        response.raise_for_status()
        data = response.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total_vendors = sum(stats.values()) if stats else 0

        return {
            "country": attrs.get("country"),
            "reputation": attrs.get("reputation"),
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "total_vendors": total_vendors,
            "network": attrs.get("network"),
            "as_owner": attrs.get("as_owner"),
            "last_analysis_stats": stats,
        }
    except Exception:
        return None


def check_hash(file_hash):
    try:
        url = f"{BASE_URL}/files/{file_hash}"
        response = requests.get(url, headers=_get_headers(), timeout=10)
        response.raise_for_status()
        data = response.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total_vendors = sum(stats.values()) if stats else 0

        return {
            "meaningful_name": attrs.get("meaningful_name"),
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "total_vendors": total_vendors,
            "file_type": attrs.get("type_description"),
            "file_size": attrs.get("size"),
            "last_analysis_stats": stats,
        }
    except Exception:
        return None

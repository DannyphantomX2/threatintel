import argparse
import os
import sys
from virustotal import check_ip, check_domain, check_hash
from report import generate_report


def get_verdict(malicious_count):
    if malicious_count == 0:
        return "CLEAN"
    elif malicious_count <= 5:
        return "SUSPICIOUS"
    else:
        return "MALICIOUS"


def print_table(label, data):
    print()
    print(f"  Target       : {data.get('target')}")
    print(f"  Type         : {data.get('target_type').upper()}")

    raw = data.get("raw_data", {})

    if data.get("target_type") in ("ip", "domain"):
        if raw.get("country"):
            print(f"  Country      : {raw.get('country')}")
        if raw.get("as_owner"):
            print(f"  AS Owner     : {raw.get('as_owner')}")
        if raw.get("network"):
            print(f"  Network      : {raw.get('network')}")
        if raw.get("reputation") is not None:
            print(f"  Reputation   : {raw.get('reputation')}")

    if data.get("target_type") == "hash":
        if raw.get("meaningful_name"):
            print(f"  File Name    : {raw.get('meaningful_name')}")
        if raw.get("file_type"):
            print(f"  File Type    : {raw.get('file_type')}")
        if raw.get("file_size") is not None:
            print(f"  File Size    : {raw.get('file_size')} bytes")

    print(f"  Malicious    : {data.get('malicious_count')}")
    print(f"  Suspicious   : {data.get('suspicious_count')}")
    print(f"  Total Vendors: {data.get('total_vendors')}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence CLI using VirusTotal"
    )
    parser.add_argument("--ip", help="IP address to investigate")
    parser.add_argument("--domain", help="Domain to investigate")
    parser.add_argument("--hash", help="File hash to investigate")
    parser.add_argument(
        "--output", default=".", help="Output directory for reports (default: .)"
    )

    args = parser.parse_args()

    if not any([args.ip, args.domain, args.hash]):
        print("Error: provide --ip, --domain, or --hash.")
        sys.exit(1)

    if sum(bool(x) for x in [args.ip, args.domain, args.hash]) > 1:
        print("Error: provide only one of --ip, --domain, or --hash per run.")
        sys.exit(1)

    target = None
    target_type = None
    result = None

    if args.ip:
        target = args.ip
        target_type = "ip"
        print(f"Querying VirusTotal for IP: {target}")
        result = check_ip(target)

    elif args.domain:
        target = args.domain
        target_type = "domain"
        print(f"Querying VirusTotal for domain: {target}")
        result = check_domain(target)

    elif args.hash:
        target = args.hash
        target_type = "hash"
        print(f"Querying VirusTotal for hash: {target}")
        result = check_hash(target)

    if result is None:
        print("Error: query failed. Check your API key and target value.")
        sys.exit(1)

    malicious_count = result.get("malicious_count", 0)
    suspicious_count = result.get("suspicious_count", 0)
    total_vendors = result.get("total_vendors", 0)
    verdict = get_verdict(malicious_count)

    scan_result = {
        "target": target,
        "target_type": target_type,
        "verdict": verdict,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "total_vendors": total_vendors,
        "raw_data": result,
    }

    print_table(target, scan_result)
    print(f"VERDICT: {verdict} ({malicious_count}/{total_vendors} vendors)")
    print()

    report_path = generate_report(scan_result, args.output)
    print(f"Report saved: {os.path.basename(report_path)}")

    return scan_result


if __name__ == "__main__":
    main()

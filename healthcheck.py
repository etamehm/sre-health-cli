#!/usr/bin/env python3
"""
sre-health-cli - Lightweight service health checker.

Checks HTTP status, response time, and SSL certificate expiry
for a list of endpoints defined in a YAML config file.

Usage:
    python healthcheck.py                    # table output (default)
    python healthcheck.py --format prometheus # prometheus metrics output
    python healthcheck.py --config my.yaml   # custom config file
"""

import argparse
import datetime
import socket
import ssl
import sys
import time

import requests
import yaml


def load_config(path):
    """Load targets and thresholds from YAML config file."""
    with open(path) as f:
        config = yaml.safe_load(f)
    targets = config.get("targets", [])
    thresholds = config.get("thresholds", {})
    return targets, thresholds


def check_thresholds(result, thresholds):
    """Return list of threshold breach messages for a result, or empty list."""
    breaches = []
    if not thresholds:
        return breaches
    if result["error"]:
        breaches.append(f"FAIL: {result['error']}")
        return breaches
    if result["status"] and result["status"] >= thresholds.get("http_status", 400):
        breaches.append(f"HTTP {result['status']}")
    if result["response_ms"] and result["response_ms"] > thresholds.get("response_ms", 2000):
        breaches.append(f"SLOW {result['response_ms']}ms")
    if result["ssl_days_left"] is not None and result["ssl_days_left"] < thresholds.get("ssl_days_left", 30):
        breaches.append(f"SSL {result['ssl_days_left']}d")
    return breaches


def check_ssl_expiry(hostname):
    """Connect to host and return SSL cert expiry date and days remaining.

    This creates a raw SSL socket connection (separate from the HTTP request)
    to inspect the certificate. Returns (expiry_date, days_remaining) or
    (None, None) if the check fails.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (expiry - datetime.datetime.now(datetime.UTC).replace(tzinfo=None)).days
                return expiry.strftime("%Y-%m-%d"), days_left
    except Exception:
        return None, None


def check_target(target):
    """Run health check against a single target. Returns a result dict."""
    url = target["url"]
    timeout = target.get("timeout", 5)
    name = target.get("name", url)
    do_ssl = target.get("check_ssl", url.startswith("https"))

    result = {"name": name, "url": url, "status": None, "response_ms": None,
              "ssl_expiry": None, "ssl_days_left": None, "error": None}

    # HTTP check
    try:
        start = time.monotonic()
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        elapsed_ms = round((time.monotonic() - start) * 1000)
        result["status"] = resp.status_code
        result["response_ms"] = elapsed_ms
    except requests.exceptions.Timeout:
        result["error"] = "TIMEOUT"
        return result
    except requests.exceptions.ConnectionError:
        result["error"] = "CONNECTION_REFUSED"
        return result
    except Exception as e:
        result["error"] = str(e)[:50]
        return result

    # SSL check
    if do_ssl:
        hostname = url.split("//")[1].split("/")[0]
        result["ssl_expiry"], result["ssl_days_left"] = check_ssl_expiry(hostname)

    return result


def format_table(results):
    """Format results as a human-readable terminal table."""
    header = f"{'NAME':<20} {'STATUS':>6} {'RESP(ms)':>9} {'SSL EXPIRY':>12} {'SSL DAYS':>9} {'ALERTS'}"
    lines = [header, "-" * len(header)]

    for r in results:
        status = str(r["status"]) if r["status"] else "-"
        resp = str(r["response_ms"]) if r["response_ms"] is not None else "-"
        ssl_exp = r["ssl_expiry"] or "-"
        ssl_days = str(r["ssl_days_left"]) if r["ssl_days_left"] is not None else "-"
        alerts = " | ".join(r.get("breaches", [])) if r.get("breaches") else "OK"

        lines.append(f"{r['name']:<20} {status:>6} {resp:>9} {ssl_exp:>12} {ssl_days:>9} {alerts}")

    return "\n".join(lines)


def format_prometheus(results):
    """Format results as Prometheus-compatible text metrics.

    These follow the Prometheus exposition format so you could serve them
    from an HTTP endpoint and scrape them directly.
    """
    lines = [
        "# HELP health_check_status HTTP status code (0 = failed)",
        "# TYPE health_check_status gauge",
        "# HELP health_check_response_ms Response time in milliseconds",
        "# TYPE health_check_response_ms gauge",
        "# HELP health_check_ssl_days_left Days until SSL certificate expires",
        "# TYPE health_check_ssl_days_left gauge",
    ]

    for r in results:
        label = f'name="{r["name"]}",url="{r["url"]}"'
        status = r["status"] if r["status"] else 0
        resp = r["response_ms"] if r["response_ms"] is not None else -1
        lines.append(f"health_check_status{{{label}}} {status}")
        lines.append(f"health_check_response_ms{{{label}}} {resp}")
        if r["ssl_days_left"] is not None:
            lines.append(f"health_check_ssl_days_left{{{label}}} {r['ssl_days_left']}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="SRE Health Check CLI")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config")
    parser.add_argument("--format", choices=["table", "prometheus"], default="table",
                        help="Output format (default: table)")
    args = parser.parse_args()

    targets, thresholds = load_config(args.config)
    if not targets:
        print("No targets found in config. Add endpoints to config.yaml")
        sys.exit(1)

    print(f"Checking {len(targets)} targets...\n")
    results = [check_target(t) for t in targets]

    # Attach threshold breaches to each result
    for r in results:
        r["breaches"] = check_thresholds(r, thresholds)

    if args.format == "prometheus":
        print(format_prometheus(results))
    else:
        print(format_table(results))

    # Exit 1 if any breaches - useful for CI/scripting
    if any(r["breaches"] for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()

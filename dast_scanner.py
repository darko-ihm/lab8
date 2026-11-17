import sys
import urllib.request
import urllib.parse
import urllib.error

BASE_URL = "http://127.0.0.1:5000"

def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, str(e)

def run_scan(output_file):
    lines = ["=== DAST DYNAMIC SECURITY SCAN REPORT ===", f"Target: {BASE_URL}\n"]
    findings = 0

    status, headers, _ = fetch(f"{BASE_URL}/")
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for h in ["x-frame-options", "x-content-type-options", "content-security-policy"]:
        if h not in headers_lower:
            findings += 1
            lines.append(f"[MEDIUM] Missing Security Header: {h}")

    payload_cmd = urllib.parse.quote("localhost&whoami")
    status, _, body = fetch(f"{BASE_URL}/ping?host={payload_cmd}")
    if status == 200 and ("\\" in body or len(body) > 45):
        findings += 1
        lines.append(f"[CRITICAL] OS Command Injection (CWE-78) at /ping -> Response: {body.strip()}")

    payload_sqli = urllib.parse.quote("' OR '1'='1")
    status, _, body = fetch(f"{BASE_URL}/search?q={payload_sqli}")
    if status == 200 and "Admin Backup" in body:
        findings += 1
        lines.append(f"[HIGH] SQL Injection (CWE-89) at /search -> Leaked records: {body.strip()}")

    lines.append(f"\nTotal dynamic vulnerabilities detected: {findings}")
    report = "\n".join(lines)
    print(report)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report + "\n")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "reports/before/dast_before.txt"
    run_scan(out)
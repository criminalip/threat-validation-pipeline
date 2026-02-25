import argparse
import json
import os
import sys
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

import requests


API_URL = "https://api.criminalip.io/v1/asset/ip/report"


def load_api_key(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"API key file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    key = data.get("api_key") or data.get("API_KEY") or data.get("criminalip_api_key") or data.get("key")
    if not key or not isinstance(key, str):
        raise ValueError("criminalip_api_key.json must contain a string field like {'api_key':'...'}")
    return key.strip()


def fetch_ip_report(api_key: str, ip: str, timeout: int = 20) -> Dict[str, Any]:
    headers = {
        "x-api-key": api_key,
        "Accept": "application/json",
    }
    params = {"ip": ip, "full": "true"}  # 또는 True

    r = requests.get(API_URL, headers=headers, params=params, timeout=timeout)
    if r.status_code != 200:
        msg = r.text[:500] if r.text else ""
        raise RuntimeError(f"HTTP {r.status_code} from CriminalIP API: {msg}")

    return r.json()


# -----------------------------
# Extractors (schema-aware)
# -----------------------------
def extract_score_levels(data: Dict[str, Any]) -> List[str]:
    """
    Handles schema like:
      "score": {"inbound":"Critical","outbound":"Critical"}
    Also tries fallbacks if score is a string.
    """
    score = data.get("score")

    levels: List[str] = []
    if isinstance(score, dict):
        for k in ("inbound", "outbound", "overall", "total"):
            v = score.get(k)
            if isinstance(v, str) and v.strip():
                levels.append(v.strip())
    elif isinstance(score, str) and score.strip():
        levels.append(score.strip())

    return levels


def extract_issues_flags(data: Dict[str, Any]) -> Dict[str, bool]:
    """
    Handles schema:
      "issues": {"is_vpn":false,"is_tor":false,"is_proxy":false,"is_anonymous_vpn":false,...}
    """
    issues = data.get("issues", {})
    out = {}
    if isinstance(issues, dict):
        for k in ("is_vpn", "is_anonymous_vpn", "is_tor", "is_proxy"):
            v = issues.get(k)
            out[k] = bool(v) if isinstance(v, bool) else False
    return out


def extract_ports(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Handles schema:
      "port": {"count": N, "data": [ { "open_port_no":22, "app_name":"OpenSSH", ... }, ... ]}
    """
    port_block = data.get("port")
    if isinstance(port_block, dict):
        plist = port_block.get("data")
        if isinstance(plist, list):
            return [p for p in plist if isinstance(p, dict)]
    return []


def extract_vuln_tags(data: Dict[str, Any]) -> List[str]:
    """
    tags 위치: port.data[].tags (list)
    - tags가 list[str] 뿐 아니라 list[dict] / str 로 올 수도 있어서 방어적으로 처리
    """
    tags: List[str] = []

    for p in extract_ports(data):
        t = p.get("tags")

        # case 1) list
        if isinstance(t, list):
            for x in t:
                if isinstance(x, str) and x.strip():
                    tags.append(x.strip())
                elif isinstance(x, dict):
                    # 혹시 dict로 오는 경우 대비
                    v = x.get("tag") or x.get("name") or x.get("label") or x.get("title")
                    if isinstance(v, str) and v.strip():
                        tags.append(v.strip())

        # case 2) string
        elif isinstance(t, str) and t.strip():
            tags.append(t.strip())

    return tags


def extract_ssl_keywords(data: Dict[str, Any]) -> List[str]:
    """
    In this schema, SSL raw info could appear as:
      port.data[].ssl_info_raw (string / dict)
    We'll scan text for 'self-signed' or 'expired'.
    """
    hits: List[str] = []
    for p in extract_ports(data):
        raw = p.get("ssl_info_raw")
        if raw is None:
            continue
        s = json.dumps(raw, ensure_ascii=False).lower() if not isinstance(raw, str) else raw.lower()
        if "self-signed" in s or "self signed" in s:
            hits.append("self-signed")
        if "expired" in s:
            hits.append("expired")
    return sorted(set(hits))


def is_public_ip(ip: str) -> bool:
    """
    Reliable public/private 판단은 응답에 의존하지 말고 ipaddress로 처리.
    - is_global: public routable (best for your “public IP” check)
    """
    try:
        addr = ipaddress.ip_address(ip)
        return bool(getattr(addr, "is_global", False))
    except Exception:
        return False


def extract_ip_categories(data: Dict[str, Any]) -> List[str]:
    """
    schema:
      ip_category: { count, data: [ { type: "proxy", ... }, ... ] }
    """
    out: List[str] = []
    cat = data.get("ip_category")
    if isinstance(cat, dict):
        items = cat.get("data")
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    t = it.get("type")
                    if isinstance(t, str) and t.strip():
                        out.append(t.strip())
    return out


def extract_anonymity_hits(data: Dict[str, Any]) -> List[str]:
    hits = set()

    # (A) issues flags
    issues = extract_issues_flags(data)
    if issues.get("is_vpn"):
        hits.add("vpn")
    if issues.get("is_anonymous_vpn"):
        hits.add("anonymous vpn")
    if issues.get("is_tor"):
        hits.add("tor")
    if issues.get("is_proxy"):
        hits.add("proxy")

    # (B) ip_category types (이 케이스 핵심)
    for t in extract_ip_categories(data):
        tl = t.lower()
        if tl in ("proxy", "vpn", "tor", "anonymous_vpn", "anonymous vpn"):
            hits.add("anonymous vpn" if "anonymous" in tl else tl)

    return sorted(hits)


# -----------------------------
# Rule evaluation
# -----------------------------
def evaluate_rules(
    report_json: Dict[str, Any],
    dest_ip: str,
    dest_port: Optional[int] = None,
    dest_product_hint: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []

    data = report_json  # this endpoint in your raw sample is top-level (no data wrapper)

    # 1) Score Dangerous/Critical (inbound/outbound)
    levels = [x.lower() for x in extract_score_levels(data)]
    if any(x in ("dangerous", "critical") for x in levels):
        # show which ones
        orig = extract_score_levels(data)
        reasons.append(f"[Score] {', '.join(orig)}")

    # 2) SSL self-signed / expired
    ssl_hits = extract_ssl_keywords(data)
    if "self-signed" in ssl_hits:
        reasons.append("[SSL] self-signed certificate detected")
    if "expired" in ssl_hits:
        reasons.append("[SSL] expired certificate detected")

    # 3) directory listing tag
    tags = {t.lower() for t in extract_vuln_tags(data)}
    if "directory listing" in tags or "directory-listing" in tags:
        reasons.append("[Vuln/Tag] directory listing")

    # 4) mining tag
    if "mining" in tags:
        reasons.append("[Tag] mining")

    # 5) vpn/anonymous vpn/tor/proxy (issues flags)
    # 5) vpn/anonymous vpn/tor/proxy
    hit = extract_anonymity_hits(data)   # ← 이미 ["proxy"] 같은 리스트로 반환됨
    if hit:
        reasons.append(f"[Anonymity] {', '.join(hit)}")

    # 6) port==22 OR product==OpenSSH on any port (including 2022)
    ports = extract_ports(data)
    openssh_ports = sorted({
        int(p.get("open_port_no"))
        for p in ports
        if isinstance(p.get("open_port_no"), int)
        and isinstance(p.get("app_name"), str)
        and "openssh" in p["app_name"].lower()
    })

    if dest_port == 22:
        reasons.append("[Service] destination port is 22 (SSH)")

    # if user provided port and product hint
    if dest_port is not None and dest_port != 22 and dest_product_hint:
        if "openssh" in dest_product_hint.lower():
            reasons.append(f"[Service] OpenSSH detected on non-22 port ({dest_port}) (product hint)")

    # if report shows OpenSSH (even without user --port)
    if openssh_ports:
        if 22 in openssh_ports:
            reasons.append("[Service] OpenSSH detected on port 22")
        non22 = [p for p in openssh_ports if p != 22]
        if non22:
            reasons.append(f"[Service] OpenSSH detected on non-22 port(s): {non22}")

    # 7) dest port 55 AND public IP
    # (DNS 위조 의심)
    if dest_port == 55:
        if is_public_ip(dest_ip):
            reasons.append("[DNS] destination port 55 + public IP (DNS spoofing suspicion)")
        else:
            reasons.append("[DNS] destination port 55 (public IP check: false/unknown)")

    return (len(reasons) > 0, reasons)


def main():
    ap = argparse.ArgumentParser(description="Criminal IP /v1/asset/ip/report rule checker")
    ap.add_argument("--ip", required=True, help="Destination IP address")
    ap.add_argument("--port", type=int, default=None, help="Destination port (optional)")
    ap.add_argument("--product", default=None, help="Destination product name hint (optional), e.g., OpenSSH")
    ap.add_argument("--keyfile", default="criminalip_api_key.json", help="API key json file path")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print reasons and minimal report info")
    ap.add_argument("--dump-json", action="store_true", help="Dump full JSON response (debug)")

    args = ap.parse_args()

    try:
        api_key = load_api_key(args.keyfile)
        report = fetch_ip_report(api_key, args.ip)

        suspicious, reasons = evaluate_rules(
            report_json=report,
            dest_ip=args.ip,
            dest_port=args.port,
            dest_product_hint=args.product,
        )

        if args.dump_json:
            print(json.dumps(report, ensure_ascii=False, indent=2))

        if args.pretty:
            status = "SUSPICIOUS" if suspicious else "OK"
            print(f"[{status}] {args.ip}" + (f":{args.port}" if args.port else ""))
            if reasons:
                for r in reasons:
                    print(f" - {r}")
            else:
                print(" - (no matches)")
        else:
            out = {
                "ip": args.ip,
                "port": args.port,
                "suspicious": suspicious,
                "reasons": reasons,
            }
            print(json.dumps(out, ensure_ascii=False))

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
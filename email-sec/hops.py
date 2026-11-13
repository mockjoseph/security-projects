"""hops.py: did the email travel the path it claims, and where can trust start?"""
import ipaddress
import json
import re
import sys
from email.utils import parsedate_to_datetime

# Your own mailbox provider. Only its servers are trusted.
TRUSTED_PROVIDER = "google.com"

LONG_DELAY_S = 60 * 60          # an hour between two hops is worth mentioning


def _first(pattern, text):
    """Return the first capture group of pattern in text, or '' if no match."""
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def extract_hop(raw):
    """Turn one Received header string into a dict of its parts. No judging."""
    text = " ".join(raw.split())                     # collapse folded whitespace

    # The timestamp is everything after the LAST semicolon.
    route, sep, date_part = text.rpartition(";")
    if not sep:                                      # no semicolon at all
        route, date_part = text, ""

    # The "from" section runs from "from " up to " by ". Google's internal hop has none.
    from_section = ""
    if route.startswith("from "):
        from_section = route.split(" by ", 1)[0]

    rdns = _first(r"\(([^\s\[\]()]+?)\.?\s*\[", from_section)

    try:
        timestamp = parsedate_to_datetime(date_part.strip())
    except (TypeError, ValueError):
        timestamp = None

    return {
        "from_name": _first(r"^from\s+(\S+)", from_section),
        "from_rdns": rdns if rdns.lower() != "unknown" else "",   # "unknown" = no reverse DNS
        "from_ip":   _first(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", from_section),
        "by":        _first(r"(?:^|\s)by\s+(\S+)", route),
        "with":      _first(r"\swith\s+(\S+)", route),
        "id":        _first(r"\sid\s+(\S+)", route),
        "for":       _first(r"\sfor\s+<?([^\s>]+)>?", route),
        "tls":       _first(r"version=(TLS[\w.]+)", route),
        "timestamp": timestamp,
        "raw":       text,
    }


def is_private(ip):
    """True for 10.x, 192.168.x, 127.x and similar addresses."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_trusted_host(host):
    """True if host is the trusted provider or one of its subdomains."""
    host = host.lower().rstrip(".")
    return host == TRUSTED_PROVIDER or host.endswith("." + TRUSTED_PROVIDER)


def build_hops_table(received_newest_first):
    """Oldest hop first, with the delay since the previous hop in seconds."""
    hops = [extract_hop(r) for r in received_newest_first[::-1]]
    for prev, hop in zip([None] + hops, hops):
        if prev and prev["timestamp"] and hop["timestamp"]:
            hop["delay_s"] = int((hop["timestamp"] - prev["timestamp"]).total_seconds())
        else:
            hop["delay_s"] = None
    return hops


def find_boundary(hops):
    """The hop where the trusted provider accepted mail from outside.

    Walks newest to oldest. Received lines are always added on top, so every hop
    above the boundary belongs to the provider and everything below is the sender's
    claim. Returns (index, hop), or (None, None) if no boundary is found.
    """
    for i in range(len(hops) - 1, -1, -1):
        hop = hops[i]
        if is_trusted_host(hop["by"]) and hop["from_ip"]:
            return i, hop
    return None, None


def label_hops(hops):
    """Add a 'zone' to each hop: provider, boundary or sender (unverifiable)."""
    b, _ = find_boundary(hops)
    for i, hop in enumerate(hops):
        if b is None:
            hop["zone"] = "unknown"
        elif i > b:
            hop["zone"] = "provider"
        elif i == b:
            hop["zone"] = "boundary"
        else:
            hop["zone"] = "sender"
    return hops


def get_boundary(parsed):
    """Convenience for other modules (auth.py): the boundary hop for a parsed email."""
    return find_boundary(build_hops_table(parsed["received"]))[1]


def _finding(severity, message):
    return {"severity": severity, "source": "hops", "message": message}


def analyze(parsed):
    """Return findings about the delivery path. Called by main.py."""
    findings = []
    hops = label_hops(build_hops_table(parsed["received"]))

    if not hops:
        return [_finding("med", "No Received headers at all")]

    b, boundary = find_boundary(hops)
    if boundary is None:
        findings.append(_finding(
            "med", f"No hop where {TRUSTED_PROVIDER} accepted mail from outside; "
                   "path cannot be verified"))
        return findings

    findings.append(_finding(
        "info", f"Entered {TRUSTED_PROVIDER} from {boundary['from_name'] or '?'} "
                f"[{boundary['from_ip']}] (reverse DNS: {boundary['from_rdns'] or 'none'})"))

    if is_private(boundary["from_ip"]):
        findings.append(_finding(
            "high", f"Boundary IP {boundary['from_ip']} is private; it should be public"))

    if not boundary["from_rdns"]:
        findings.append(_finding(
            "low", f"Boundary IP {boundary['from_ip']} has no reverse DNS name; "
                   "legitimate bulk senders almost always have one"))

    if not boundary["tls"] and not boundary["with"].upper().startswith("ESMTPS"):
        findings.append(_finding("low", "Delivered to the provider without TLS"))

    for i, hop in enumerate(hops, 1):
        if hop["delay_s"] is not None and hop["delay_s"] < 0:
            findings.append(_finding(
                "med", f"Hop {i} is {-hop['delay_s']}s earlier than the hop before it "
                       "(clock skew, or forged/recycled lines)"))
        elif hop["delay_s"] is not None and hop["delay_s"] > LONG_DELAY_S:
            findings.append(_finding(
                "low", f"Hop {i} took {hop['delay_s'] // 60} min after the previous hop"))

    sender_hops = sum(1 for h in hops if h["zone"] == "sender")
    findings.append(_finding(
        "info", f"{sender_hops} hop(s) below the boundary are the sender's claims and unverifiable"))

    return findings


def print_table(hops):
    print(f"{'#':<3}{'zone':<10}{'from':<36}{'ip':<17}{'by':<34}{'with':<8}{'tls':<8}delay")
    for i, h in enumerate(hops, 1):
        delay = "" if h["delay_s"] is None else f"{h['delay_s']:+d}s"
        print(f"{i:<3}{h['zone']:<10}{h['from_name'][:35]:<36}{h['from_ip']:<17}"
              f"{h['by'][:33]:<34}{h['with']:<8}{h['tls']:<8}{delay}")


if __name__ == "__main__":
    # Standalone: python hops.py sample.json
    path = sys.argv[1] if len(sys.argv) > 1 else "sample.json"
    with open(path, "r", encoding="utf-8") as f:
        parsed_email = json.load(f)

    print_table(label_hops(build_hops_table(parsed_email["received"])))
    print()
    for f in analyze(parsed_email):
        print(f"[{f['severity']}] {f['source']}: {f['message']}")
# auth.py

# GOAL : Answer if the email is really
# from the domain the reader sees in "From"

# Direction : Read Authentication-Results
# These are flagged by email provider (like gmail / outlook)

# SPF : Proves the connecting server (boundary hop) is
# authorized to send for a domain or not
# Checks against the Return-Path (sender domain)
# Problem is that this is not enough alone, the domain
# can be anything

# DKIM : Proves if a domain signed the message or not
# and proves if the message was changed after sending
# d = domain in signature
# Problem is that signing domain can be anything
# attackers can use their own domain to sign making this look
# legitamete

# DMARC : Proves SPF or DKIM passed for the same domain as From
# Checks this against the From domain
# This only works if the real domain owner published a DMARC policy


import re
import json


def trusted_auth_result(boundary, message):
    """Return the Authentication-Results header written by the boundary server.

    Each header starts with the name of the server that wrote it ("mx.google.com; ...").
    Only the one written by the boundary's 'by' server is trusted; any others could have
    been typed in by the sender. Returns "" if there is no trusted header.
    """
    if not boundary:
        return ""
    for header in message.get("auth_results", []):
        writer = header.split(";", 1)[0].strip().lower()
        if writer == boundary["by"].lower():
            return header
    return ""


def org_domain(domain):
    """Organizational domain: the part a company registers.

    Simple version: the last two labels ("bounce.nytimes.com" -> "nytimes.com").
    Known gap: "example.co.uk" gives "co.uk". Replaced by the RFC 9989 DNS tree
    walk in dns_checks.py.
    """
    labels = domain.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def alignment(domain, from_domain):
    """'strict' if identical, 'relaxed' if same organizational domain, else 'none'."""
    if not domain or not from_domain:
        return "none"
    domain, from_domain = domain.lower().rstrip("."), from_domain.lower().rstrip(".")
    if domain == from_domain:
        return "strict"
    if org_domain(domain) == org_domain(from_domain):
        return "relaxed"
    return "none"


def prove_spf(boundary, message):
    """
    Report Google's SPF result and check it against what we know. No judging here;
    analyze() decides what the result means once it can see DKIM and the sender.

    message:  parsed email dict (from parser.py / the JSON file)
    boundary: the boundary hop from hops.get_boundary()

    returns: dict with
        verdict              pass, fail, softfail, neutral, none, temperror,
                             permerror, or "missing" if there is no trusted result
        checked_ip           the IP Google says it checked
        ip_matches_boundary  checked_ip == the boundary's from_ip
        identity             "mailfrom" (envelope sender) or "helo" (server name)
        checked_domain       the domain SPF was evaluated for
        matches_return_path  checked_domain == the Return-Path domain
        alignment            strict / relaxed / none, compared with the From domain
        verified             None until dns_checks.py does its own SPF check
    """
    result = {
        "verdict": "missing",
        "checked_ip": "",
        "ip_matches_boundary": False,
        "identity": "",
        "checked_domain": "",
        "matches_return_path": False,
        "alignment": "none",
        "verified": None,
    }

    header = trusted_auth_result(boundary, message)
    if not header:
        return result

    # Only look inside the spf= clause, so DKIM or DMARC text can't be matched by mistake.
    clause = re.search(r"\bspf=[^;]*", header)
    if not clause:
        return result
    clause = clause.group(0)

    result["verdict"] = re.match(r"spf=(\w+)", clause).group(1).lower()

    # Google's comment: "designates <ip> as permitted sender" on pass,
    # "does not designate <ip> as permitted sender" on fail.
    ip = re.search(r"\bdesignates?\s+([0-9A-Fa-f:.]+)", clause)
    if ip:
        result["checked_ip"] = ip.group(1)
        result["ip_matches_boundary"] = ip.group(1) == boundary["from_ip"]

    # Which identity SPF checked: the envelope sender, or the HELO name when
    # Return-Path was empty (bounces, some phishing kits).
    mailfrom = re.search(r'smtp\.mailfrom="?([^";\s]+)', clause)
    helo = re.search(r'smtp\.helo="?([^";\s]+)', clause)
    if mailfrom:
        result["identity"] = "mailfrom"
        result["checked_domain"] = mailfrom.group(1).rpartition("@")[2].lower()
    elif helo:
        result["identity"] = "helo"
        result["checked_domain"] = helo.group(1).lower()

    rp_domain = message.get("return_path_domain", "").lower()
    result["matches_return_path"] = bool(rp_domain) and result["checked_domain"] == rp_domain
    result["alignment"] = alignment(result["checked_domain"], message.get("from_domain", ""))

    return result


def parse_dkim_tags(signature: str) -> dict:
    """
    Parse one DKIM-Signature header into {tag: value}.
    Split on ';', then each piece on the FIRST '='; strip all whitespace from values.
    """
    pass


def google_dkim_verdicts(header: str) -> list[dict]:
    """
    Pull every dkim= clause out of the trusted Authentication-Results.
    Each -> {"verdict": "pass", "domain": "nytimes.com", "selector": "scph20250409", "b_prefix": "SIzWjmvA"}
    (domain comes from header.d=, or from header.i= after the '@')
    """
    pass


def prove_dkim(boundary, message) -> list[dict]:
    """
    Report each DKIM signature and Google's verdict for it. No judging here.

    message:  parsed email dict
    boundary: boundary hop, used only to pick the trusted Authentication-Results

    returns: one dict per DKIM-Signature (empty list if there are none)
    """
    header = trusted_auth_result(boundary, message)
    verdicts = google_dkim_verdicts(header)
    results = []
    for signature in message.get("dkim_signatures", []):
        tags = parse_dkim_tags(signature)
        # find this signature's verdict: match b_prefix to tags["b"], else d + s
        # build the result dict, call alignment(tags["d"], from_domain)
    return results

def prove_dmarc():

    pass

with open("sample.json") as f:
    message = json.load(f)

spf = re.search(r"spf=\s*(\S+)", message["auth_results"][0])
if spf:
    print(spf.group(1))   # e.g. pass

if spf.group(1) == "pass":
    ip = re.search(r"designates\s+(\S+)", message["auth_results"][0])
    print(ip.group(1))
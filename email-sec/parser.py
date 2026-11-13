import hashlib
import re
import sys
import json

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class HTMLFacts(HTMLParser):
    """Collects links (href plus the text a reader sees) and images from HTML."""
    def __init__(self):
        super().__init__()
        self.links, self.images, self.forms = [], [], []
        self._link = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            self._link = {"href": a.get("href") or "", "text": ""}
        elif tag == "img":
            self.images.append(a.get("src") or "")
        elif tag == "form":                      # credential forms in HTML attachments
            self.forms.append(a.get("action") or "")

    def handle_data(self, data):
        if self._link is not None:
            self._link["text"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self._link is not None:
            self._link["text"] = " ".join(self._link["text"].split())
            self.links.append(self._link)
            self._link = None


def body_text(msg, kind):
    part = msg.get_body(preferencelist=(kind,))
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):   # bogus charsets are common in phish
        return part.get_payload(decode=True).decode("utf-8", errors="replace")


def attachments(msg):
    found = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        data = part.get_payload(decode=True) or b""
        found.append({
            "filename": filename or "",
            "declared_type": part.get_content_type(),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "first_bytes": data[:8].hex(),       # real type: 25504446 = PDF, 504b0304 = ZIP/Office
        })
    return found

"""parser.py: load an .eml and pull out the headers that matter for triage."""



def domain_of(address):
    """'Name <user@Example.com>' -> 'example.com' ('' if there isn't one)."""
    _, addr = parseaddr(address or "")
    return addr.rpartition("@")[2].lower()


def parse_eml(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    def one(name):
        value = msg[name]
        return str(value) if value is not None else ""

    def every(name):
        return [str(h) for h in msg.get_all(name, [])]

    from_name, from_addr = parseaddr(one("From"))

    return {
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": domain_of(from_addr),
        "reply_to": one("Reply-To"),
        "reply_to_domain": domain_of(one("Reply-To")),
        "return_path": one("Return-Path"),
        "return_path_domain": domain_of(one("Return-Path")),
        "to": one("To"),
        "subject": one("Subject"),
        "date": one("Date"),
        "message_id": one("Message-ID"),
        "received": every("Received"),              # newest first, as in the file
        "auth_results": every("Authentication-Results"),
        "dkim_signatures": every("DKIM-Signature"),
        "defects": [type(d).__name__ for d in msg.defects],
    }

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "sample.eml"
    result = parse_eml(path)

    # Temporary: save the parsed result next to the .eml (sample.eml -> sample.json)
    out_path = path.rsplit(".", 1)[0] + ".json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"Wrote {out_path}\n")

    for key, value in result.items():
        if isinstance(value, list):
            print(f"{key}: ({len(value)})")
            for item in value:
                print("    ", item)
        else:
            print(f"{key}: {value}")
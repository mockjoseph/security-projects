# main.py
import sys

import hops
from parser import parse_eml

#import links
#import sender
#import auth

email = parse_eml(sys.argv[1])
findings = []
for analyzer in (hops):
    findings += analyzer.analyze(email)

for f in sorted(findings, key=lambda f: f["severity"]):
    print(f"[{f['severity']}] {f['source']}: {f['message']}")
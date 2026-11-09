# Main runner of the email analysis tool
import email
from email.policy import default

# 1. Load the eml file
with open("sample.eml", "rb") as f:
    msg = email.message_from_bytes(f.read(), policy=default)

# 2. Pull Headers
print("From:", msg["From"])
print("Reply-To:", msg["Reply-To"])
print("Return-Path:", msg["Return-Path"])
print("To:", msg["To"])
print("Subject:", msg["Subject"])
print("Date:", msg["Date"])
print("Message-ID:", msg["Message-ID"])

print()
print("All 'Received' Headers:")
for hop in msg.get_all("Received", []):
    print(hop)

print()
print("All 'Authentication-Results' Headers:")
for hop in msg.get_all("Authentication-Results", []):
    print(hop)

print()
print("DKIM Sig:", msg["DKIM-Signature"])

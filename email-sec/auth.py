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

def prove_spf():
    
    pass

def prove_dkim():

    pass

def prove_dmarc():

    pass
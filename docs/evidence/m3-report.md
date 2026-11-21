# Assessment report #7

**Target:** juice-shop  
**Overall risk:** info  
**Narrative source:** deterministic rules

## Executive summary

1 open port(s) found. Highest severity: info. Findings use deterministic exposure rules.

## Findings

| Severity | Port | Service | Detail |
|---|---|---|---|
| info | 3000/tcp | http | identified from HTTP response |

## Remediation

### INFO: Open port 3000/tcp (http)

Web service detected; needs application-level testing.

**Fix:** Run a web scan (ZAP integration planned); enforce HTTPS and security headers.

## Method and limits

- Scan: nmap TCP connect, top 100 ports, against a scope-verified address.
- Severity is assigned by deterministic rules; AI text cannot change it.
- No CVE correlation yet: absence of a CVE here does not mean a service is patched.
- AI-written text is validated, length-limited and has CVE identifiers removed.


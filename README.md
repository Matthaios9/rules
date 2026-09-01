# YARA Rules

A collection of YARA rules for detecting malware, exploit kits, webshells, and
other threats organized by category so you can pull in just what you need.

## What's YARA?

If you're not familiar: YARA is a tool used by malware analysts to identify
files based on patterns, think of it like a very flexible "signature"
system. You write a rule describing what a piece of malware looks like
(specific byte sequences, strings, file structure), and YARA scans files
against it and tells you what matched. It's widely used in incident
response, threat hunting, and malware research.

## What's in here

Rules are split by category:

- `malware/` — general malware families, APT groups, RATs, ransomware, POS malware
- `webshells/` — web shell detection
- `exploit_kits/` — known exploit kit signatures
- `maldocs/` — malicious document detection (Office, PDF)
- `cve_rules/` — rules tied to specific CVEs
- `crypto/` — cryptographic algorithm detection
- `email/` — phishing and malicious email detection
- `packers/` — packer and compiler identification
- `capabilities/` — generic capability detection (not necessarily malicious on their own)
- `antidebug_antivm/` — anti-analysis/anti-VM technique detection
- `utils/` — helper rules (base64, IP/domain extraction, etc.); some rules in here are disabled by default and need to be enabled — note some of these rules are disabled by default and need to be enabled before use

## Requirements

YARA 4.0 or later.

Check your installed version:

```bash
yara -v
```

Install it if you don't have it:

- **Ubuntu/Debian:** `sudo apt install yara`
- **macOS:** `brew install yara`
- Or build from source: https://yara.readthedocs.io

## Usage

Scan a single file against a rule:

```bash
yara malware/RANSOM_Locky.yar /path/to/suspicious/file
```

Scan a directory recursively against a whole category:

```bash
yara -r malware/*.yar /path/to/directory
```

Scan against every rule in the repo:

```bash
find . -name "*.yar" -exec yara -w {} /path/to/file \;
```

Note the `-w` flag treats warnings as non-fatal so a scan doesn't stop
partway through.

## License

GNU GPLv2 — see [LICENSE](./LICENSE.md).
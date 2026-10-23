# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — Threat Hunt Pack

Hunt hypotheses, Sigma rules, YARA rules and Cortex XQL queries for **PHP2Shell**, the two critical (CVSS v4.0 9.2) unauthenticated RCE vulnerabilities in the PHP core runtime patched on 21 October 2026.

**TLP:CLEAR** · Version 1.2 · 22 October 2026

> Patching is the only complete fix: PHP **8.5.12, 8.4.27, 8.3.36, 8.2.35**, then restart every PHP worker. PHP 8.1 and older receive no upstream fix. This pack is for finding exploitation that happened before you patched: Amazon saw the first attempt on **17 October 2026**, four days before disclosure.

## Contents

| Path | What it is |
|---|---|
| [`report/PHP2Shell_Threat_Hunt_Report.md`](report/PHP2Shell_Threat_Hunt_Report.md) | Full report: summary, IOCs, 7 hunt procedures, detection content, validation status, revision notes, references (also as `.docx`) |
| [`detections/sigma/`](detections/sigma/) | 20 Sigma rules + 1 correlation rule, mapped to Procedures P1–P7 |
| [`detections/yara/php2shell_hunt.yar`](detections/yara/php2shell_hunt.yar) | 4 YARA rules: poisoned session files (code and serialized gadgets), small PHP web shells, malicious `.user.ini` / `.htaccess` |
| [`detections/xql/`](detections/xql/) | Hand-written Cortex XDR / XSIAM hunt queries for Procedures 4–7 |
| [`detections/conversions/splunk/`](detections/conversions/splunk/) | Auto-generated Splunk SPL from the Sigma rules (reference only, generic field names) |
| [`tests/`](tests/) | Regex tests for the Sigma rules (Python `re` + RE2, with a backtracking guard) and YARA tests with generated samples |

## Coverage

| Procedure | What it hunts | Sigma | YARA | XQL |
|---|---|---|---|---|
| P1 OOM corruption | Oversized field names, many part headers, empty file controls, deep nesting, `in Unknown on line 0` OOM errors, worker crashes, oversized-POST bursts, MadPot source IPs | P1-00 – P1-04, P1-18 | — | — |
| P2 Stale global state | `PHPSESSID` as multipart form field, upload-progress field, PHP code / serialized gadgets in part name, filename or progress value | P2-05 – P2-07 | 2 session-file rules | — |
| P3 Memory disclosure | Oversized `Set-Cookie: PHPSESSID` (~67 KB leak) | P3-08 | — | — |
| P4 Web shell deployment | PHP files written by the PHP worker or the web account | P4-09, P4-10 | Generic web shell | Q4 |
| P5 Suspicious execution | Tools, interpreters and LOLBins under PHP workers or run as the web account | P5-11, P5-12, P5-19 | — | Q5 |
| P6 Persistence | Cron, SSH keys, systemd, `.user.ini` / `.htaccess`, `crontab` as web account | P6-13 – P6-15 | `.user.ini` / `.htaccess` | Q6 |
| P7 Command and control | Shells, netcat, interpreters (incl. PHP CLI) connecting out as the web account; worker egress on unusual ports | P7-16, P7-17 | — | Q7 |

## Quick start

```bash
# Sigma: validate, test and convert (example: Splunk)
pip install sigma-cli pysigma-backend-splunk pyyaml google-re2
sigma check detections/sigma/
python3 tests/test_sigma_regex.py
sigma convert -t splunk --without-pipeline detections/sigma/

# YARA: test, then sweep (the yara CLI takes one target per run)
pip install yara-python
python3 tests/test_yara.py
for d in /var/lib/php/sessions /var/www /tmp /dev/shm; do
  yara -r -s detections/yara/php2shell_hunt.yar "$d"
done
```

## Validation status

| Item | Validated | Not validated |
|---|---|---|
| Sigma | `sigma check` passes (sigma-cli 3.1.0); ATT&CK tags checked against v20 STIX data; all rules convert to Splunk SPL; body/header regexes pass `tests/test_sigma_regex.py` in Python `re` and RE2 with a backtracking guard | No production true positives. Request shapes come from analysis of leaked pre-disclosure PoCs, not a reproduced exploit |
| YARA | Compiles without warnings (YARA 4.5.4); `tests/test_yara.py`: 59 samples pass, 3 documented gaps; includes session files produced by a PHP 8.3.6 server | Not run against real attacker artefacts |
| XQL | Regexes compile in RE2; field names match Cortex schema documentation | Not executed in a tenant: confirm ENUM values and user-name format locally |

All rules are `status: experimental`. An independent review checked every claim against primary sources and tested the rules against a local PHP 8.3.6 server; v1.2 addresses all of its findings (see the revision notes in the report).

## Before you deploy

1. Body-inspection rules (P1-03, P1-18, P2-05/06/07) and P3-08 need fields most logs do not carry: `request_body`, `request_content_type`, `response_set_cookie`. Map them to your WAF, reverse-proxy or NDR schema (report Section 3.1). Endpoint agents and NGFW logs cannot see request bodies.
2. Add per-site PHP-FPM pool users (cPanel, Plesk) to the account lists in P4–P7 and the XQL queries.
3. Run everything in log-only / Count mode first.
4. A clean session-file YARA sweep is not proof of no exploitation: upload-progress cleanup (on by default) empties completed entries, and Debian/Ubuntu purge old session files every 30 minutes. Image session directories early.
5. The six MadPot IPs include shared anonymization infrastructure: investigate matches, do not block on them alone.
6. Elasticsearch Lucene regexp does not support `(?i)`, `\s`, `\b` or lazy quantifiers; use ES|QL or EQL for the regex rules there.

## Author

**Saied** ([@saiedatef](https://github.com/saiedatef)): threat hunting and DFIR. The seven hunt hypotheses and the detection content in this repository are my work. Issues, false-positive reports and pull requests are welcome.

## License

- Detection content (`detections/`, `tests/`): [Detection Rule License (DRL) 1.1](LICENSE-DETECTION-RULES.md)
- Report (`report/`): [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE-REPORT.md)

## Disclaimer

Provided as is, for defensive use. Test in your environment before production deployment. Corrections and pull requests are welcome.

---
title: "PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — Threat Hunt Report"
subtitle: "Hunt hypotheses, Sigma and YARA detection content"
date: "22 October 2026 · Version 1.2 · TLP:CLEAR"
---

# At a glance

| Item | Detail |
|---|---|
| Vulnerabilities | CVE-2026-109618 (RCE via out-of-memory corruption) and CVE-2026-109619 (RCE via stale global state), collectively "PHP2Shell" [1][2] |
| Severity | CVSS v4.0 9.2 (Critical), both CVEs [1][2] |
| Affected | PHP runtime serving web requests. Symantec lists PHP-FPM, Apache mod_php, php-cgi, FrankenPHP and LiteSpeed [6]. The advisories validate RCE on mod_php for both CVEs and on PHP-FPM for the session path of CVE-2026-109619; FPM, FrankenPHP and LSAPI remain unconfirmed for CVE-2026-109618 [1][2]. Researchers found affected releases back to PHP 5.4 [4][5] |
| First fixed releases | PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 [1][2]. No upstream fix for 8.1 and older [8][17] |
| Exploitation | First attempt seen by Amazon MadPot on 17 Oct 2026, before disclosure; attempts from several sources on 21 Oct [9] |
| Fix | Upgrade PHP and restart every worker. Updating the application does not update the runtime underneath it [4] |
| Detection content | 20 Sigma rules + 1 correlation rule, 4 YARA rules, 4 Cortex XQL hunt queries, plus test scripts (Section 3, Appendices A–C) |

# 1. Summary of Attack

**Attack Names:** PHP2Shell, a pair of critical remote code execution vulnerabilities in the PHP core runtime, collectively tracked as CVE-2026-109618 and CVE-2026-109619. The PHP project released fixes on October 21, 2026 [3][8].

**Threat Actors:** No specific named threat actor or APT group has been attributed. Amazon traced the earliest exploitation attempt to its MadPot honeypots on October 17; the traffic came from an anonymized IP address, and it remains unclear how the actor obtained exploit details during the embargo [7][9]. Varied payloads and anonymization infrastructure suggest multiple actors [9].

**Targeted Sectors/Industries:** PHP underpins a large share of the web. WordPress, Drupal, TYPO3, Joomla, Magento, Nextcloud, pfSense and OPNsense are written in PHP, and PHP code also appears in components of proprietary products and appliances [6][16]. Palo Alto Networks Cortex Xpanse identified over 22.6 million exposed instances potentially vulnerable to both CVEs [18][19]. PHP runs shared hosting platforms and control panels such as cPanel and Plesk, and many vendor applications bundle PHP without saying so, which makes affected assets hard to find [12]. All internet-facing sectors running PHP are at risk globally.

**Appliances:** Palo Alto Networks lists all versions of PAN-OS and Panorama as affected, with no special configuration needed, and had not shipped fixed releases at the time of reporting [26][30]. Fortinet PSIRT confirms FortiOS, FortiWeb and FortiAnalyzer are not affected and is investigating twelve other products, including FortiSIEM, FortiSOAR and FortiClient EMS [16]. Include appliance management interfaces in the hunt scope.

## 1.1 Affected and fixed versions

| PHP branch | Vulnerable | First fixed |
|---|---|---|
| 8.5 | < 8.5.12 | 8.5.12 |
| 8.4 | < 8.4.27 | 8.4.27 |
| 8.3 | < 8.3.36 | 8.3.36 |
| 8.2 | < 8.2.35 | 8.2.35 |
| 8.1 and older | Affected (per researchers) | No upstream fix — move to a supported branch or a vendor backport |

Source: [1], [2]; end-of-support status [8], [17]. Restart Apache, PHP-FPM and any long-running PHP workers after upgrading.

**Interim mitigations from the advisories (not complete fixes) [1][2]:** set `session.upload_progress.enabled=0` (recommended even after patching if the feature is unused); on PHP 8.5 set `fatal_error_backtraces=0`; enforce `memory_limit=-1` administratively with container or cgroup memory limits, and never `RLIMIT_AS` / `RLIMIT_DATA`; keep `post_max_size` conservative; block multipart requests at the frontend where the application has no uploads; consider `pm.max_requests=1`; restart every worker after any change.

## 1.2 MITRE ATT&CK Tactics & Techniques

Tactic names follow ATT&CK Enterprise v20, in which Defense Evasion is split into Stealth and Defense Impairment. Data sources use v20 data components.

| Tactic | Technique | How it applies | Rules |
|---|---|---|---|
| Initial Access | T1190 Exploit Public-Facing Application | Unauthenticated RCE through crafted POST bodies, processed before application code runs | P1–P3 |
| Credential Access | T1212 Exploitation for Credential Access | Memory disclosure of tokens, keys and credentials through `Set-Cookie: PHPSESSID` | P3-08 |
| Execution | T1059.004 Unix Shell; T1059.006 Python; T1059.001 PowerShell; T1059.003 Windows Command Shell | Commands run by or under the PHP worker after exploitation | P5, P7-16 |
| Discovery | T1033 System Owner/User Discovery | `id`, `whoami`, `uname` run under the web account | P5 |
| Stealth | T1218 System Binary Proxy Execution | LOLBins (mshta, rundll32, regsvr32, certutil) under PHP on Windows | P5-12 |
| Persistence | T1505.003 Web Shell | Web shell deployment and `.user.ini` / `.htaccess` auto-prepend | P4, P6-14 |
| Persistence | T1053.003 Cron; T1098.004 SSH Authorized Keys; T1543.002 Systemd Service | Persistence as the web service account | P6-13, P6-15 |
| Command and Control | T1071.001 Web Protocols; T1095 Non-Application Layer Protocol; T1571 Non-Standard Port | Reverse shells and implant check-ins from the web tier | P7 |

## 1.3 Indicators of Compromise (IOCs)

**Relevant CVEs**

- CVE-2026-109618 (CVSS 9.2) — PHP Group PHP runtime — RCE via out-of-memory corruption [1]
- CVE-2026-109619 (CVSS 9.2) — PHP Group PHP runtime — RCE via stale global state; the PHP advisory lists "memory disclosure" among its confirmed impacts [2]

**CVE attribution conflict.** Sources disagree on which CVE covers the session upload-progress path and the memory disclosure. The PHP advisory for CVE-2026-109619 names session upload progress as a confirmed producer and consumer and lists memory disclosure as an impact [2], and the researchers' site agrees [4]. Wiz's blog table lists "Upload-progress unserializer use-after-free" and "Remote process-memory disclosure" under CVE-2026-109618, and fatal-error backtrace and OPcache findings under CVE-2026-109619 [5]. This report follows the PHP advisory and tags the affected rules with both CVEs.

**Network indicators — source IPs observed by Amazon MadPot [9]**

| IP address | First observed |
|---|---|
| 103.216.220.92 | 2026-10-17 |
| 31.223.184.166 | 2026-10-21 |
| 37.19.200.5 | 2026-10-21 |
| 134.209.159.64 | 2026-10-21 |
| 103.114.163.188 | 2026-10-21 |
| 95.217.98.37 | 2026-10-21 |

These addresses include shared anonymization infrastructure that is not exclusive to this activity. Amazon advises investigating matches rather than blocking them [9].

**File names / behavioral indicators**

- Symantec file-based protection detects related tooling as `Hacktool.Php2shell` [6].
- Arctic Wolf Labs observed scanning and exploitation attempts that passed `wget` requests to retrieve ELF and Golang binaries associated with commodity malware [12].
- Fake proof-of-concept tools circulated around the disclosure [25]. Treat any "PHP2Shell PoC" from an unverified repository as potentially malicious before running it in a lab.

**Request- and log-level indicators**

> **Source caveat.** The specific request shapes below — the "rawkey" name, the ~1 MiB field name, the ~450-byte upload-progress bodies, the `PHPSESSID` form-field chain and the ~590-request brute force — come from Abstract Security's analysis of PoCs that leaked before the official release; Abstract noted the leaked claims were "yet to be verified" [14]. The PHP advisories confirm the underlying mechanisms (OOM during request parsing; session upload progress as a producer and consumer) but do not publish request shapes [1][2]. Treat these indicators as strong hunting leads, not confirmed signatures.

- CVE-2026-109618 ("rawkey" variant): a form field **name** large enough to exhaust `memory_limit` during POST parsing — roughly 1 MiB in the leaked PoC. It works through `application/x-www-form-urlencoded` as well as `multipart/form-data` bodies. No legitimate client sends a field name near 1 KB [14].
- CVE-2026-109618, other OOM triggers named by the advisory: multipart bodies without a usable declared content length, a part with an unrestricted number of headers, many empty file controls (they do not count toward `max_file_uploads`) and nested field names [1].
- Session upload-progress path: multipart POSTs of about 450 bytes carrying `PHP_SESSION_UPLOAD_PROGRESS`, often with `PHPSESSID` supplied as a **form field** rather than a cookie, and PHP code or serialized objects (`|O:8:"`) in the filename, part name or progress value [14][8]. PHP stores the client-supplied field name and filename in the session without validation [29].
- Memory disclosure: an abnormally large `Set-Cookie: PHPSESSID` value in the response. One response can expose about 67 KB of worker memory [13].
- Error logs: `Allowed memory size … (tried to allocate …) in Unknown on line 0` — memory exhaustion outside any script [14]. Worker crashes (`AH00052 … exit signal Segmentation fault`, php-fpm children exiting on signal 11/6 or with code 255) are the author's hunting guidance based on the use-after-free behaviour the advisories describe [1][2].
- Network sensors: Palo Alto Networks Threat Prevention signature 543004, with signatures 97622–97625 added on 21 October [19][26]; FortiGuard virtual patches shipped in version 37.316 [26].

# 2. Attack Procedures (Threat Hunt Hypotheses)

## Procedure 1: Exploit Public-Facing Application via OOM Corruption — T1190

**Description:** PHP handles out-of-memory (OOM) conditions by unwinding straight out of the current execution context and aborting the request. In certain early-request contexts, request-scoped memory is reachable before it has been fully initialized. If any allocation fails in that window, the non-local exit skips the initialization and PHP's error path does not account for the half-built state. The request shutdown routine then reads or branches on that memory. The failing allocation does not need to be related to the corrupted memory, so the trigger is generic: any OOM during the window is enough. Several OOM-induction strategies trigger it consistently, which makes exploitation reliable and leads to remote code execution [1][13].

AWS describes both PHP2Shell vulnerabilities as rooted in "how PHP handles multipart/form-data request processing" before application code runs [8]; the leaked "rawkey" PoC also works with an oversized field name in a urlencoded body [14]. The advisory lists further OOM triggers: missing content length, unlimited headers per part, empty file controls and nested field names [1]. On Apache with mod_php, the attack completes before any application code runs, so application logs may show nothing [6]. The leaked PoC analysis describes an ASLR brute-force phase of about 590 oversized requests over roughly 15 minutes from one source [14].

**Logs & Event IDs:**

- Apache/HTTPD and PHP error logs: OOM errors (`Allowed memory size … exhausted … in Unknown on line 0`), SIGSEGV/SIGABRT child exits (`AH00052`)
- PHP-FPM logs: children exiting on a signal or with code 255, and respawn events
- Network/WAF logs: POST requests with form field names of 1,000+ bytes, parts with dozens of headers, runs of empty file controls, deeply nested field names, oversized bodies, bursts of large POSTs from one source

**ATT&CK data components:** DC0085 Network Traffic Content, DC0038 Application Log Content

**Detection content:** Sigma P1-00, P1-01, P1-02, P1-03, P1-04, P1-18 (Appendix A).

**Coverage gap:** application-specific OOM paths (large imports, image processing, deep JSON) and multipart bodies without a usable content length have no request signature. ModSecurity `REQBODY_ERROR` / `MULTIPART_STRICT_ERROR` and frontend limits on parts, headers per part and nesting depth are the better control there [1][14].

## Procedure 2: Exploit Public-Facing Application via Stale Global State — T1190

**Description:** PHP workers are long-lived and reused across requests, and they keep some global state (error, session, object and extension data) that points to memory belonging to a single request. That state should be cleared before the request's memory is freed. A fatal error can stop an operation before it cleans up — running out of memory, hitting the execution time limit or a failed compile. A later warning during shutdown can also refill error state that was already cleared. The request's memory is then freed while the worker still points to it, which is a use-after-free. When the same worker handles its next request, early steps that run before normal setup can read, free or act on that stale pointer. With a carefully crafted memory layout, an attacker can turn this into RCE. Exploitation takes two separate HTTP requests handled by the same worker: the first leaves stale state behind and the second uses it [2][13].

The advisory confirms session upload progress as both a producer and a consumer of stale state, with session lifecycle RCE validated against mod_php and PHP-FPM [2]. Session upload progress is enabled by default [29]. In review testing on PHP 8.3.6 with benign requests, a `PHPSESSID` multipart form field set the session ID even with `session.use_only_cookies=On`, and the raw client filename was stored in the session file, matching the leaked PoC analysis [14].

**Other confirmed paths not covered by request signatures:** the PHP 8.5 fatal-error-backtrace producer (confirmed RCE against mod_php), INI diagnostics raised before request initialization (a confirmed consumer; FPM is exposed when the frontend passes `PHP_VALUE` / `PHP_ADMIN_VALUE`), and fatal errors or timeouts on attacker-reachable routes [2]. Wiz additionally reports OPcache type confusion [5]. Mitigate these with the advisory settings in Section 1.1 and hunt them through Procedures 4–7.

**Logs & Event IDs:**

- PHP-FPM logs: repeated worker restarts, use-after-free crashes
- Apache error logs: segmentation faults from mod_php workers
- Web server and WAF logs: two requests from the same source in quick succession that land on the same worker (not necessarily the same endpoint), particularly with `PHP_SESSION_UPLOAD_PROGRESS` in the body or `PHPSESSID` as a form field
- Session files (`sess_*` in `session.save_path`): upload-progress entries whose field name, filename or key holds PHP code or a serialized object; also session IDs that do not fit your `session.sid_length` / `session.sid_bits_per_character` format (attacker-chosen IDs)

**ATT&CK data components:** DC0085 Network Traffic Content, DC0038 Application Log Content, DC0039 File Creation

**Detection content:** Sigma P2-05, P2-06, P2-07; YARA `PHP2Shell_Session_UploadProgress_PHP_Code`, `PHP2Shell_Session_UploadProgress_Serialized_Gadget`.

## Procedure 3: Memory Disclosure via Stale Session-ID Pointer — T1212

**Description:** The session ID finding follows a similar pattern to the use-after-free but produces information disclosure rather than a crash. After memory exhaustion leaves stale session ID state, attacker-influenced memory is interpreted as a string with an oversized length. PHP then returns the resulting value through a `Set-Cookie: PHPSESSID` response header. An attack can expose approximately 67 KB of process memory. Its contents depend on the worker's state at the time of exploitation and may include internal runtime data or sensitive information processed by the application [13]. See Section 1.3 for the CVE attribution conflict.

The memory disclosure can expose passwords, authentication tokens, API keys, certificates and information belonging to other requests without requiring code execution, which makes it harder to catch with tools focused on malicious execution [4].

**Logs & Event IDs:**

- Reverse proxy / load balancer / WAF logs: abnormally large `Set-Cookie: PHPSESSID` response headers (default IDs are 32 characters)
- Reverse proxy error logs (untested lead): a header this large can exceed nginx's default proxy buffer and surface as "upstream sent too big header"
- Network capture: oversized response cookies from PHP endpoints

**ATT&CK data components:** DC0085 Network Traffic Content, DC0038 Application Log Content

**Detection content:** Sigma P3-08. A hit means process memory left the server: rotate secrets handled by that application.

## Procedure 4: Web Shell Deployment — T1505.003

**Description:** The primary goal of exploitation is likely to be server takeover, with RCE leading to a web shell and then persistence or pivoting into the wider network. Crashing the server is an easy fallback, and credential or memory theft is a quieter alternative [6]. Post-exploitation monitoring should cover web shell deployment, suspicious processes spawned by PHP or web servers, malicious command execution, persistence activity and lateral movement [12].

Post-exploitation indicators include new or modified `.php` files in web roots, upload directories, plugin directories and `mu-plugins`. The shell is written by the PHP worker or by a process running as the web account (`sh`, `wget -O`, `curl -o`), so hunts must anchor on the web account as well as the worker image, and must not exclude `php-fpm` or the web server process as the writer.

**Logs & Event IDs:**

- File integrity monitoring: new/modified `.php` files in web root directories
- Sysmon Event ID 11 (FileCreate) on web-accessible directories (Windows and Sysmon for Linux)
- Windows Security Event ID 4663 (object access) — requires a SACL on the web directories

**ATT&CK data components:** DC0039 File Creation, DC0061 File Modification

**Detection content:** Sigma P4-09, P4-10; YARA `Generic_PHP_Webshell_Request_To_Exec`; XQL Q4.

## Procedure 5: Suspicious Process Spawned by PHP or Run as the Web Account — T1059

**Description:** Suspicious execution patterns include: on Linux, php-fpm, php-cgi, httpd or apache2 launching sh, bash, python, perl, curl, wget or nc; any process whose command line matches `/dev/tcp/`, `fsockopen` or `mkfifo`; on Windows, php-cgi.exe or php.exe launching cmd.exe, powershell.exe, certutil.exe or cscript.exe; and nc.exe run with `-e`, or PowerShell command lines containing `System.Net.Sockets.TcpClient` or `New-Object Net.WebClient` [6].

PHP's `exec()`, `system()` and `shell_exec()` always run through `/bin/sh -c` on Linux and `cmd.exe /c` on Windows. A bare shell child is therefore normal for many applications. On Debian and Ubuntu `/bin/sh` is dash, which forks before running the command, so tools such as `curl` or `python3` usually show `sh`, not `php-fpm`, as their parent. Hunts therefore combine two anchors: the PHP worker as parent (with a suspicious command line for shell children) and the web service account as the user, regardless of parent. Match resolved binary names: telemetry often records `/usr/bin/python3.13` or `/bin/nc.openbsd`.

**Logs & Event IDs:**

- Sysmon Event ID 1 (Process Creation) filtered on ParentImage (php-fpm, php-cgi, httpd, apache2, lsphp, frankenphp) or on User (web service accounts)
- Windows Security Event ID 4688 (Process Creation) — enable command-line auditing
- Linux auditd `execve` syscall rule scoped to the web server user UID

**ATT&CK data components:** DC0032 Process Creation

**Detection content:** Sigma P5-11, P5-12, P5-19; XQL Q5.

## Procedure 6: Persistence via Cron, SSH Keys, or Startup Modification — T1053 / T1098

**Description:** Persistence indicators to hunt for include new cron entries, systemd units, Supervisor entries, SSH `authorized_keys` additions, newly created application admin accounts, or unexpected outbound connections from PHP service accounts [14]. Checks should also include new or modified `.php` files in web roots and upload directories, `.user.ini` or `.htaccess` changes that auto-prepend a payload [28], and unexpected cron jobs, processes and users [14][4].

A web service account that installs its own crontab writes the spool file through the privileged `crontab` binary (setgid on Debian/Ubuntu, setuid root on RHEL), so the write is attributed to `crontab`, not to the PHP worker. On shared hosting, add per-site PHP-FPM pool users and `nobody` (LiteSpeed default) to every account list.

**Logs & Event IDs:**

- Linux auditd: file writes to `/etc/cron*`, `/var/spool/cron/`, `~/.ssh/authorized_keys`
- Sysmon for Linux Event ID 11 (FileCreate) on cron/systemd paths; Event ID 1 for `crontab` run as the web account
- Windows Security Event ID 4698 (Scheduled Task Created)

**ATT&CK data components:** DC0039 File Creation, DC0061 File Modification, DC0001 Scheduled Job Creation, DC0032 Process Creation

**Detection content:** Sigma P6-13, P6-14, P6-15; YARA `PHP2Shell_Persistence_UserIni_Htaccess_Prepend`; XQL Q6.

## Procedure 7: Command and Control via Reverse Shell — T1071.001 / T1095

**Description:** Reverse-shell indicators include any process whose command line matches `/dev/tcp/`, `fsockopen` or `mkfifo` on Linux, and on Windows, nc.exe run with `-e`, or PowerShell command lines containing `System.Net.Sockets.TcpClient` or `New-Object Net.WebClient` [6]. A native-code payload can open a socket without ever spawning a shell, so outbound connections from the web UID should also be logged [14]. Include the PHP CLI (`php -r '$s=fsockopen(...)'`) and `openssl` in the interpreter list.

Hunts should not exclude port 443 (reverse shells commonly use it) or internal destinations (pivots into the internal network go there).

**Logs & Event IDs:**

- Sysmon Event ID 3 (Network Connection) from PHP/web server processes and from shells running as the web account
- Linux auditd `connect` syscall from the web user UID
- Firewall/proxy logs: unexpected outbound connections from web server hosts

**ATT&CK data components:** DC0082 Network Connection Creation, DC0032 Process Creation

**Detection content:** Sigma P7-16, P7-17; XQL Q7.

# 3. Detection Content

## 3.1 Sigma rules

20 Sigma rules plus one `event_count` correlation rule. Full rules are in Appendix A and in `detections/sigma/`.

| Rule | Detection | Procedure | Log source | Level |
|---|---|---|---|---|
| P1-00 | Requests from Amazon MadPot source IPs | P1, P2 | webserver | medium |
| P1-01 | PHP memory exhaustion outside script context | P1, P2 | PHP / web server error log | high |
| P1-02 | PHP worker crash or abnormal exit | P1, P2 | PHP / web server error log | medium |
| P1-03 | Oversized form field name (rawkey) | P1 | webserver + request body | high |
| P1-04 | Oversized POST + burst correlation (≥10 in 10 min per IP) | P1 | webserver | low / high |
| P1-18 | Structural OOM trigger (many part headers, empty file controls, deep nesting) | P1 | webserver + request body | high |
| P2-05 | `PHPSESSID` supplied as multipart form field | P2 | webserver + request body | high |
| P2-06 | Upload-progress field with session identifier | P2 | webserver + request body | medium |
| P2-07 | PHP code or serialized object written to session via upload progress | P2, P4 | webserver + request body | high |
| P3-08 | Oversized `PHPSESSID` in Set-Cookie (memory disclosure) | P3 | proxy response headers | critical |
| P4-09 | PHP file written to upload/temp dir by PHP worker or web account | P4 | file_event | high |
| P4-10 | PHP file written under web root by PHP worker or web account (hunt) | P4 | file_event | low |
| P5-11 | Suspicious child of PHP worker (Linux) | P5 | process_creation / linux | high |
| P5-12 | Suspicious child of PHP worker or IIS app pool (Windows) | P5 | process_creation / windows | high |
| P5-19 | Download, network or interpreter tool run as web account (Linux) | P5 | process_creation / linux | medium |
| P6-13 | Persistence file written by PHP worker or web account (Linux) | P6 | file_event / linux | high |
| P6-14 | `.user.ini` / `.htaccess` written by PHP worker or web account | P6 | file_event | medium |
| P6-15 | `crontab` run by web service account | P6 | process_creation / linux | high |
| P7-16 | Shell, netcat or interpreter network connection as web account | P7 | network_connection / linux | high |
| P7-17 | PHP worker egress on unusual port (hunt) | P7 | network_connection / linux | low |

**Fields to map before deployment**

| Field | Meaning | Typical source |
|---|---|---|
| `request_body` | Raw HTTP request body | ModSecurity audit log part C, WAF full-request logging, NDR HTTP body extraction |
| `request_content_type` | `Content-Type` request header | Same as above, or a custom access-log format |
| `response_set_cookie` | `Set-Cookie` response header value(s) | Reverse proxy / load balancer custom log format, NDR |
| `cs-bytes` | Request size in bytes | Apache `%I` (mod_logio), nginx `$request_length`, IIS `cs-bytes` |
| `c-ip`, `cs-method`, `cs-cookie` | Sigma webserver taxonomy | Standard access logs |

**Deployment notes**

1. Run every rule in log-only or Count mode first; promote after a clean baseline.
2. Body-inspection rules (P1-03, P1-18, P2-05/06/07) need the full request body. Cloud WAFs inspect only the first 8–128 KB of a body [14][8].
3. Endpoint agents and NGFWs do not log request bodies or response headers. Procedures 1–3 need a WAF, reverse proxy or NDR source.
4. P2-05 covers the default `session.name` (`PHPSESSID`). Add any custom session name.
5. Add per-site PHP-FPM pool users (cPanel, Plesk) to the account lists in P4–P7 and the XQL queries.
6. Behind a CDN or load balancer, group the P1-04 correlation by the logged X-Forwarded-For client address.
7. Regexes are tested on Python `re` (PCRE-like, as Splunk uses) and RE2 (Cortex XQL, Chronicle, Loki). Elasticsearch Lucene regexp does not support `(?i)`, `\s`, `\b` or lazy quantifiers; use ES|QL or EQL there.
8. Hunt the window from 17 October 2026 (first observed attempt) to your patch date, not only from disclosure [9].

## 3.2 YARA rules

Four YARA rules for file sweeps. Full rules are in Appendix B and in `detections/yara/`.

| Rule | Scan target | Finds |
|---|---|---|
| `PHP2Shell_Session_UploadProgress_PHP_Code` | Session files (`sess_*` in `session.save_path`) | Upload-progress session data holding `<?php`, `<?=` or `<? ` in the field name, filename or progress key — code planted for a later include of the session file |
| `PHP2Shell_Session_UploadProgress_Serialized_Gadget` | Session files | `\|O:N:"` or `\|C:N:"` inside a stored string or the progress key — serialize-handler mismatch gadget |
| `Generic_PHP_Webshell_Request_To_Exec` | Web roots, uploads, `/tmp`, `/dev/shm` | Small PHP files passing request input into eval or execution functions (direct, one-step assignment or variable function). Generic, not PHP2Shell-specific |
| `PHP2Shell_Persistence_UserIni_Htaccess_Prepend` | `.user.ini`, `.htaccess` | `auto_prepend_file` / `auto_append_file` pointing at session, temp or upload paths, image or text files, or wrapper URLs; PHP handlers mapped to image extensions (including `FilesMatch` and cPanel `ea-php` handlers) |

```bash
for d in /var/lib/php/sessions /var/www /tmp /dev/shm; do
  yara -r -s detections/yara/php2shell_hunt.yar "$d"
done
```

**Limits of the session-file sweep.** `session.upload_progress.cleanup` is on by default and empties progress data once the POST is fully read; in testing, a completed request left a 0-byte `sess_<attacker-chosen-id>` file that YARA cannot match. Debian and Ubuntu also purge `sess_*` files older than `session.gc_maxlifetime` (24 minutes by default) every 30 minutes, so files from 17–22 October are probably gone. A clean sweep is not evidence of no exploitation. During incident response, image the session directory first, and look for session file names whose length or character set does not fit your `session.sid_length` and `session.sid_bits_per_character`.

## 3.3 Cortex XQL hunt queries

Four endpoint hunt queries for Cortex XDR / XSIAM (`xdr_data`). In process events, `actor_process_*` is the parent and `action_process_*` the new process; file targets are `action_file_*`. Every query anchors on both the PHP worker image and the web service account. Full queries are in Appendix C and in `detections/xql/`.

| Query | Procedure | Purpose |
|---|---|---|
| Q4 | P4 | PHP script created or written in upload, media or temp directories by the PHP worker or a web account |
| Q5 | P5 | Download tools, interpreters and LOLBins under the PHP worker or run as a web account; shells only with suspicious command lines |
| Q6 | P6 | Cron, SSH key, systemd, `.user.ini` and `.htaccess` writes by the worker or a web account |
| Q7 | P7 | Shells, netcat variants and interpreters connecting out as a web account; worker egress on unusual ports |

Request-level hunts for Procedures 1–3 cannot run on `xdr_data`: endpoint telemetry carries no request bodies, cookies or response headers. Run the Sigma rules for those procedures against the dataset where WAF or reverse-proxy logs land.

## 3.4 Validation status

| Item | Validated | Not validated |
|---|---|---|
| Sigma | `sigma check` passes (sigma-cli 3.1.0, pySigma 1.5.1) with ATT&CK tags checked against v20 STIX data; every rule converts to Splunk SPL; `tests/test_sigma_regex.py` checks each body/header regex against realistic multipart and urlencoded samples in Python `re` and RE2, plus a backtracking guard on 1–2 MB bodies (all pass) | No production true positives; request shapes come from leaked-PoC analysis, not from a reproduced exploit |
| YARA | Compiles without warnings on YARA 4.5.4; `tests/test_yara.py` runs 62 samples (59 checked, all pass, plus 3 documented web-shell gaps), including session files produced by a PHP 8.3.6 server | Not run against real attacker artefacts |
| XQL | Regexes compile in RE2; field names match the Cortex schema documentation | Not executed in a tenant; ENUM values and the user-name format must be confirmed locally |
| Independent review | A second reviewer re-checked facts against primary sources and tested rules against a local PHP 8.3.6 server with benign requests; all findings are addressed in v1.2 | — |

Known YARA gaps: web shells that take input through `filter_input()` or `getallheaders()`, and `include $_GET[...]` file inclusion, are not matched by the generic web shell rule.

# 4. Revision notes

## v1.1 → v1.2 (independent review)

| Area | Change | Basis |
|---|---|---|
| Source caveat | Request shapes marked as derived from pre-disclosure leaked PoCs, not confirmed by the advisories | [14] |
| CVE attribution | Documented the conflict between the PHP advisory and Wiz; rules on the session and disclosure paths tagged with both CVEs | [2][5] |
| Affected SAPIs | Separated the SAPI list from what the advisories validated | [1][2][6] |
| Coverage | Added the advisory's other OOM triggers (new rule P1-18), the uncovered stale-state paths and the interim mitigations | [1][2] |
| Appliances | Added PAN-OS / Panorama affected status | [26][30] |
| Sigma P2-05, P2-07, P1-03 | Fixed bypasses through folded headers, trailing junk, long parameter lists, payloads in part name or progress value, and short tags; P1-03 no longer fires on uploaded file content | Tested against PHP 8.3.6 |
| Sigma P4–P7 | Anchored on web service accounts as well as the worker image (dash forks, cmd.exe intermediates); resolved binary names; added `nobody`, `daemon`, the PHP CLI and IIS app pool identities; new rule P5-19; removed php.exe from Windows parents | Review findings F3, F4, F18–F20, F33 |
| Sigma P1-04 | Correlation now emits the base rule (`generate: true`) | Sigma specification |
| Sigma regexes | All regexes RE2-compatible; backtracking guard added | RE2 limits |
| YARA | Fixed false positives on `$pdo->exec($_POST…)` and CLI `exec($_SERVER…)`; added two-stage, variable-function, `urldecode` and short-tag coverage; gadgets in field name, key, `C:` objects and after quotes; session-file and cPanel/FilesMatch persistence; renamed the generic web shell rule | Review findings F15–F17, F34 |
| XQL | Account anchoring, create/write sub-type filter, `(?i)` on regexes, outgoing-only network filter | Review findings F3, F4, F18, F21 |
| Conversions | Removed auto-generated Cortex conversions (wrong direction mapping); kept Splunk conversions | Review finding F22 |
| ATT&CK | Data sources replaced by v20 data components; T1005 replaced by T1212; T1083 and T1499.004 removed; table aligned with rule tags | ATT&CK v20 STIX |
| Text | YARA command fixed (one target per run); session-sweep limits; AWS quote; crontab setgid/setuid; reference titles; citation for upload-progress default | Review findings F13, F14, F20, F27, F28, F30 |
| Tests | Shipped `tests/test_sigma_regex.py` and `tests/test_yara.py` | — |

## v1.0 → v1.1

| Area | Change | Basis |
|---|---|---|
| Fixed versions | Added fixed releases and the end-of-support note for 8.1 and older | [1][2][8][17] |
| IOCs | Added the six source IPs published by Amazon (v1.0 stated none were published) | [9] |
| Request indicators | rawkey variant works through urlencoded bodies too; ~1 MiB field name; ~450-byte upload-progress bodies. Size-only thresholds (v1.0 Query 1, >8 MB) miss both | [14] |
| ATT&CK | Removed T1055 (Process Injection) and T1041 (Exfiltration Over C2); Procedure 7 retitled from "Lateral Movement" to "Command and Control" | ATT&CK v20 |
| Detection name | `Hacktool.Php2shell` (v1.0 read `Hacktool.Php2shell.1`) | [6] |
| Queries | v1.0 Queries 1–3 used HTTP fields not present in `xdr_data`; Query 4 excluded `php-fpm` as writer; Query 5 read the parent field as the child; Queries 4 and 6 used `file_path` instead of `action_file_path`; Query 7 excluded port 443 and internal ranges and had a broken private-range regex | Section 3.3 |
| Sources | Added direct links; replaced two unlocatable sources; removed two unrelated sources (Node.js Brotli, GitLab) | References |

# References

Sources 10, 11, 15, 20–24 and 27 are not cited inline; they are retained from the v1.0 source list as further reading.

1. PHP security advisory GHSA-w8hw-w9fx-j79w — RCE via OOM corruption (CVE-2026-109618) — <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
2. PHP security advisory GHSA-6wmf-4rv5-p3rp — RCE via stale global state (CVE-2026-109619) — <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
3. The PHP Foundation — Today's PHP security release and how we're strengthening PHP security — <https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/>
4. PHP2Shell research site (Wiz Research, OpenAI Codex Security, Calif) — <https://www.php2shell.com/>
5. Wiz Research — PHP2Shell: AI uncovers critical RCE vulnerabilities affecting 70% of the Internet — <https://www.wiz.io/blog/php2shell-php-rce>
6. Symantec — PHP2Shell: Two Critical PHP Flaws Allow Unauthenticated Remote Code Execution — <https://www.security.com/blog-post/php2shell-critical-vulns-cve-2026-109618-109619>
7. Daily CyberSecurity — PHP2Shell Exploited in the Wild as PoC Exploits and Full Details Go Public — <https://securityonline.info/php2shell-exploited-poc-public/>
8. AWS Security Blog — Using AWS WAF to apply mitigations for PHP2Shell RCE vulnerabilities (CVE-2026-109618 and CVE-2026-109619) — <https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/>
9. AWS Security Blog — Amazon Threat Intelligence identifies PHP2Shell exploitation prior to public disclosure in MadPot — <https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/>
10. Mend.io — PHP2Shell: the fix is a runtime upgrade, not a code change — <https://www.mend.io/blog/php2shell-php-rce-cve-2026-109618/>
11. GuidePoint Security — Keep Calm, and Patch PHP2Shell (via Security Boulevard) — <https://securityboulevard.com/2026/10/keep-calm-and-patch-php2shell/>
12. Arctic Wolf Labs — Finding, Prioritizing, and Patching PHP2Shell Exposure — <https://arcticwolf.com/resources/blog/arctic-wolf-labs-finding-prioritizing-and-patching-php2shell-exposure/>
13. Imperva — PHP2Shell: When PHP Runs Out of Memory at the Wrong Moment — <https://www.imperva.com/blog/php2shell-vulnerability-updates/>
14. Abstract Security (ASTRO) — PHP2Shell: Critical PHP RCE Vulnerabilities CVE-2026-109618 and CVE-2026-109619 — <https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619>
15. FortiGuard Labs — Threat Signal: PHP2Shell Remote Code Execution Vulnerabilities — <https://www.fortiguard.com/threat-signal-report/6551/php2shell-remote-code-execution-vulnerabilities>
16. FortiGuard PSIRT — FG-IR-26-186: PHP core RCE vulnerability patches — <https://fortiguard.fortinet.com/psirt/FG-IR-26-186>
17. Canadian Centre for Cyber Security — AL26-026: Critical vulnerabilities impacting PHP — <https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619>
18. SecurityBrief Australia — Palo Alto warns on 22 million exposed PHP instances — <https://securitybrief.com.au/story/palo-alto-warns-on-22-million-exposed-php-instances>
19. Unit 42 — Threat Brief: Critical Vulnerabilities in PHP: CVE-2026-109618, CVE-2026-109619 — <https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/>
20. Recorded Future — PHP2Shell Exploitation: Two Critical PHP Flaws Explained — <https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation>
21. Australian Cyber Security Magazine — Critical PHP vulnerabilities allow remote execution — <https://australiancybersecuritymagazine.com.au/acsc-warns-of-critical-php-vulnerabilities/>
22. HKCERT — PHP Multiple Vulnerabilities — <https://www.hkcert.org/security-bulletin/php-multiple-vulnerabilities_20261022>
23. oss-security — Re: CVE-2026-109619: PHP 8.2–8.5 RCE via stale global state — <https://www.openwall.com/lists/oss-security/2026/10/21/16>
24. Akamai — Critical Remote Code Execution Vulnerabilities in PHP Core — <https://www.akamai.com/blog/security-research/critical-remote-code-execution-vulnerabilities-php-core>
25. JFrog Security Research — PHP2Shell: All You Need to Know About CVE-2026-109618 and CVE-2026-109619 — <https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/>
26. Help Net Security — What the PHP2Shell vulnerability means for Fortinet, Cisco and Palo Alto customers — <https://www.helpnetsecurity.com/2026/10/22/php2shell-vulnerability-fortinet-cisco-palo-alto-networks/>
27. PHP Manual — Session Upload Progress — <https://www.php.net/manual/en/session.upload-progress.php>
28. PHP Manual — .user.ini files — <https://www.php.net/manual/en/configuration.file.per-user.php>
29. PHP Manual — Session runtime configuration (session.upload_progress.enabled: "Defaults to 1, enabled") — <https://www.php.net/manual/en/session.configuration.php>
30. Palo Alto Networks security advisory — CVE-2026-109618 (as linked from [26]) — <https://security.paloaltonetworks.com/CVE-2026-109618>

# Appendix A — Sigma rules

Copy from `detections/sigma/` for deployment. Licensed under the Detection Rule License (DRL) 1.1.

## Procedure 1 — OOM corruption

### P1-00 — `P1-00_php2shell_amazon_madpot_source_ips.yml`

```yaml
title: PHP2Shell - Web Requests From Source IPs Reported in Amazon MadPot Telemetry
id: 6cf57e83-f704-4e5e-be76-925d5cd9bfee
status: experimental
description: |
    Matches web or proxy traffic from the six source IPs Amazon Threat Intelligence tied to PHP2Shell exploitation
    attempts in MadPot honeypot telemetry (first seen 2026-10-17, before public disclosure; the rest on 2026-10-21).
    Amazon states these addresses include shared anonymization infrastructure that is not exclusive to this activity,
    and advises investigating matches rather than blocking. Use the hit to scope the time window, then pivot to
    P1-01/P1-02 errors and P5/P6 host rules on the targeted server.
references:
    - https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/
author: Saied (@saiedatef)
date: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: webserver
detection:
    selection:
        c-ip:
            - '103.216.220.92'
            - '31.223.184.166'
            - '37.19.200.5'
            - '134.209.159.64'
            - '103.114.163.188'
            - '95.217.98.37'
    condition: selection
falsepositives:
    - Unrelated users of the same shared anonymization (VPN/proxy) infrastructure
level: medium
```

### P1-01 — `P1-01_php2shell_php_oom_unknown_script.yml`

```yaml
title: PHP2Shell - PHP Memory Exhaustion Outside Script Context
id: 647bc736-857f-4b52-9045-15dfe39ded8b
status: experimental
description: |
    Detects PHP memory-exhaustion fatal errors that the engine could not attribute to any script ("in Unknown on line 0").
    The allocation failed during request start-up, before application code ran. That is the window abused by
    CVE-2026-109618 (OOM corruption) and the OOM trigger used to leave stale state behind for CVE-2026-109619.
    Ordinary application OOM errors name the script and line, so this pattern is rare in normal operation.
references:
    - https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
    - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
author: Saied (@saiedatef)
date: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    product: php
    service: error
    definition: 'Requirements: log_errors=On and PHP errors collected from Apache error.log (mod_php), nginx error.log ("FastCGI sent in stderr"), the php-fpm pool log, or the file set in error_log'
detection:
    keywords:
        '|all':
            - 'tried to allocate'
            - 'in Unknown on line 0'
    condition: keywords
falsepositives:
    - Legitimate request bodies that exhaust memory_limit during POST parsing (uploads close to post_max_size). Review the request that preceded the error.
level: high
```

### P1-02 — `P1-02_php2shell_php_worker_crash.yml`

```yaml
title: PHP2Shell - PHP Worker Crash or Abnormal Exit
id: 1ebfb427-fa49-4d80-a835-5a36e86561db
status: experimental
description: |
    Detects Apache (mod_php) child processes terminating on SIGSEGV or SIGABRT, and php-fpm workers exiting on
    signal 11/6 or with exit code 255. Both PHP2Shell advisories describe use-after-free and uninitialized-memory
    conditions that crash workers when exploitation fails, and the FPM child is terminated when request startup fails.
    The specific crash strings are the author's guidance from standard Apache and php-fpm log formats, not quotes from
    the advisories. A burst from one host shortly after oversized or multipart POSTs is the pattern to hunt.
references:
    - https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
    - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
    - https://www.imperva.com/blog/php2shell-vulnerability-updates/
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    product: php
    service: error
    definition: 'Requirements: Apache error.log (AH00052 child exit messages) and the php-fpm master log collected'
detection:
    keywords:
        - 'exit signal Segmentation fault'
        - 'exit signal Aborted'
        - 'exited on signal 11'
        - 'exited on signal 6'
        - 'exited with code 255'
    condition: keywords
falsepositives:
    - Buggy or mismatched PHP extensions, OPcache/JIT defects and memory pressure. A single crash is weak evidence; a burst that follows oversized or multipart POSTs is not.
    - php-fpm children exiting with code 255 after unrelated fatal startup errors (bad ini values, missing extensions)
level: medium
```

### P1-03 — `P1-03_php2shell_rawkey_oversized_field_name.yml`

```yaml
title: PHP2Shell - Oversized Form Field Name in POST Body (CVE-2026-109618)
id: 950797a7-103b-406a-b1bd-9776958f94ef
status: experimental
description: |
    Detects a form field NAME of 1,000 bytes or more in a urlencoded body or in a multipart part header. The
    CVE-2026-109618 "rawkey" variant forces memory exhaustion while PHP copies an enormous field name during POST
    parsing. No legitimate client sends a field name anywhere near 1 KB. The multipart pattern only inspects
    Content-Disposition headers (including folded continuation lines, which PHP joins), so long lines in uploaded
    file content do not match. Logic follows the ASTRO ModSecurity rules 3101004, 3101005 and 3101007.
    Request shapes come from public analysis of pre-disclosure PoCs (Abstract Security, 21 Oct 2026) and are not
    confirmed by the PHP advisory. Gating on Content-Length is avoided: chunked and HTTP/2 requests do not need one.
references:
    - https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - detection.emerging-threats
logsource:
    category: webserver
    definition: 'Requirements: full request body capture (ModSecurity audit log part C, WAF full-request logging or NDR HTTP body extraction). Map request_body and request_content_type to your schema. Cloud WAFs only inspect the first 8-128 KB of a body.'
detection:
    selection_urlencoded_type:
        request_content_type|startswith: 'application/x-www-form-urlencoded'
    selection_urlencoded_body:
        request_body|re: '(?:^|&)[^&=]{1000,}'
    selection_multipart_type:
        request_content_type|startswith: 'multipart/form-data'
    selection_multipart_body:
        request_body|re|i: '(?:^|\n)[ \t]*Content-Disposition[ \t]*:(?:[^\r\n]|\r?\n[ \t])*?\bname[ \t]*=[ \t]*(?:"(?:\\"|[^"\r\n]|\r?\n[ \t]){1000,}|''(?:[^''\r\n]|\r?\n[ \t]){1000,}|[^\s;"'']{1000,})'
    condition: (selection_urlencoded_type and selection_urlencoded_body) or (selection_multipart_type and selection_multipart_body)
falsepositives:
    - Clients that send a long JSON or XML document with the default urlencoded content type (for example curl -d without -H). The body then has no "&" or "=" and looks like one huge key.
    - A short part name followed by a filename longer than 1,000 characters. Rare and suspicious in its own right.
level: high
```

### P1-04 — `P1-04_php2shell_oversized_post_burst.yml`

```yaml
title: PHP2Shell - Oversized POST Request to Web Server
id: 42f03a2b-ef76-48ad-82e0-ee3e4776105d
name: php2shell_oversized_post
status: experimental
description: |
    Base rule for the burst correlation below. Flags POST requests with a body of 1,000,000 bytes or more. On its own
    this is a hunting signal, not an alert: the CVE-2026-109618 urlencoded "rawkey" variant needs roughly 1 MiB of
    field name, so exploit attempts of that variant are caught together with legitimate large uploads. The 1 MiB
    figure comes from public analysis of pre-disclosure PoCs (Abstract Security) and is not confirmed by the advisory.
references:
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
    - https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - detection.emerging-threats
logsource:
    category: webserver
    definition: 'Requirements: request size logged as cs-bytes (Apache %I via mod_logio, nginx $request_length, IIS cs-bytes, ALB received_bytes)'
detection:
    selection:
        cs-method: 'POST'
        cs-bytes|gte: 1000000
    condition: selection
falsepositives:
    - Legitimate file uploads and large form or API submissions
level: low
---
title: PHP2Shell - Burst of Oversized POST Requests From One Source
id: 18b7117a-7ca1-4643-adb9-e5d0e59ecb63
status: experimental
description: |
    Ten or more POST requests of 1 MB or larger from one client IP within 10 minutes. Public analysis of the
    CVE-2026-109618 PoC (Abstract Security, pre-disclosure) describes an ASLR brute-force phase of about 590 oversized
    requests over roughly 15 minutes from a single source. Correlate hits with P1-01 and P1-02 on the target host.
    Behind a CDN or load balancer, group by the logged X-Forwarded-For client address instead of c-ip.
references:
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - detection.emerging-threats
correlation:
    type: event_count
    rules:
        - php2shell_oversized_post
    group-by:
        - c-ip
    timespan: 10m
    condition:
        gte: 10
    generate: true
falsepositives:
    - Bulk upload clients, backup or sync agents and media pipelines posting to PHP applications. Allow-list them by source.
level: high
```

### P1-18 — `P1-18_php2shell_multipart_structural_oom_trigger.yml`

```yaml
title: PHP2Shell - Structural Out-of-Memory Trigger in POST Body (CVE-2026-109618)
id: 3b0c6e2a-5f4d-4a7e-9c1b-8d2e6f0a4c71
status: experimental
description: |
    Detects three request-body structures the CVE-2026-109618 advisory lists as ways to force out-of-memory during
    request parsing, beyond the oversized field name covered by P1-03:
      - a multipart part with 50 or more headers ("A multipart part can contain an unrestricted number of headers")
      - a run of 50 or more empty file controls ("Empty file controls do not count towards max_file_uploads")
      - a field name nested 16 or more levels deep ("Nested field names multiply the generated array work")
    Thresholds are the author's judgment: browsers send two or three headers per part, a handful of empty file inputs
    and rarely more than five nesting levels. The empty-file check only counts consecutive empty parts, so an attacker
    interleaving other fields evades it; ModSecurity MULTIPART_STRICT_ERROR / REQBODY_ERROR and frontend limits on
    parts and headers per part close that gap better.
references:
    - https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
author: Saied (@saiedatef)
date: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - detection.emerging-threats
logsource:
    category: webserver
    definition: 'Requirements: full request body capture (ModSecurity audit log part C, WAF full-request logging or NDR HTTP body extraction). Map request_body and request_content_type to your schema.'
detection:
    selection_multipart_type:
        request_content_type|startswith: 'multipart/form-data'
    selection_many_part_headers:
        request_body|re: '(?:^|\n)--[^\r\n]+\r?\n(?:[A-Za-z0-9-]+[ \t]*:[^\r\n]*\r?\n){50,}'
    selection_empty_file_controls:
        request_body|re|i: '(?:Content-Disposition[ \t]*:[^\r\n]*filename[ \t]*=[ \t]*""[^\r\n]*\r?\n(?:[A-Za-z0-9-]+[ \t]*:[^\r\n]*\r?\n){0,10}\r?\n\r?\n--[^\r\n]+\r?\n){50,}'
    selection_deep_nesting:
        request_body|re|i: '(?:(?:\[|%5b)[^&=\r\n\]%]*(?:\]|%5d)){16,}'
    condition: (selection_multipart_type and (selection_many_part_headers or selection_empty_file_controls)) or selection_deep_nesting
falsepositives:
    - Generated forms with deeply nested array inputs (some e-commerce and form-builder plugins)
    - Bulk-upload widgets that submit many empty file inputs
level: high
```

## Procedure 2 — Stale global state

### P2-05 — `P2-05_php2shell_phpsessid_multipart_form_field.yml`

```yaml
title: PHP2Shell - Session ID Supplied as Multipart Form Field
id: d3f9df31-109d-489e-b918-de67ed57e988
status: experimental
description: |
    Detects a multipart POST that carries PHPSESSID as a form field. During upload-progress tracking PHP copies that
    value into the session ID even when session.use_only_cookies is on, so the attacker chooses which session file is
    written. Session upload progress is a confirmed path in the stale-global-state advisory. Modern clients send the
    session ID in the Cookie header; only legacy Flash-era uploaders (SWFUpload, Uploadify) posted it as a field.
    The pattern tolerates folded headers, any quoting, trailing junk after the name and long parameter lists, all of
    which PHP still accepts. Covers the default session.name only; add your custom session name if you changed it.
    Request shapes come from public analysis of pre-disclosure PoCs (Abstract Security, 21 Oct 2026). Sources differ
    on CVE attribution for the upload-progress path (PHP advisory: CVE-2026-109619; Wiz: CVE-2026-109618), so both
    CVEs are tagged.
references:
    - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
    - https://www.wiz.io/blog/php2shell-php-rce
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
    - https://www.php.net/manual/en/session.configuration.php
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: webserver
    definition: 'Requirements: full request body capture (ModSecurity audit log part C, WAF full-request logging or NDR HTTP body extraction). Map request_body and request_content_type to your schema.'
detection:
    selection_method:
        cs-method: 'POST'
    selection_type:
        request_content_type|startswith: 'multipart/form-data'
    selection_field:
        request_body|re|i: '(?:^|\n)[ \t]*Content-Disposition[ \t]*:(?:[^\r\n]|\r?\n[ \t])*?\bname[ \t]*=[ \t]*["'']?PHPSESSID(?:["''\s;]|$)'
    condition: all of selection_*
falsepositives:
    - Legacy Flash-era upload widgets (SWFUpload, Uploadify) that post the session ID as a form field
level: high
```

### P2-06 — `P2-06_php2shell_upload_progress_with_session.yml`

```yaml
title: PHP2Shell - Session Upload Progress Field With Session Identifier
id: 72f8afa4-0371-4790-ba3a-9bc0b35423f5
status: experimental
description: |
    Detects the request shape targeted by the AWS WAF "PHP2Shell" rule: a POST whose body contains
    PHP_SESSION_UPLOAD_PROGRESS while a PHPSESSID is present in the Cookie header or the body. Session upload progress
    is enabled by default and is a confirmed path in the stale-global-state advisory. Lower confidence than P2-05
    because legitimate upload progress bars send the same field; treat hits as hunt leads and pivot to P1-01/P1-02
    errors on the same host. Sources differ on CVE attribution for this path (PHP advisory: CVE-2026-109619;
    Wiz: CVE-2026-109618), so both CVEs are tagged.
references:
    - https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/
    - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
    - https://www.php.net/manual/en/session.configuration.php
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: webserver
    definition: 'Requirements: full request body capture plus the Cookie request header. Map request_body to your schema.'
detection:
    selection_method:
        cs-method: 'POST'
    selection_progress:
        request_body|contains: 'PHP_SESSION_UPLOAD_PROGRESS'
    selection_sid_cookie:
        cs-cookie|contains: 'PHPSESSID'
    selection_sid_body:
        request_body|contains: 'PHPSESSID'
    condition: selection_method and selection_progress and 1 of selection_sid_*
falsepositives:
    - Applications that implement upload progress bars through session.upload_progress
level: medium
```

### P2-07 — `P2-07_php2shell_multipart_filename_payload.yml`

```yaml
title: PHP2Shell - PHP Code or Serialized Object Written to Session via Upload Progress
id: 42dc20cc-257b-4e12-a107-9b2459e67c2c
status: experimental
description: |
    Detects multipart uploads that would plant PHP code or a serialized object in the PHP session file through
    upload-progress tracking. PHP stores three client-controlled strings raw in the session: the part name
    (field_name), the filename (name) and the PHP_SESSION_UPLOAD_PROGRESS value (part of the session key); php.net
    warns these "are not validated". The rule flags:
      - a PHP open tag (<?php, <?= or <? followed by whitespace) or an object (O: / C:) in any Content-Disposition
        header, including folded headers, which covers both field_name and filename
      - the same payloads in the value of the PHP_SESSION_UPLOAD_PROGRESS field
    A planted tag is executed by a later local file inclusion of the session file; a planted object is decoded under a
    mismatched serialize handler. Part content is not inspected, so uploaded PHP or XML files do not match.
    Request shapes come from public analysis of pre-disclosure PoCs (Abstract Security, 21 Oct 2026).
references:
    - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
    - https://www.php.net/manual/en/session.configuration.php
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: webserver
    definition: 'Requirements: full request body capture (ModSecurity audit log part C, WAF full-request logging or NDR HTTP body extraction). Map request_body and request_content_type to your schema.'
detection:
    selection_type:
        request_content_type|startswith: 'multipart/form-data'
    selection_header_payload:
        request_body|re|i: '(?:^|\n)[ \t]*Content-Disposition[ \t]*:(?:[^\r\n]|\r?\n[ \t])*?(?:<\?(?:php\b|=|\s)|\|\s*[oc]\s*:\s*\d{1,10}\s*:|\b[oc]\s*:\s*\d{1,10}\s*:\s*\\?["''])'
    selection_progress_payload:
        request_body|re|i: '\bname[ \t]*=[ \t]*["'']?PHP_SESSION_UPLOAD_PROGRESS["'']?[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n[^\r\n]*(?:<\?|\|\s*[oc]\s*:\s*\d)'
    condition: selection_type and (selection_header_payload or selection_progress_payload)
falsepositives:
    - Filenames that contain text such as o:1:" (very rare)
level: high
```

## Procedure 3 — Memory disclosure

### P3-08 — `P3-08_php2shell_oversized_phpsessid_response_cookie.yml`

```yaml
title: PHP2Shell - Oversized PHPSESSID in Set-Cookie Response (Memory Disclosure)
id: 35f97849-2911-4420-a527-d2ee4b24af43
status: experimental
description: |
    Detects a Set-Cookie response header whose PHPSESSID value is 512 characters or longer. In the stale session-ID
    disclosure path, attacker-influenced memory is read as a string with an oversized length and returned through
    Set-Cookie: PHPSESSID, leaking roughly 67 KB of worker memory per response (Imperva). PHP-generated IDs are
    32 characters by default and session.sid_length never exceeded 256, so 512+ leaves a wide margin. A hit means
    process memory (credentials, tokens, keys, other users' request data) left the server: treat it as data exposure.
    Untested lead: a header this large can exceed nginx's default proxy buffer and produce "upstream sent too big
    header" errors instead of a logged cookie. Sources differ on CVE attribution (PHP advisory: CVE-2026-109619;
    Wiz: CVE-2026-109618), so both CVEs are tagged.
references:
    - https://www.imperva.com/blog/php2shell-vulnerability-updates/
    - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
    - https://www.wiz.io/blog/php2shell-php-rce
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.credential-access
    - attack.t1212
    - attack.initial-access
    - attack.t1190
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: proxy
    definition: 'Requirements: response header logging on a reverse proxy, load balancer, WAF or NDR sensor in front of PHP. Map response_set_cookie to the logged Set-Cookie value(s).'
detection:
    selection:
        response_set_cookie|re|i: 'PHPSESSID=[^;\r\n]{512,}'
    condition: selection
falsepositives:
    - None expected with the default session handler. Custom session ID generators that emit very long IDs.
level: critical
```

## Procedure 4 — Web shell deployment

### P4-09 — `P4-09_php2shell_php_file_written_to_upload_dir.yml`

```yaml
title: PHP2Shell - PHP Script Written to Upload or Temp Directory by Web Worker or Web Account
id: 9941eaa3-d791-40a8-9b8d-b17daf49f225
status: experimental
description: |
    Detects an executable PHP file written into an upload, media or temp directory by a PHP web worker (php-fpm,
    php-cgi, LiteSpeed, FrankenPHP, Apache mod_php) or by any process running as a web service account. After RCE a
    web shell is often dropped by a child process (sh, wget -O, curl -o) rather than by the worker itself, so the
    rule anchors on the account as well as the worker image. This is the web shell drop that typically follows
    PHP2Shell exploitation. Add per-site PHP-FPM pool users (cPanel, Plesk) to the account list.
references:
    - https://www.php2shell.com/
    - https://www.security.com/blog-post/php2shell-critical-vulns-cve-2026-109618-109619
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.persistence
    - attack.t1505.003
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: file_event
    definition: 'Requirements: Sysmon EID 11 (Windows or Linux), auditd, or EDR file-creation telemetry on web servers, including the writing user'
detection:
    selection_writer_image:
        - Image|re: '/(?:php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp[0-9.]*|frankenphp|apache2|httpd)$'
        - Image|endswith:
              - '\php-cgi.exe'
              - '\httpd.exe'
    selection_writer_user:
        - User:
              - 'www-data'
              - 'apache'
              - 'nginx'
              - 'wwwrun'
              - 'http'
              - 'nobody'
              - 'daemon'
        - User|startswith: 'IIS APPPOOL\'
    selection_ext:
        TargetFilename|endswith:
            - '.php'
            - '.phtml'
            - '.phar'
            - '.php5'
            - '.php7'
            - '.pht'
    selection_path:
        TargetFilename|contains:
            - '/uploads/'
            - '/sites/default/files/'
            - '/images/'
            - '/media/'
            - '/tmp/'
            - '/dev/shm/'
            - '\uploads\'
            - '\images\'
            - '\Temp\'
    condition: 1 of selection_writer_* and selection_ext and selection_path
falsepositives:
    - Plugins that cache generated PHP into upload folders (some page-cache and form builders). Baseline per site.
level: high
```

### P4-10 — `P4-10_php2shell_php_file_written_to_webroot_hunt.yml`

```yaml
title: PHP2Shell - PHP Script Written Anywhere Under Web Root by Web Worker or Web Account (Hunt)
id: ab40e47c-6c8c-4f4e-b3fd-d3821041d41f
status: experimental
description: |
    Hunting companion to P4-09. Returns every PHP file created under common web roots, including plugin and
    mu-plugins folders, by a PHP web worker or by any process running as a web service account. Expect volume from
    CMS core, plugin and theme updates; stack by file path and time, and investigate files that appear outside an
    update window or between 2026-10-17 (earliest observed exploitation attempt) and your patch date.
references:
    - https://www.php2shell.com/
    - https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.persistence
    - attack.t1505.003
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: file_event
    definition: 'Requirements: Sysmon EID 11 (Windows or Linux), auditd, or EDR file-creation telemetry on web servers, including the writing user'
detection:
    selection_writer_image:
        - Image|re: '/(?:php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp[0-9.]*|frankenphp|apache2|httpd)$'
        - Image|endswith:
              - '\php-cgi.exe'
              - '\httpd.exe'
    selection_writer_user:
        - User:
              - 'www-data'
              - 'apache'
              - 'nginx'
              - 'wwwrun'
              - 'http'
              - 'nobody'
              - 'daemon'
        - User|startswith: 'IIS APPPOOL\'
    selection_ext:
        TargetFilename|endswith:
            - '.php'
            - '.phtml'
            - '.phar'
            - '.php5'
            - '.php7'
            - '.pht'
    selection_path:
        TargetFilename|contains:
            - '/var/www/'
            - '/srv/www/'
            - '/public_html/'
            - '/htdocs/'
            - '/mu-plugins/'
            - '\inetpub\'
            - '\xampp\htdocs\'
            - '\wamp64\www\'
    condition: 1 of selection_writer_* and selection_ext and selection_path
falsepositives:
    - CMS core, plugin and theme auto-updates performed by the web worker or web account
level: low
```

## Procedure 5 — Suspicious child process

### P5-11 — `P5-11_php2shell_lnx_web_worker_suspicious_child.yml`

```yaml
title: PHP2Shell - Suspicious Child Process of PHP Web Worker (Linux)
id: fa1d84c9-219c-4060-8f54-e6f781ea1a90
status: experimental
description: |
    Detects post-exploitation execution directly under a PHP worker on Linux: download and network tools or
    interpreters started by the worker, or a shell started by the worker with reverse-shell, decoding, download or
    staging content on the command line. Arctic Wolf reported wget pulling ELF and Golang commodity malware after
    exploitation. PHP exec(), system() and shell_exec() always run through /bin/sh -c, so a bare shell child is
    normal for many apps and needs a suspicious command line here. On Debian/Ubuntu /bin/sh is dash, which forks
    instead of exec-ing, so tools often appear with sh as parent: P5-19 covers that by anchoring on the web account.
    Image names are matched as resolved binaries (python3.13, nc.openbsd).
references:
    - https://arcticwolf.com/resources/blog/arctic-wolf-labs-finding-prioritizing-and-patching-php2shell-exposure/
    - https://www.security.com/blog-post/php2shell-critical-vulns-cve-2026-109618-109619
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.execution
    - attack.t1059.004
    - attack.t1059.006
    - attack.discovery
    - attack.t1033
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|re: '/(?:php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp[0-9.]*|frankenphp|apache2|httpd)$'
    selection_tools:
        Image|re: '/(?:curl|wget|nc(?:\.openbsd|\.traditional)?|ncat|netcat|socat|whoami|id|uname|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|gawk|openssl)$'
    selection_shell:
        Image|re: '/(?:sh|bash|dash|zsh|ksh)$'
    selection_shell_cli:
        CommandLine|contains:
            - '/dev/tcp/'
            - '/dev/udp/'
            - 'mkfifo'
            - 'base64 -d'
            - 'base64 --decode'
            - 'curl '
            - 'wget '
            - '/dev/shm/'
            - '/var/tmp/'
            - 'cd /tmp'
            - 'chmod +x'
            - 'chmod 777'
            - 'whoami'
            - 'uname -a'
            - ' nc '
            - 'nc -e'
            - ' ncat '
            - ' socat '
            - 'busybox '
            - 'python -c'
            - 'python3 -c'
            - 'perl -e'
            - 'sh -i'
            - 'bash -i'
            - 'authorized_keys'
            - 'crontab'
            - 'fsockopen'
    condition: selection_parent and (selection_tools or (selection_shell and selection_shell_cli))
falsepositives:
    - Applications that legitimately call curl, wget or Python helpers from PHP (image processing, PDF generation, update checks). Baseline per host and allow-list exact command lines.
level: high
```

### P5-12 — `P5-12_php2shell_win_web_worker_suspicious_child.yml`

```yaml
title: PHP2Shell - Suspicious Child Process of PHP Web Worker (Windows)
id: 25b79205-1e70-4f99-a842-6570948aa399
status: experimental
description: |
    Detects post-exploitation execution under PHP on Windows: LOLBins and scripting hosts started by php-cgi.exe
    (IIS FastCGI) or Apache httpd.exe with mod_php, or cmd.exe with reconnaissance, download or reverse-shell content.
    PHP on Windows runs exec() through cmd.exe /c, so cmd.exe alone is not treated as suspicious, and tools usually
    appear with cmd.exe as parent; the IIS application pool identity branch catches those for PHP under IIS.
    php.exe (CLI) is excluded to avoid developer and CI hosts. w3wp.exe children are left to existing SigmaHQ rules.
references:
    - https://www.security.com/blog-post/php2shell-critical-vulns-cve-2026-109618-109619
    - https://www.php2shell.com/
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
    - attack.stealth
    - attack.t1218
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\php-cgi.exe'
            - '\httpd.exe'
    selection_iis_identity:
        User|startswith: 'IIS APPPOOL\'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\certutil.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\bitsadmin.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
            - '\whoami.exe'
            - '\schtasks.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\nltest.exe'
            - '\curl.exe'
            - '\nc.exe'
            - '\nc64.exe'
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_cmd_cli:
        CommandLine|contains:
            - 'whoami'
            - 'certutil'
            - 'powershell'
            - 'bitsadmin'
            - 'mshta'
            - 'rundll32'
            - 'regsvr32'
            - 'cscript'
            - 'nltest'
            - 'net user'
            - 'net localgroup'
            - 'Net.WebClient'
            - 'DownloadString'
            - 'FromBase64String'
            - 'Sockets.TcpClient'
            - 'schtasks'
            - 'nc.exe'
            - 'curl '
            - 'Invoke-WebRequest'
    condition: (selection_parent and (selection_child or (selection_cmd and selection_cmd_cli))) or (selection_iis_identity and selection_child)
falsepositives:
    - PHP applications that shell out to PowerShell or curl.exe by design. Allow-list exact command lines per server.
    - Other IIS applications in the same environment running LOLBins under their application pool identity
level: high
```

### P5-19 — `P5-19_php2shell_lnx_web_account_tool_execution.yml`

```yaml
title: PHP2Shell - Download, Network or Interpreter Tool Run as Web Service Account (Linux)
id: 8e4a1f6d-2c7b-4b39-a5d0-61f9c3e7b2a4
status: experimental
description: |
    Companion to P5-11. Detects download, network and interpreter tools run as a web service account regardless of
    the parent process. PHP exec() goes through /bin/sh -c, and on Debian/Ubuntu dash forks before running the
    command, so post-exploitation tools usually show sh, not php-fpm, as their parent; anchoring on the account
    catches them. Image names are matched as resolved binaries (python3.13, nc.openbsd). Add per-site PHP-FPM pool
    users (cPanel, Plesk) to the account list.
references:
    - https://arcticwolf.com/resources/blog/arctic-wolf-labs-finding-prioritizing-and-patching-php2shell-exposure/
    - https://www.security.com/blog-post/php2shell-critical-vulns-cve-2026-109618-109619
author: Saied (@saiedatef)
date: 2026-10-22
tags:
    - attack.execution
    - attack.t1059.004
    - attack.t1059.006
    - attack.discovery
    - attack.t1033
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_user:
        User:
            - 'www-data'
            - 'apache'
            - 'nginx'
            - 'wwwrun'
            - 'http'
            - 'nobody'
            - 'daemon'
    selection_tools:
        Image|re: '/(?:curl|wget|nc(?:\.openbsd|\.traditional)?|ncat|netcat|socat|whoami|id|uname|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|gawk|openssl)$'
    condition: all of selection_*
falsepositives:
    - WordPress or application cron jobs that run curl or wget as the web account
    - Applications that call Python, Perl or curl helpers by design. Baseline per host and allow-list exact command lines.
level: medium
```

## Procedure 6 — Persistence

### P6-13 — `P6-13_php2shell_lnx_persistence_file_write.yml`

```yaml
title: PHP2Shell - Persistence File Written by PHP Web Worker or Web Account (Linux)
id: 491d9f7b-4014-4f89-9e95-de8a07fd0112
status: experimental
description: |
    Detects a PHP web worker, or any process running as a web service account, writing cron, SSH authorized_keys,
    systemd or Supervisor persistence files. A web service account can usually reach its own home directory
    (for example /var/www/.ssh/authorized_keys) even when /etc is out of reach, so both are covered. Add per-site
    PHP-FPM pool users (cPanel, Plesk) to the account list.
references:
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
    - https://www.php2shell.com/
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.persistence
    - attack.t1053.003
    - attack.t1098.004
    - attack.t1543.002
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
    definition: 'Requirements: Sysmon for Linux EID 11 or auditd watches on /etc/cron*, /var/spool/cron, systemd unit paths and ~/.ssh'
detection:
    selection_writer_image:
        Image|re: '/(?:php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp[0-9.]*|frankenphp|apache2|httpd)$'
    selection_writer_user:
        User:
            - 'www-data'
            - 'apache'
            - 'nginx'
            - 'wwwrun'
            - 'http'
            - 'nobody'
            - 'daemon'
    selection_target:
        - TargetFilename|contains:
              - '/etc/cron'
              - '/var/spool/cron/'
              - '/etc/systemd/system/'
              - '/.config/systemd/user/'
              - '/etc/init.d/'
              - '/etc/supervisor'
        - TargetFilename|endswith: '/.ssh/authorized_keys'
    condition: 1 of selection_writer_* and selection_target
falsepositives:
    - Hosting control panels that manage cron or SSH keys through a PHP front end running as the web account
level: high
```

### P6-14 — `P6-14_php2shell_user_ini_htaccess_write.yml`

```yaml
title: PHP2Shell - .user.ini or .htaccess Written by PHP Web Worker or Web Account
id: 401ef638-d5d9-48e4-89d5-9b1096a1c5aa
status: experimental
description: |
    Detects a PHP web worker, or any process running as a web service account, writing .user.ini or .htaccess.
    Attackers use auto_prepend_file in .user.ini, or php_value / AddHandler directives in .htaccess, to make a
    dropped payload load on every request without touching application files. Content is not visible in file
    telemetry: pull the file and scan it with the YARA rule PHP2Shell_Persistence_UserIni_Htaccess_Prepend.
references:
    - https://www.php.net/manual/en/configuration.file.per-user.php
    - https://www.php2shell.com/
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.persistence
    - attack.t1505.003
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: file_event
    definition: 'Requirements: Sysmon EID 11 (Windows or Linux), auditd, or EDR file-creation telemetry on web servers, including the writing user'
detection:
    selection_writer_image:
        - Image|re: '/(?:php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp[0-9.]*|frankenphp|apache2|httpd)$'
        - Image|endswith:
              - '\php-cgi.exe'
              - '\httpd.exe'
    selection_writer_user:
        - User:
              - 'www-data'
              - 'apache'
              - 'nginx'
              - 'wwwrun'
              - 'http'
              - 'nobody'
              - 'daemon'
        - User|startswith: 'IIS APPPOOL\'
    selection_target:
        TargetFilename|endswith:
            - '/.user.ini'
            - '/.htaccess'
            - '\.user.ini'
            - '\.htaccess'
    condition: 1 of selection_writer_* and selection_target
falsepositives:
    - WordPress permalink updates and security plugins (e.g. web application firewall plugins that set auto_prepend_file) rewrite these files legitimately
level: medium
```

### P6-15 — `P6-15_php2shell_lnx_crontab_by_web_account.yml`

```yaml
title: PHP2Shell - Crontab Modified by Web Service Account (Linux)
id: 478a2a37-83c9-4b9b-a8d6-484fbfc6d906
status: experimental
description: |
    Detects the crontab binary run under a web service account (listing with -l excluded). A web user installing its
    own crontab writes the spool file through the privileged crontab binary (setgid crontab on Debian/Ubuntu, setuid
    root on RHEL), so the file write is attributed to crontab, not to php-fpm, and file-based rules keyed on the PHP
    worker (P6-13) can miss it. Check whether your telemetry records the real or the effective UID for crontab.
references:
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.persistence
    - attack.t1053.003
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_image:
        Image|endswith: '/crontab'
    selection_user:
        User:
            - 'www-data'
            - 'apache'
            - 'nginx'
            - 'wwwrun'
            - 'http'
            - 'nobody'
            - 'daemon'
    filter_list_only:
        CommandLine|endswith: ' -l'
    condition: all of selection_* and not filter_list_only
falsepositives:
    - Applications that install their own scheduled jobs from the web account during setup
level: high
```

## Procedure 7 — Command and control

### P7-16 — `P7-16_php2shell_lnx_web_account_shell_network_connection.yml`

```yaml
title: PHP2Shell - Shell, Netcat or Interpreter Network Connection Under Web Service Account (Linux)
id: ce27d192-4c9a-4f94-b5e1-3f9a89afea09
status: experimental
description: |
    Detects shells, netcat variants, socat, scripting interpreters (including the PHP CLI, as in
    php -r '$s=fsockopen(...)') or openssl opening an outbound network connection while running as a web service
    account. That combination is a reverse shell or an implant check-in. Internal destinations are not filtered, so
    pivots into the internal network are kept; port 443 is not excluded either, because reverse shells commonly use
    it. Image names are matched as resolved binaries (python3.13, nc.openbsd).
references:
    - https://www.security.com/blog-post/php2shell-critical-vulns-cve-2026-109618-109619
    - https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
author: Saied (@saiedatef)
date: 2026-10-22
modified: 2026-10-22
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.t1095
    - attack.execution
    - attack.t1059.004
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: network_connection
    product: linux
    definition: 'Requirements: Sysmon for Linux EID 3 or auditd connect syscall rules scoped to the web service UID'
detection:
    selection:
        Image|re: '/(?:sh|bash|dash|zsh|ksh|nc(?:\.openbsd|\.traditional)?|ncat|netcat|socat|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|gawk|openssl)$'
        User:
            - 'www-data'
            - 'apache'
            - 'nginx'
            - 'wwwrun'
            - 'http'
            - 'nobody'
            - 'daemon'
        Initiated: 'true'
    condition: selection
falsepositives:
    - Python, Perl or PHP CLI helpers and cron jobs run by the application that call external APIs. Allow-list by destination.
level: high
```

### P7-17 — `P7-17_php2shell_php_worker_unusual_egress_hunt.yml`

```yaml
title: PHP2Shell - PHP Worker Outbound Connection on Unusual Port (Hunt)
id: f6128487-7459-4e2f-96ff-6f54c67e9e90
status: experimental
description: |
    Hunting rule for native-code payloads that open a socket from inside the PHP worker without spawning a shell.
    Returns outbound connections from PHP workers to public addresses on ports other than web, mail, DNS and common
    database ports. Port 443 traffic from the worker is not covered here (too much legitimate API traffic); review it
    with destination rarity analysis instead.
references:
    - https://www.php2shell.com/
    - https://www.imperva.com/blog/php2shell-vulnerability-updates/
author: Saied (@saiedatef)
date: 2026-10-22
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.t1571
    - cve.2026-109618
    - cve.2026-109619
    - detection.emerging-threats
logsource:
    category: network_connection
    product: linux
    definition: 'Requirements: Sysmon for Linux EID 3 or EDR network telemetry attributed to the PHP worker process'
detection:
    selection:
        Image|contains:
            - '/php-fpm'
            - '/php-cgi'
            - '/lsphp'
            - '/frankenphp'
            - '/apache2'
            - '/httpd'
        Initiated: 'true'
    filter_private:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '127.0.0.0/8'
            - '169.254.0.0/16'
            - '::1/128'
            - 'fc00::/7'
            - 'fe80::/10'
    filter_ports:
        DestinationPort:
            - 25
            - 53
            - 80
            - 443
            - 465
            - 587
            - 3306
            - 5432
            - 6379
            - 11211
    condition: selection and not 1 of filter_*
falsepositives:
    - Applications calling third-party APIs on non-standard ports, SMTP relays on custom ports, external databases
level: low
```

# Appendix B — YARA rules

File: `detections/yara/php2shell_hunt.yar`. Licensed under the Detection Rule License (DRL) 1.1.

```yara
/*
   PHP2Shell (CVE-2026-109618 / CVE-2026-109619) - YARA hunting rules
   Companion to: PHP2Shell Threat Hunt Report (v1.2, 2026-10-22)

   Scan targets
     - Session files: session.save_path (e.g. /var/lib/php/sessions, /var/lib/php/session, /tmp), files named sess_*
     - Web roots, upload, cache and temp directories (/var/www, uploads, /tmp, /dev/shm)
     - .user.ini and .htaccess files under web roots

   Usage (the yara CLI takes one target per run)
     for d in /var/lib/php/sessions /var/www /tmp /dev/shm; do yara -r -s php2shell_hunt.yar "$d"; done

   Limits of the session-file sweep
     - session.upload_progress.cleanup=On (default) empties the progress data once the POST is fully read; a
       completed exploit request can leave a 0-byte sess_<attacker-chosen-id> file that YARA cannot match.
     - Debian/Ubuntu purge sess_* files older than session.gc_maxlifetime (default 24 min) every 30 min.
     A clean sweep is therefore NOT evidence of no exploitation. Image session directories early during IR.

   License: Detection Rule License (DRL) 1.1
*/

rule PHP2Shell_Session_UploadProgress_PHP_Code
{
    meta:
        description = "PHP session file holding upload-progress data that contains a PHP open tag. PHP stores the client-supplied field name, filename and PHP_SESSION_UPLOAD_PROGRESS value raw in the session; a planted tag is executed by a later local file inclusion of the session file."
        author = "Saied (@saiedatef)"
        date = "2026-10-22"
        modified = "2026-10-22"
        reference1 = "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"
        reference2 = "https://www.php.net/manual/en/session.configuration.php"
        reference3 = "https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619"
        cve = "CVE-2026-109618, CVE-2026-109619 (sources differ on attribution)"
        mitre_attack = "T1190, T1505.003"
        scan_target = "PHP session files (sess_*)"
        score = 80
    strings:
        $k_content_length = "s:14:\"content_length\";" ascii
        $k_bytes          = "s:15:\"bytes_processed\";" ascii
        $k_field          = "s:10:\"field_name\";s:" ascii
        $php_open         = "<?php" ascii nocase
        $php_echo         = "<?=" ascii
        $php_short        = /<\?\s/
    condition:
        filesize < 2MB
        and $k_content_length and $k_bytes and $k_field
        and any of ($php_*)
}

rule PHP2Shell_Session_UploadProgress_Serialized_Gadget
{
    meta:
        description = "PHP session file holding upload-progress data where a serialized string value contains a serialize-handler separator followed by an object (|O:N: or |C:N:). This plants a gadget that is decoded under a mismatched serialize handler. Covers the field name, filename and progress key."
        author = "Saied (@saiedatef)"
        date = "2026-10-22"
        modified = "2026-10-22"
        reference1 = "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"
        reference2 = "https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619"
        cve = "CVE-2026-109618, CVE-2026-109619 (sources differ on attribution)"
        mitre_attack = "T1190"
        scan_target = "PHP session files (sess_*)"
        score = 85
    strings:
        $k_content_length = "s:14:\"content_length\";" ascii
        $gadget_in_string = /s:\d{1,6}:"[^"]{0,4096}\|\s*[OC]:\d{1,6}:"/
        $gadget_in_key    = /upload_progress_[^|"]{0,4096}\|\s*[OC]:\d{1,6}:"/
        $gadget_after_q   = /"\|\s*[OC]:\d{1,6}:"/
    condition:
        filesize < 2MB and $k_content_length and any of ($gadget_*)
}

rule Generic_PHP_Webshell_Request_To_Exec
{
    meta:
        description = "Small PHP file that passes request input into an execution or eval primitive, directly, through one variable assignment, or as a variable function. Generic sweep for web shells dropped after PHP2Shell RCE (Procedure 4); not specific to this vulnerability."
        author = "Saied (@saiedatef)"
        date = "2026-10-22"
        modified = "2026-10-22"
        reference1 = "https://www.security.com/blog-post/php2shell-critical-vulns-cve-2026-109618-109619"
        mitre_attack = "T1505.003"
        scan_target = "Web roots, upload, cache and temp directories"
        score = 70
    strings:
        $open = "<?" ascii
        $direct = /(^|[^>:$a-zA-Z0-9_])(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(base64_decode\s*\(\s*|str_rot13\s*\(\s*|gzinflate\s*\(\s*|urldecode\s*\(\s*|rawurldecode\s*\(\s*|stripslashes\s*\(\s*)*\$_(GET|POST|REQUEST|COOKIE|FILES)\s*[\[{]/ nocase
        $assign = /\$[a-zA-Z_]\w{0,30}\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*;[^;]{0,200}(^|[^>:$a-zA-Z0-9_])(system|shell_exec|passthru|exec|popen|proc_open|eval|assert)\s*\(\s*\$[a-zA-Z_]/ nocase
        $varfunc = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $backtick = /`\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*`/ nocase
        $create_fn = /create_function\s*\([^;]{0,100}\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $preg_e = /preg_replace\s*\(\s*["'][^"']{1,100}\/[a-z]*e[a-z]*["']\s*,\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        filesize < 30KB and $open and any of ($direct, $assign, $varfunc, $backtick, $create_fn, $preg_e)
}

rule PHP2Shell_Persistence_UserIni_Htaccess_Prepend
{
    meta:
        description = ".user.ini or .htaccess that auto-prepends/appends a file from a session, temp or upload location, an image/text file, or a php:// / data: / phar:// wrapper, or that maps image extensions to a PHP handler. Used to load a dropped payload on every request (Procedure 6)."
        author = "Saied (@saiedatef)"
        date = "2026-10-22"
        modified = "2026-10-22"
        reference1 = "https://www.php.net/manual/en/configuration.file.per-user.php"
        mitre_attack = "T1505.003"
        scan_target = ".user.ini and .htaccess files under web roots"
        note = "Security plugins legitimately set auto_prepend_file to a .php file in the web root (for example a WAF bootstrap); those do not match. Appending a .txt footer from a cache folder does match and should be reviewed."
        score = 75
    strings:
        $prepend_bad = /auto_(prepend|append)_file\s*=?\s*["']?\s*(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\/var\/lib\/php\/sessions?\/|php:\/\/|data:|phar:\/\/|[^\n"']{0,200}\/uploads\/|[^\n"']{0,200}\/sess_|[^\n"']{0,200}\.(jpe?g|png|gif|ico|txt|log)["']?[ \t]*(\r?\n|$))/ nocase
        $handler_img = /(AddType|AddHandler|SetHandler)\s+application\/x-httpd-(ea-|alt-)?php[^\n]{0,60}\.(jpe?g|png|gif|ico|txt)/ nocase
        $filesmatch = /<FilesMatch\s+"[^"]{0,80}(jpe?g|png|gif|ico|txt)[^"]{0,20}">\s*SetHandler\s+application\/x-httpd-/ nocase
    condition:
        filesize < 64KB and any of them
}
```

# Appendix C — Cortex XQL hunt queries

Files: `detections/xql/`. Validate field names in your tenant before scheduling.

## Q4 — `Q4_webshell_written_by_php_worker.xql`

```sql
// PHP2Shell - Procedure 4 - PHP script written to an upload, media or temp directory (Linux)
// Cortex XDR / XSIAM, dataset xdr_data. Validate field names and ENUM values in your tenant before scheduling.
// Writer = the PHP worker OR any process running as a web service account (shells are often dropped by sh,
// wget -O or curl -o, not by php-fpm itself). Add per-site PHP-FPM pool users (cPanel, Plesk) to the account list.
// Only create/write events are kept: php-fpm opens every .php file it runs. Add ENUM.FILE_RENAME if your tenant has it.
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.FILE and agent_os_type = ENUM.AGENT_OS_LINUX
| filter (event_sub_type = ENUM.FILE_CREATE_NEW or event_sub_type = ENUM.FILE_WRITE)
| filter (
    actor_process_image_name ~= "(?i)^(php-fpm.*|php-cgi.*|lsphp.*|frankenphp|apache2|httpd)$"
    or actor_effective_username ~= "(?i)(www-data|apache|nginx|wwwrun|http|nobody|daemon)$"
  )
| filter action_file_name ~= "(?i)\.(php|phtml|phar|php5|php7|pht)$"
| filter action_file_path ~= "(?i)/uploads/|/sites/default/files/|/images/|/media/|/tmp/|/dev/shm/"
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, actor_effective_username, action_file_path, action_file_sha256, event_sub_type
| sort desc _time
```

## Q5 — `Q5_suspicious_child_of_php_worker.xql`

```sql
// PHP2Shell - Procedure 5 - Suspicious process under a PHP worker or a web service account (Linux and Windows)
// Cortex XDR / XSIAM, dataset xdr_data. Validate field names and ENUM values in your tenant before scheduling.
// actor_process_* = parent, action_process_* = the new process.
// PHP exec() runs through /bin/sh -c (dash forks first) or cmd.exe /c, so post-exploitation tools usually have
// sh or cmd.exe as parent; the query therefore also anchors on the account running the new process.
// Bare sh / cmd.exe children are excluded on purpose and need a suspicious command line.
// Add per-site PHP-FPM pool users (cPanel, Plesk) to the account regex.
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (
    actor_process_image_name ~= "(?i)^(php-fpm.*|php-cgi.*|lsphp.*|frankenphp|apache2|httpd)$"
    or action_process_username ~= "(?i)(www-data|apache|nginx|wwwrun|http|nobody|daemon)$"
    or action_process_username ~= "(?i)^IIS APPPOOL"
  )
| filter (
    action_process_image_name ~= "(?i)^(curl|wget|nc|nc\.openbsd|nc\.traditional|ncat|netcat|socat|whoami|id|uname|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|gawk|openssl|powershell\.exe|pwsh\.exe|certutil\.exe|cscript\.exe|wscript\.exe|bitsadmin\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|whoami\.exe|schtasks\.exe|net\.exe|net1\.exe|nltest\.exe|curl\.exe|nc\.exe|nc64\.exe)$"
    or (
      action_process_image_name ~= "(?i)^(sh|bash|dash|zsh|ksh|cmd\.exe)$"
      and action_process_image_command_line ~= "(?i)/dev/tcp/|/dev/udp/|mkfifo|base64 -d|base64 --decode|curl |wget |/dev/shm/|/var/tmp/|cd /tmp|chmod \+x|chmod 777|whoami|uname -a| nc |nc -e| ncat | socat |busybox |python3? -c|perl -e|sh -i|bash -i|authorized_keys|crontab|fsockopen|Net\.WebClient|DownloadString|FromBase64String|Sockets\.TcpClient|Invoke-WebRequest|certutil|bitsadmin|mshta|rundll32|regsvr32|nltest"
    )
  )
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, action_process_image_name, action_process_image_command_line, action_process_username
| sort desc _time
```

## Q6 — `Q6_persistence_written_by_web_account.xql`

```sql
// PHP2Shell - Procedure 6 - Persistence files written by a PHP worker or a web service account (Linux)
// Cortex XDR / XSIAM, dataset xdr_data. Validate field names and ENUM values in your tenant before scheduling.
// .user.ini / .htaccess hits need content review (YARA rule PHP2Shell_Persistence_UserIni_Htaccess_Prepend):
// WordPress and security plugins rewrite them legitimately. A crontab installed by the web account is written by
// the privileged crontab binary; hunt that with Sigma P6-15 (process events) as well.
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.FILE and agent_os_type = ENUM.AGENT_OS_LINUX
| filter (event_sub_type = ENUM.FILE_CREATE_NEW or event_sub_type = ENUM.FILE_WRITE)
| filter (
    actor_process_image_name ~= "(?i)^(php-fpm.*|php-cgi.*|lsphp.*|frankenphp|apache2|httpd)$"
    or actor_effective_username ~= "(?i)(www-data|apache|nginx|wwwrun|http|nobody|daemon)$"
  )
| filter action_file_path ~= "(?i)^/etc/cron|^/var/spool/cron/|/\.ssh/authorized_keys$|^/etc/systemd/system/|/\.config/systemd/user/|^/etc/init\.d/|^/etc/supervisor|/\.user\.ini$|/\.htaccess$"
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, actor_effective_username, action_file_path, event_sub_type
| sort desc _time
```

## Q7 — `Q7_reverse_shell_and_worker_egress.xql`

```sql
// PHP2Shell - Procedure 7 - Command and control from the web tier (Linux)
// Cortex XDR / XSIAM, dataset xdr_data. Validate field names and ENUM values in your tenant before scheduling.
// action_network_is_server = false keeps outgoing connections only.

// 7a - Shells, netcat variants, interpreters (including the PHP CLI) and openssl connecting out as a web account.
//      No port or internal-range exclusions: reverse shells use 443, and pivots go to internal hosts.
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK and agent_os_type = ENUM.AGENT_OS_LINUX
| filter action_network_is_server = false
| filter actor_effective_username ~= "(?i)(www-data|apache|nginx|wwwrun|http|nobody|daemon)$"
| filter actor_process_image_name ~= "(?i)^(sh|bash|dash|zsh|ksh|nc|nc\.openbsd|nc\.traditional|ncat|netcat|socat|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|gawk|openssl)$"
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, actor_effective_username, action_remote_ip, action_remote_port
| sort desc _time

// 7b - Hunt: native-code payloads opening sockets from inside the PHP worker on unusual ports.
//      Run as a separate query (remove the leading // on each line).
// config case_sensitive = false
// | dataset = xdr_data
// | filter event_type = ENUM.NETWORK and agent_os_type = ENUM.AGENT_OS_LINUX
// | filter action_network_is_server = false
// | filter actor_process_image_name ~= "(?i)^(php-fpm.*|php-cgi.*|lsphp.*|frankenphp|apache2|httpd)$"
// | filter not (action_remote_ip incidr "10.0.0.0/8" or action_remote_ip incidr "172.16.0.0/12" or action_remote_ip incidr "192.168.0.0/16" or action_remote_ip incidr "127.0.0.0/8" or action_remote_ip incidr "169.254.0.0/16")
// | filter action_remote_port not in (25, 53, 80, 443, 465, 587, 3306, 5432, 6379, 11211)
// | comp count() as connections by agent_hostname, actor_process_image_name, action_remote_ip, action_remote_port
// | sort desc connections
```


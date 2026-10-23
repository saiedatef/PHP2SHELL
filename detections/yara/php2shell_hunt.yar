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

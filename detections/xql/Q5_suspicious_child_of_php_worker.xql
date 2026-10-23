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

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

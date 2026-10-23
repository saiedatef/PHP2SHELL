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

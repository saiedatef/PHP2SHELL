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

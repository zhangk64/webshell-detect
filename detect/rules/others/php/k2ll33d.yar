rule Backdoor_Webshell_PHP_000066
{
    meta:
        description = "k2ll33d"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if(function_exists('pcntl_fork'))"
        $b = "$process = proc_open($shell, $descriptorspec, $pipes)"
        $c = "$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null)"
        $d = "set_time_limit(0);error_reporting(0)"
        $e = "<?php"
        
    condition:
        all of them
}
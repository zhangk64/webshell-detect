rule Backdoor_Webshell_PHP_000060
{
    meta:
        description = "indrjith"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if(!empty($_SERVER['HTTP_USER_AGENT']))"
        $b = "if (function_exists('pcntl_fork'))"
        $c = "if(!empty($_SERVER['HTTP_USER_AGENT']))"
        $d = "$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null)"
        $e = "$process = proc_open($shell, $descriptorspec, $pipes)"
        
    condition:
        all of them
}
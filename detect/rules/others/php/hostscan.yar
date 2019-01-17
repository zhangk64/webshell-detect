rule Backdoor_Webshell_PHP_000057
{
    meta:
        description = "hostscan"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if($ex = exec('nmap '.$ncmd.' '.$_POST['start'], $out))"
        $b = "Requirements (php5)"
        $c = "php5-mysql - for mysql connections"
        $d = "<?php"
        
    condition:
        all of them
}
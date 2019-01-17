rule Backdoor_Webshell_PHP_000056
{
    meta:
        description = "hima"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$cmd_cnt = $_POST['command'];"
        $b = "$exec .= \" 1> $tmpfile 2>&1; \" . \"cat $tmpfile; rm $tmpfile\""
        $c = "$exec = $cmd_cnt"
        $d = "$cmd_out = `$exec"
        $e = "<?php"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000053
{
    meta:
        description = "h4ntu"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$cmd = $_POST['cmd']"
        $b = "if (isset($chdir)) @chdir($chdir)"
        $c = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\")"
        $d = "<?php"
        
    condition:
        all of them
}
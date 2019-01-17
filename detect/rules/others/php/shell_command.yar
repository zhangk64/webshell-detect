rule Backdoor_Webshell_PHP_000523
{
    meta:
        description = "shell command"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$result = shell_exec($_POST['cmd'] . \" 2>&1\")"
        $b = "<SCRIPT LANGUAGE=\"JavaScript\">"
        $c = "<?php"
        $d = "if ($_POST['cmd']) $_POST['cmd'] = my_encode($_POST['cmd'])"
        
    condition:
        all of them
}
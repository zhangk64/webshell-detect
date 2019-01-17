rule Backdoor_Webshell_PHP_000052
{
    meta:
        description = "grp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "echo eval($_POST['code'])"
        $b = "<?php"
        $c = "$modules_base = \"http://cribble.by.ru/grp_mod/\""
        $d = "function filesmtime($file)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000507
{
    meta:
        description = "php xiaoma"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if(fwrite($f,$_POST[\"c\"]))"
        $b = "$f=fopen($_POST[\"f\"],\"w\");"
        $c = "<?php echo $_SERVER[\"SCRIPT_FILENAME\"];?>"
        $d = "if ($_POST)"
        
    condition:
        all of them
}
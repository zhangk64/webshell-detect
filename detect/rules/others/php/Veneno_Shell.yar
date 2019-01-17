rule Backdoor_Webshell_PHP_000540
{
    meta:
        description = "veneno"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval($_POST['codigo'])"
        $b = "if (!system(\"perl back.pl \".$_GET['ipar']. \" \".$_GET['portar']))"
        $c = "<?php"
        $d = "error_reporting(0)"
        
    condition:
        all of them
}
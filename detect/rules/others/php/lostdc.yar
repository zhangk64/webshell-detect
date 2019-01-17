rule Backdoor_Webshell_PHP_000472
{
    meta:
        description = "lostdc"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "define(\"startTime\",getTime())"
        $b = "$file = $_GET ['file']"
        $c = "$fp = fopen ($file , \"w\")"
        $d = "$new = $_POST ['new']"
        $e = "if (rename ($old , $new))"
        $f = "<?php"
        
    condition:
        all of them
}
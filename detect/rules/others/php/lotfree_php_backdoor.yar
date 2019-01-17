rule Backdoor_Webshell_PHP_000473
{
    meta:
        description = "lotfree"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "system($_REQUEST['cmd'])"
        $b = "LOTFREE PHP Backdoor"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000487
{
    meta:
        description = "nshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$script=$_POST['script'];"
        $b = "eval($script)"
        $c = "$function=passthru"
        $d = "$safe_mode=@ini_get('safe_mode')"
        
    condition:
        all of them
}
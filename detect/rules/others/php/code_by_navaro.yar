rule Backdoor_Webshell_PHP_000021
{
    meta:
        description = "code by navaro"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "ob_end_clean()"
        $b = "$cmd = @$_POST['cmd']"
        $c = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\")"
        $d = "$b33 = $_SERVER['DOCUMENT_ROOT']"
        
    condition:
        all of them
}
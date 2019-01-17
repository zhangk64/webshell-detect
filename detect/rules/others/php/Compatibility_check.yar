rule Backdoor_Webshell_PHP_000023
{
    meta:
        description = "compatibility check"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if ( isset($_REQUEST['debug']) )"
        $b = "if (true == empty($ptrs))"
        $c = "function isFatalError($msg"
        $d = "$checked = $v->checkemails($emails, $a0x)"
        
    condition:
        all of them
}
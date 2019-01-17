rule Backdoor_Webshell_PHP_000520
{
    meta:
        description = "security"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval($_POST['code']);"
        $b = "if (isset($_GET['exec_st']))"
        $c = "if (isset($meth))"
        $d = "@ignore_user_abort(true);"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000514
{
    meta:
        description = "ru24post"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$function=passthru;"
        $b = "echo \"\".$function($_POST['cmd']).\"</pre></body></html>\""
        $c = "error_reporting(0);"
        $d = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a;ls -la\"; }"
        
    condition:
        all of them
}
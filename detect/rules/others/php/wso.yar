rule Backdoor_Webshell_PHP_000550
{
    meta:
        description = "wso"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (!isset($_COOKIE[md5($_SERVER['HTTP_HOST'])])"
        $b = "eval($_POST['p1'])"
        $c = "if( !empty($_POST['a']) && function_exists('action' . $_POST['a']) )"
        $d = "echo htmlspecialchars($_POST['p2'])"
        $e = "$file = $db->loadFile($_POST['p2'])"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000018
{
    meta:
        description = "cmd"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$sm = @ini_get('safe_mode');"
        $b = "$perms = fileperms($file);"
        $c = "else if(function_exists('shell_exec'))"
        $d = "else if(stristr(php_uname(),\"Linux\"))"
        $e = "if($lock == 'on' && (!isset($_SESSION['authenticated']) || $_SESSION['authenticated']!=1) )"
        
    condition:
        all of them
}
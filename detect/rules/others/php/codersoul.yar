rule Backdoor_Webshell_PHP_000020
{
    meta:
        description = "codersoul"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "error_reporting(E_ALL ^ E_NOTICE)"
        $b = "if(!empty($_POST['item']))"
        $c = "function __construct()"
        $d = "function buildPageLogin($error=NULL)"
        $e = "class MySqlLib"
        $f = "function getLinkDir($dir,$complete=true)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000503
{
    meta:
        description = "php kit list"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if($_GET['file'])"
        $b = "if($handle = @opendir($fichero))"
        $c = "$buffer = fread($fp, filesize($fichero))"
        $d = "$fichero=$_GET['file']"
        
    condition:
        all of them
}
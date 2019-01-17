rule Backdoor_Webshell_PHP_000508
{
    meta:
        description = "poisonshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval($_POST['codigo'])"
        $b = "if (!system(\"perl back.pl \" . $_GET['ipar']"
        $c = "echo '<style type=\"text/css\">"
        $d = "$tipo = pathinfo($_GET['reload'])"
        
    condition:
        all of them
}
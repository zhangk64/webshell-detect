rule Backdoor_Webshell_PHP_000001
{
    meta:
        description = "ak team"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval(stripslashes($_POST['phpcode']))"
        $b = "$result = passthru($_POST['cmmd'])"
        $c = "$fp = fopen($_POST['rename'],'w')"
        $d = "fwrite($fp, stripslashes($_POST['filecontent']))"
        $e = "phpinfo()"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000031
{
    meta:
        description = "defacing"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$cmd = stripslashes(trim($cmd))"
        $b = "$boom = explode(\" \",$cmd,2)"
        $c = "if($descpec = array(0 => array(\"pipe\", \"r\"),1 => array(\"pipe\", \"w\"),2 => array(\"pipe\", \"w\"),))"
        $d = "while (list($info, $value) = each ($uname))"
        $e = "$uname = @posix_uname();"
        
    condition:
        all of them
}
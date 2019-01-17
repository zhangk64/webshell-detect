rule Backdoor_Webshell_PHP_000004
{
    meta:
        description = "aventgroup"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if ($sedat=@opendir(\"/tmp\"))"
        $b = "while (($ekinci=readdir ($sedat)))"
        $c = "$i=explode(\";\",$metin);"
        $d = "closedir($sedat)"
        $e = "$baglan=fopen(\"/tmp/$ekinci\",'r')"
        
    condition:
        all of them
}
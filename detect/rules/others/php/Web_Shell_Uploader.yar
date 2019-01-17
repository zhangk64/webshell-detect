rule Backdoor_Webshell_PHP_000544
{
    meta:
        description = "web shell uploader"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$lines=array()"
        $b = "for($i=0;$i<count($lines);$i++)"
        $c = "for($i=0;$i<strlen($str);$i+=$len)"
        $d = "<? echo $request; ?>"
        
    condition:
        all of them
}
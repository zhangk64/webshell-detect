rule Backdoor_Webshell_ASP_000829
{
    meta:
        description = "wen jian bao cun"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-3"
        
    strings:
        $a ="execute(UnEncode(darkst))"
        $b ="for i = 1 to len(temp)"
        $c ="If Asc(Mid(temp, i, 1)) < 32 Or Asc(Mid(temp, i, 1)) > 126 Then"
        $d ="if pk>126 then"
        $e ="function UnEncode(temp)"
        
    condition:
        all of them
}

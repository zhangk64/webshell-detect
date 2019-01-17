rule Backdoor_Webshell_ASP_000812
{
    meta:
        description = "miansha quanqiu"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "BytesToBstr = objstream.ReadText"
        $b = "<%@ LANGUAGE = VBScript.encode%>"
        $c = "objstream.Position = 0"
        $d = "objstream.Write body"
        $e = "Http.setRequestHeader \"CONTENT-TYPE\", \"application/x-www-form-urlencoded\""
        $f = "aspCode=PostHTTPPage"
        
    condition:
        all of them
}
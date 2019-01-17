rule Backdoor_Webshell_ASP_000828
{
    meta:
        description = "upload picture"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%end if%>"
        $b = "shell=request(\"txt\")"
        $c = "set TextFile=FileObject.CreateTextFile(Server.MapPath(\"up1oad.asp\"))"
        $d = "TextFile.Write(shell)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000814
{
    meta:
        description = "mssql cracker by tnt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%=Server.MapPath(\"r.txt\")%>"
        $b = "Set fs = CreateObject(\"Scripting.FileSystemObject\")"
        $c = "If request.Form(\"CFile\") <> \"\" Then CreateResult(str & vbcrlf & tTime)"
        $d = "If Request.Form(\"go\") <> \"1\" Then"
        $e = "If Len(str) >= length Then Exit Sub"
        
    condition:
        all of them
}
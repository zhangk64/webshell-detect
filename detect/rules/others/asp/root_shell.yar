rule Backdoor_Webshell_ASP_000822
{
    meta:
        description = "root shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%=Request.ServerVariables(\"LOCAL_ADDR\")%>"
        $b = "Call ScriptCMD.Run(\"cmd.exe /c \" & Command & \" > \" & TempFile,0,True)"
        $c = "Public Function SaveToFile (Path)"
        $d = "<%=HTMLEncode(FileText)%>"
        $e = "Sub SaveFile()"
        $f = "For Each DriveB in FSO.Drives"
        $G = "<%If flag=0 Then%>"
        
    condition:
        all of them
}
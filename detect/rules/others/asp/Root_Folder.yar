rule Backdoor_Webshell_ASP_000821
{
    meta:
        description = "root folder"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Server.ScriptTimeOut  = 7200"
        $b = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        $c = "Set WshShell = Nothing"
        $d = "Private Sub Class_Terminate()"
        $e = "If Err.Number <> 0 Then"
        $f = "If Trim(Request.QueryString(\"massact\")) = \"test\" Then"
    condition:
        all of them
}
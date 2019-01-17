rule Backdoor_Webshell_ASP_000680
{
    meta:
        description = "cmd"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")"
        $b = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        $c = "If (szCMD <> \"\") Then"
        $d = "Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)"
        $e = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")"
        
    condition:
        all of them
}
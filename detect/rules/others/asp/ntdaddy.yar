rule Backdoor_Webshell_ASP_000817
{
    meta:
        description = "ntdaddy"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a1 = "Call  oScript.Run  (\"cmd.exe  /c  \"  &  szCMD  &  \"  >  \"  &  szTempFile,  0,  True)"
        $b1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        $a2 = "Set  dc  =  fs.Drives"
        $b2 = "Set dc = fs.Drives"
        $a3 = "Set  sf  =  f.SubFolders"
        $b3 = "Set sf = f.SubFolders"
        $a4 = "Set  f  =  fs.GetFolder(FP)"
        $b4 = "Set f = fs.GetFolder(FP)"
        $c = "Language=VBScript"
        $a5 = "Set  oScript  =  Server.CreateObject(\"WSCRIPT.SHELL\")"
        $b5 = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")"
        
    condition:
        ((all of ($a*)) or (all of($b*))) and $c
}
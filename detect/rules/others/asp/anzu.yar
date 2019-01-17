rule Backdoor_Webshell_ASP_000670
{
    meta:
        description = "An Zu"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a1 = "filepath1=server.mappath(\".\")"
        $a2 = "sEssioN(\"FolderPath\")=rRepatH(fOlDeRpATH)"
        $a3 = "RESPONSE.binArywRiTE oSm.Read"
        $a4 = "SEt Rs=CoNn.OPENschEmA(20)"
        $a5 = "PrIVate suB class_InitIALIZe"
        $a6 = "iF noT cF.FolDERexists(pATH) and pAth<>\"\" tHEN"
        
        $b1 = "response.buffer = true"
        $b2 = "for each obj in getobject(\"winnt://.\")"
        $b3 = "if shellpath=\"\" then shellpath = \"cmd.exe\""
        $b4 = "call ws.run (shellpath&\" /c \" & defcmd & \" > \" & sztempfile, 0, true)"
        $b5 = "set cf=createobject(obt(0,0))"
        $b6 = "set fold=cf.getfolder(path)"
        
        $c1 = "f=gpath()"
        $c2 = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\" & ftpport & vbCrLf"
        $c3 = "set c=Server.CreateObject(\"Microsoft.XMLHTTP\")"
        $c4 = "sEssioN(\"FolderPath\")=rRepatH(fOlDeRpATH)"
        
        $d1 = "SET OBJFOLDER = SA.NAMESPACE(THEPATH)"
        $d2 = "SET OBJUSER = GETOBJECT(\"WINNT://./\" & STRUSER & \",USER\")"
        $d3 = "CMDRESULT = DOWSCMDRUN(CMDPATH & \" /C \" & CMDSTR)"
        $d4 = "If InStr(LCase(cmdPath), \"cmd.exe\") > 0 Or InStr(LCase(cmdPath), LCase(myCmdDotExeFile)) > 0 Then"
        $d5 = "doWsCmdRun = ws.Exec(cmdStr).StdOut.ReadAll()"
        $d6 = "ws.Run cmdStr & \" > \" & aspPath, 0, True"
        
        $e1 = "Session(\"FolderPath\")=RRePath(FolderPath)"
        $e2 = "Sub Scan(targetip, portNum)"
        $e3 = "if Action<>\"Servu\" then ShowErr()"
        $e4 = "Set T=Server.CreateObject(ObT(i,0))"
        $e5 = "If Session(\"FolderPath\")=\"\" Then"
        
    condition:
        (all of ($a*)) or (all of ($b*)) or (all of ($c*)) or (all of ($d*)) or (all of ($e*))
}

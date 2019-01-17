rule Backdoor_Webshell_ASP_000684
{
    meta:
        description = "directory scan"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a1 = "Response.Buffer = True"
        $a2 = "Server.ScriptTimeOut=999999999"
        $a3 = "function GetFullPath(path)"
        $a4 = "function ShowDirWrite_Dir_File(Path,CheckFile,CheckNextDir)"
        $a5 = "function CheckFileWrite(filepath)"
        $a6 = "Set objFSO = CreateObject(CONST_FSO)"
        $a7 = "if objFSO.FileExists(filepath) then"
        $a8 = "if B=false then"
        $a9 = "Re = CheckFileWrite(Path)"
        
        $b1 = "Server.ScriptTimeOut=999999999"
        $b2 = "Set Fso=server.createobject(\"scr\"&\"ipt\"&\"ing\"&\".\"&\"fil\"&\"esy\"&\"ste\"&\"mob\"&\"jec\"&\"t\")"
        $b3 = "if sPath=\"\" then"
        $b4 = "<%=ShowPath%>"
        $b5 = "Function CheckDirIsOKWrite(DirStr)"
        $b6 = "Function Bianli(path)"
    condition:
        all of ($a*) or all of ($b*)
}
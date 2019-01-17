rule Backdoor_Webshell_ASP_000686
{
    meta:
        description = "fso browser"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Call fsoX.CopyFolder(sessionPath, thePath"
        $b = "vbNewLine:echo \"function changeThePath(me)"
        $c = "& vbNewLine:echo \"location.href = '?pageName='"
        $d = "Function AcEncodeII(Code)"
        
    condition:
        all of them
}

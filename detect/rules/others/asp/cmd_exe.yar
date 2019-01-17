rule Backdoor_Webshell_ASP_000681
{
    meta:
        description = "cmd exe"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<SCRIPT language=\"JavaScript\" runat=\"server\">"
        $b = "var giTimeout           = parseInt(getVar(\"timeout\", \"0\"));"
        $c = "var sIISVer = Request.ServerVariables(\"SERVER_SOFTWARE\");"
        $d = "while (!oCMD.StdErr.AtEndOfStream)"
        $e = "oAS.SaveToFile(sDestinationPath, 2)"
        $f = "return outputTransferStatus"
        
    condition:
        all of them
}
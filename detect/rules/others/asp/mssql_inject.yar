rule Backdoor_Webshell_ASP_000816
{
    meta:
        description = "mssql infiltration"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%OPTION EXPLICIT%>"
        $b = "Call HtmlFooter()"
        $c = "Call HtmlHeader()"
        $d = "if strPath =\"\" then"
        $e = "Function CmdShell()"
        $f = "Set Rs = Conn.Execute(sSQL)"
        $g = "strSN = CStr(Request.ServerVariables(\"SCRIPT_NAME\"))"
        $h = "if IsNull(Request.Cookies(Cookie_Login)) Or IsEmpty(Request.Cookies(Cookie_Login)) then"
        $i = "For each sfd In fd.SubFolders"
        
    condition:
        all of them
}
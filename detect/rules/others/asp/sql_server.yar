rule Backdoor_Webshell_ASP_000825
{
    meta:
        description = "sql server"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%@LANGUAGE=\"VBSCRIPT\" CODEPAGE=\"936\"%>"
        $b = "FunCtion GetDataName(namestr,Passstr,kustr)"
        $c = "ElseIf Session(\"jk1986\") <> \"\"  And Session(\"dbname\") <> \"\" Then"
        $d = "Server.MapPath(Request.ServerVariables(\"SCRIPT_NAME\"))"
        $e = "If Session(\"jk1986\") = \"\" Then"
        
    condition:
        all of them
}
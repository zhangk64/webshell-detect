rule Backdoor_Webshell_ASPX_000872
{
    meta:
        description = "rootShell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<title>Root@Shell 1.0 By Silentz</title>"
        $b = "<center><span class=\"\"title\"\"><b>Welcome to Root@Shell</b></span></center><br>"
        $c = "ElseIf InStr(Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\"), \",\") > 0 Then"
        $d = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text"
        
    condition:
        all of them
}
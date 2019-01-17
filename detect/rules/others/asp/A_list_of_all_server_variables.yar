rule Backdoor_Webshell_ASP_000676
{
    meta:
        description = "list of server variables"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Dim Vars"
        $b = "<% For Each Vars In Request.ServerVariables %>"
        $c = "<TD><FONT SIZE=\"1\" face=\"Arial, Helvetica, sans-serif\"><%= Vars %>"
        $d = "<TD><FONT SIZE=\"1\" face=\"Arial, Helvetica, sans-serif\"><%= Request.ServerVariables(Vars) %>"
        
    condition:
        all of them
}
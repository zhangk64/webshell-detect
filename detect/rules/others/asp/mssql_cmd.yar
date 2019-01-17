rule Backdoor_Webshell_ASP_000813
{
    meta:
        description = "mssql statement execution tool"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "src=\"<%=Request.ServerVariables(\"SCRIPT_NAME\")%>"
        $b = "If Sql_serverip<>\"\" and Sql_linkport<>\"\" and Sql_username<>\"\" and Sql_password<>\"\" and Sql_content<>\"\" Then"
        $c = "If Sql_linkport=\"\" Then Sql_linkport=\"1433\""
        $d = "If Request(\"do\")<>\"\" Then"
        $e = "Dim Sql_serverip,Sql_linkport,Sql_username,Sql_password,Sql_database,Sql_content"
        
    condition:
        all of them
}
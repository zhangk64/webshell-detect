rule Backdoor_Webshell_JSP_000662
{
    meta:
        description = "oracle execute"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "ResultSet rs = stmt.executeQuery(sql)"
        $b = "executeUpdate(str, url, user, password) + \" tiao !\""
        $c = "var sqlrequest = document.getElementById('sqlrequest')"
        $d = "var iniselect = document.getElementById('emSql').value"
        $e = "String strResponse =\"<b>execute :\\\"\" + strsql + \"\\\"</b><table border=1>\""
        $f = "List listtmp = toFuckLZ(strsql, url, user, password)"
        
    condition:
        all of them
}
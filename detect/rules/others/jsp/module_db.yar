rule Backdoor_Webshell_JSP_000658
{
    meta:
        description = "module db"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-3"
        
    strings:
        $a = "public static Connection getConn(String driverName, String url"
        $b = "Class.forName(driverName)"
        $c = "<%=conn_userName%>"
        $d = "private final String[] del_report = new String[1]"
        
    condition:
        all of them
}
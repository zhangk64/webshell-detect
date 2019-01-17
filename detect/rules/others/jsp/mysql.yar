rule Backdoor_Webshell_JSP_000660
{
    meta:
        description = "mysql sjk jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="Connection conn = DriverManager.getConnection(url, username, password)"
        $b ="Statement stmt = conn.createStatement()"
        $c ="OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(backupDir+table+ex), \"UTF-8\")"
        $d ="rs = stmt.executeQuery(\"SELECT * FROM \" + table)"
        $e ="response.setStatus(200)"
        
    condition:
        all of them
}
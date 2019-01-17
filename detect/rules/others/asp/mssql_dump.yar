rule Backdoor_Webshell_ASP_000815
{
    meta:
        description = "mysql guide library"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%"
        $b = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)"
        $c = "serverip=request(\"server\")"
        $d = "SET conn= Server.CreateObject(\"ADODB.Connection\")"
        $e = "sql=\"select * from [\" & tablename & \"]"
        $f = "conn.open \"Provider=SQLOLEDB;Server=\" & serverip & \";Database=\" & dbname & \";UID=\" & sqluser & \";PWD=\" & sqlpass"
        
    condition:
        all of them
}

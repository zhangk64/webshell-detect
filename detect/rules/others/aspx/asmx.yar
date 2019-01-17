rule Backdoor_Webshell_ASPX_000836
{
    meta:
        description = "service web"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "[WebService(Namespace = \"http://www.wooyun.org/whitehats/RedFree\")]"
        $b = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == 0)"
        $c = "SqlCommand cm = Conn.CreateCommand()"
        $d = "FileStream FS = new FileStream(Z2, FileMode.Create, FileAccess.Write);"
        
    condition:
        all of them
}
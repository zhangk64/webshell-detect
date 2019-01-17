rule Backdoor_Webshell_JSP_000572
{
    meta:
        description = "file manager"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "static Hashtable uploadTable = new Hashtable()"
        $b = "System.out.println(e.toString())"
        $c = "os = new FileOutputStream"
        $d = "new FileOutputStream(f)"
        $e = "FileOutputStream out1 = new FileOutputStream(f_des_copy)"
        $f = "exec(strCommand, null,"
        
    condition:
        all of them
}

rule Backdoor_Webshell_JSP_000558
{
    meta:
        description = "jfolerajsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "uploadTable.remove(fName)"
        $b = "System.out.println(e.toString())"
        $c = "os = new FileOutputStream"
        $d = "new FileOutputStream(f)"
        $e = "ZipOutputStream out = new ZipOutputStream(new FileOutputStream("
        $f = "FileOutputStream out1 = new FileOutputStream(f_des_copy)"
        $g = "Process p = Runtime.getRuntime().exec("
        $h = "\"cmd /c \" + strCmd)"
        
    condition:
        all of them
}

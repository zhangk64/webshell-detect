rule Backdoor_Webshell_JSP_000562
{
    meta:
        description = "hua xia"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Runtime runtime = Runtime.getRuntime()"
        $b = "FileOutputStream out = new FileOutputStream(newFile)"
        $c = "FileOutputStream out = new FileOutputStream(new File(dstPath))"
        $d = "proc = runtime.exec(cmd)"
        
    condition:
        all of them
}

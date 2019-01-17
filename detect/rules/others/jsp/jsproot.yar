rule Backdoor_Webshell_JSP_000565
{
    meta:
        description = "jsp root"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "selfName=request.getRequestURI()"
        $b = "FileOutputStream out = new FileOutputStream(new File(dstPath))"
        $c = "proc = runtime.exec(cmd)"
        
    condition:
        all of them
}

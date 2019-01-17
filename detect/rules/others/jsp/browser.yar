rule Backdoor_Webshell_JSP_000556
{
    meta:
        description = "browser"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "boundary == null || boundary.trim().length() < 1"
        $b = "stFields.nextToken().trim().equalsIgnoreCase(\"filename\")"
        $c = "os = new FileOutputStream"
        $d = "new FileOutputStream("
        $e = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir))"
        
    condition:
        all of them
}
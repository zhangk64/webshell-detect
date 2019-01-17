rule Backdoor_Webshell_JSP_000559
{
    meta:
        description = "devilz"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "os = new FileOutputStream"
        $b = "FileOutputStream ooo = new FileOutputStream(xCwd + fname)"
        $c = "new FileOutputStream(fullPath)"
        $d = "Process p = Runtime.getRuntime().exec(finals)"
        $e = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(cwd))"
        
    condition:
        all of them
}

rule Backdoor_Webshell_JSP_000664
{
    meta:
        description = "pwnshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "currentDir = new File(System.getProperty(\"user.dir\")).getCanonicalPath()"
        $b = "Process p = Runtime.getRuntime().exec("
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000569
{
    meta:
        description = "jsp backdoor reverse"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "< %!"
        $b = "% >"
        $c = "Process proc = rt.exec(\"cmd.exe\")"
        $d = "JSP Backdoor Reverse Shell"
        
    condition:
        all of them
}
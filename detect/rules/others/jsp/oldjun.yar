rule Backdoor_Webshell_JSP_000661
{
    meta:
        description = "file oldjun"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Process ls_proc = Runtime.getRuntime().exec(\"cmd.exe /c dir \\\"\" + file.getAbsolutePath() + \"\\\" /tc\")"
        
    condition:
        all of them
}

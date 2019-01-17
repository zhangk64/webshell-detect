rule Backdoor_Webshell_JSP_000667
{
    meta:
        description = "send"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Process child = Runtime.getRuntime().exec(k8cmd)"
        $b = "out.print(\"->|\")"
        $c = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"))"
        $d = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParameter(\"cmd\"))"
        $e = "cmd.jsp = Command Execution"
        
    condition:
    ($a and $b) or (($c or $d) and $e)
}

rule Backdoor_Webshell_JSP_000666
{
    meta:
        description = "sava problem"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "String url=request.getParameter(\"url\")"
        $b = "OutputStream o=new FileOutputStream(f)"
        $c = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd)"
        $d = "String cmd = request.getParameter(\"cmd\")"
        $e = "String method=request.getParameter(\"act\")"
        $f = "tring text=request.getParameter(\"smart\")"
        
    condition:
        ($a and $b and $e and $f) or ($c and $d)
}
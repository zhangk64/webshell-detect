rule Backdoor_Webshell_JSP_000665
{
    meta:
        description = "sava"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "request.getRealPath(request.getServletPath())"
        $b = "pt = new FileOutputStream(path)"
        $c = "OutputStream o=new FileOutputStream(f)"
        
    condition:
        2 of them
}

rule Backdoor_Webshell_JSP_000571
{
    meta:
        description = "juhua chat room"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a ="StringBuffer bf = null"
        $b ="if (null == application.getAttribute(\"talks\"))"
        $c ="String p1 = request.getParameter(\"what\")"
        $d ="if (null != b && b.length() > 0)"
        
    condition:
        all of them
}

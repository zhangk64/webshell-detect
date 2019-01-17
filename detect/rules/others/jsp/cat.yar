rule Backdoor_Webshell_JSP_000557
{
    meta:
        description = "cat"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="FileOutputStream fos = new FileOutputStream(path)"
        $b ="application.getRealPath(\"/\"):\".\")).getCanonicalPath()"
        $c ="String file = request.getParameter(\"file\")"
        $d ="String data = request.getParameter(\"data\")"
        $e ="bos.write(buf, 0, len)"
        
    condition:
        all of them
}

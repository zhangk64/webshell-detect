rule Backdoor_Webshell_JSP_000561
{
    meta:
        description = "directory listing"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "String file = request.getParameter(\"file\")"
        $b = "FileOutputStream fos = new FileOutputStream(path)"
        $c = "inutStreamToOutputStream(Runtime.getRuntime().exec(cmd).getInputStream()).toByteArray(),encoding"
        $d = "application.getRealPath(\"/\"):\".\")).getCanonicalPath()"
        $e = "bos.write(buf, 0, len)"
        
    condition:
        all of them
}

rule Backdoor_Webshell_JSP_000564
{
    meta:
        description = "jfolerajsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "stFields.nextToken().trim().equalsIgnoreCase(\"filename\")"
        $b = "request.setAttribute (\"dir\", application.getRealPath(\".\")"
        $c = "os = new FileOutputStream(path = getFileName(saveInDir,"
        $d = "OutputStream fos = new FileOutputStream (f_new)"
        $e = "By Bagheera"
        
    condition:
        all of them
}

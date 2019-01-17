rule Backdoor_Webshell_JSP_000568
{
    meta:
        description = "jsp spy jsproot"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "OutputStream o = response.getOutputStream()"
        $b = "FileOutputStream out = new FileOutputStream(nf)"
        $c = "ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zipfile))"
        $d = "out = new FileOutputStream(savePath + fileName)"
        $e = "p = Runtime.getRuntime().exec(\"cmd /c \"+command)"
        $f = "p = Runtime.getRuntime().exec(command)"
        $g = "Utils.exec(value,prop)"
        
    condition:
        all of them
}
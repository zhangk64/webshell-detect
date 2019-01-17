rule Backdoor_Webshell_JSP_000668
{
    meta:
        description = "shack2"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "String s = contentDisposition.substring(contentDisposition.indexOf(\"name=\\\"\") + 6)"
        $b = "String s = contentDisposition.substring(contentDisposition.indexOf(\"filename=\\\"\") + 10)"
        $c = "fos = new FileOutputStream(zipPath)"
        $d = "osw=new OutputStreamWriter(new FileOutputStream(path))"
        $e = "osw=new OutputStreamWriter(new FileOutputStream(path),encode)"
        $f = "FileOutputStream fos = new FileOutputStream(fileName)"
        $g = "Process p = Runtime.getRuntime().exec(cmds)"
        
    condition:
        all of them
}
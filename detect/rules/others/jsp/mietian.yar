rule Backdoor_Webshell_JSP_000657
{
    meta:
        description = "mietian"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Process p = Runtime.getRuntime().exec(cmd)"
        $b = "String pwd=request.getParameter(\"pwd\")"
        $c = "OutputStream os = new FileOutputStream(new File(p, fn))"
        $d = "FileOutputStream fos = new FileOutputStream(f)"
        $e = "FileOutputStream fos=new FileOutputStream(d)"
        $f = "Process p = rt.exec(\"\\\"\" + path + \"\\\" x -o+ -p- \" + file.getAbsolutePath() + \" \" + dir.getAbsolutePath())"
        $g = "String str=exec(ps[i], null)"
        $h = "String str=  exec(isLinux ? \"/etc/init.d/ \"+ps[i]+\" restart\" : \"net stop \"+ps[i]+\" & net start \"+ps[i], null)"
        $i = "pro=Runtime.getRuntime().exec(isLinux?\"bash\":\"cmd\",null,f)"
        
    condition:
        all of them
}

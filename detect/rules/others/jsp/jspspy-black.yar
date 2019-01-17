rule Backdoor_Webshell_JSP_000566
{
    meta:
        description = "jsp spy black"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "String strAbsPath = file.getParent()"
        $b = "bos = new BufferedOutputStream(new FileOutputStream(path))"
        $c = "FileOutputStream fos = new FileOutputStream(newFile)"
        $d = "FileOutputStream fos = new FileOutputStream(dfile)"
        $e = "pro = Runtime.getRuntime().exec(\"cmd.exe /c netstat -an\")"
        $f = "pro = Runtime.getRuntime().exec(\"cmd.exe /c net start\")"
        $g = "pro = Runtime.getRuntime().exec(\"cmd.exe /c tasklist /svc\")"
        $h = "pro = run.exec(cmd)"
        $i = "process = Runtime.getRuntime().exec(\"ipconfig /all\")"
        
    condition:
        all of them
}
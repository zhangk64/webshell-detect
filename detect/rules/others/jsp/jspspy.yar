rule Backdoor_Webshell_JSP_000567
{
    meta:
        description = "jsp root"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "this.ol.getCmd().equals(\"first\")"
        $b = "private static class StreamConnector extends Thread"
        $c = "return stmt.getUpdateCount()"
        $d = "WEB_ROOT = application.getRealPath(\"/\")"
        $e = "return \"\"+stmt.getUpdateCount()"
        $f = "new FileOutputStream(new File(to)))"
        $h = "new BufferedOutputStream(new FileOutputStream(saveF)))"
        $k = "Process pro = Runtime.getRuntime().exec(command)"
        $l = "Process pro = Runtime.getRuntime().exec(program)"
        $m = "Process process = Runtime.getRuntime().exec(program)"
        $n = "Process pro = Runtime.getRuntime().exec(exe)"
        $o = "return \"\" + stmt.getUpdateCount()"
        
    condition:
        $a and $b and ($c or $e or $o) and $d and $f and $h and $k and $l and $m and $n
}
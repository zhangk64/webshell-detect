rule Backdoor_Webshell_JSP_000669
{
    meta:
        description = "webmanage cbs"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-3"
        
    strings:
        $a1 ="if (OS.startsWith(\"Windows\"))"
        $a2 ="p = Runtime.getRuntime().exec(cmds)"
        $a3 ="BufferedInputStream in = new BufferedInputStream(p.getInputStream())"
        $a4 ="String s = contentDisposition.substring(contentDisposition.indexOf(\"filename=\\\"\") + 10)"
        
        $b1 ="public static final class Config"
        $b2 ="page.logoutLink.parents(\"ul\").removeClass(\"hide\")"
        $b3 ="if (\"view\".equals(action) || \"download\".equals(action))"
        $b4 ="protected String getUrl(String action, String path)"
        
    condition:
        all of ($a*) or all of ($b*)
}

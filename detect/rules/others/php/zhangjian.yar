rule Backdoor_Webshell_PHP_000554
{
    meta:
        description = "zhangjian"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<input name=\"dir\" type=\"text\" value=\"c:/\" />"
        $b = "<div align=\"center\">code Author:<span class=\"STYLE1\"><font color='red'>"
        
    condition:
        all of them
}
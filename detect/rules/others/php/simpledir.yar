rule Backdoor_Webshell_PHP_000527
{
    meta:
        description = "simpledir"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "echo \"File:<input type=\\\"text\\\" style=\\\"width:600px;\\\" name=\\\"file\\\" value=\\\"\".$path.\"\\\" /><input type=\\\"button\\\" style=\\\"margin-left:20px;\\\" value=\\\"update\\\" onclick=\\\"update()\\\" /><span id=\\\"result\\\"></span><br/>\""
        $b = "if('update'==$_POST['action'])"
        $c = "echo \"<a href=\\\"javascript:get('\".str_replace('\\\\','/',$path).\"/\".$file.\"');\\\">\".$file.\"</a><br>\""
        $d = "if('update'==@$_POST['action'])"
        
    condition:
        ($a and $b) or ($c and $d)
}
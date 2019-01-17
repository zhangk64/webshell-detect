rule Backdoor_Webshell_PHP_000070
{
    meta:
        description = "knull"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "ob_start(); system($cmd); $ret_exec=ob_get_contents(); ob_end_clean()"
        $b = "$webshcmd = $ini['aliases'][$token] . substr($webshcmd, $length)"
        $c = "if ($_POST['bd_host'] === 'plbd')"
        $d = "htmlspecialchars($_POST['port']) . '</p>'"
        $e = "<?php } ?>"
        
    condition:
        all of them
}
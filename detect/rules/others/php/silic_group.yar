rule Backdoor_Webshell_PHP_000525
{
    meta:
        description = "silic group"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "header(\"Content-type:text/html; charset=gb2312\")"
        $b = "$f1=$HTTP_SERVER_VARS['php_self']"
        $c = "<?php echo \"S\".$t2.\" G\".$t3.$C0DE.$t4;?>"
        $d = "<?php echo $HTTP_SERVER_VARS['php_self'];?>"
        
    condition:
        all of them
}
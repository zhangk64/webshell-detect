rule Backdoor_Webshell_PHP_000073
{
    meta:
        description = "linux target"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if(@exec($_POST['exec'],$ar))"
        $b = "$ee=fopen($_POST['nf'],'w+')"
        $c = "@copy($_POST['strin'],$_POST['remot'])"
        $d = "<?php"
        $e = "while(list($key,$val)=each($_POST))"
        
    condition:
        all of them
}
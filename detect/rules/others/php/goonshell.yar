rule Backdoor_Webshell_PHP_000050
{
    meta:
        description = "goonshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval(stripslashes($_POST['phpexec']))"
        $b = "$self = basename($_SERVER['PHP_SELF'])"
        $c = "<?php"
        $d = "elseif($dir && $_SESSION['dir']){$dir = $_SESSION['dir'];}"
        $e = "if(!$act && !$cmd && !$cookie && !$f && !$dir && !$gf && !$img){main();}"
        
    condition:
        all of them
}
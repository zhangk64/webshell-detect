rule Backdoor_Webshell_PHP_000062
{
    meta:
        description = "itset"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$head='<style type=\"text/css\">"
        $b = "echo $head.'"
        $c = "if (system('ls -s '.$_POST['ad1syc'].\" \".$_POST['ad2syc']))"
        $d = "$colort='\"#e4e1de\"'"
        $e = "<?php"
        
    condition:
        all of them
}
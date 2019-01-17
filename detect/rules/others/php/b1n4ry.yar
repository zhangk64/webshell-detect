rule Backdoor_Webshell_PHP_000005
{
    meta:
        description = "b1n4ry"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<?php"
        $b = "eval(stripslashes($phpc))"
        $c = "fwrite($bc,'#!/usr/bin/perl"
        $d = "</html>'"
        $e = "if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name']))"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000480
{
    meta:
        description = "mysql manager"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="Created by PhpStorm"
        $b ="header(\"Access-Control-Allow-Origin:*\")"
        $c ="$(function()"
        $d ="<!-- tile header -->"
    condition:
        all of them
}

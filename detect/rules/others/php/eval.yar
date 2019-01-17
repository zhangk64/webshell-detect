rule Backdoor_Webshell_PHP_000036
{
    meta:
        description = "eval"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="include_once(dirname(__FILE__)"
        $b ="Created by PhpStorm"
        $c ="header(\"Access-Control-Allow-Origin:*\")"
        
    condition:
        all of them
}

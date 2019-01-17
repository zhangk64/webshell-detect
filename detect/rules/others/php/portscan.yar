rule Backdoor_Webshell_PHP_000509
{
    meta:
        description = "portscan"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-5"
        
    strings:
        $a ="header(\"Access-Control-Allow-Origin:*\")"
        $b ="Created by PhpStorm"
        $c ="<button type=\"button\" class=\"btn btn-primary\" onclick=\"doPortScan()\" style=\"float: right"
        $d = "<div class=\"tile-header\">"
        
    condition:
        all of them
}
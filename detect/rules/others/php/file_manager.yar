rule Backdoor_Webshell_PHP_000041
{
    meta:
        description = "file manager"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-5"
        
    strings:
        $a ="Created by PhpStorm"
        $b ="header(\"Access-Control-Allow-Origin:*\")"
        $c =" <button type=\"button\" class=\"btn btn-default\" style=\"height: 37px;\" onclick=\"goDir(':webRoot')"
        $d ="<!-- /tile widget -->"
        
    condition:
        all of them
}
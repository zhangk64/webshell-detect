rule Backdoor_Webshell_PHP_000016
{
    meta:
        description = "by blaster"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "ob_start();"
        $b = "curl_setopt($ch,CURLOPT_URL,$son);"
        $c = "$al=curl_exec($ch);"
        $d = "elseif(eregi(\"Access\",$al))"
        $e = "<?PHP"
        
    condition:
        all of them
}
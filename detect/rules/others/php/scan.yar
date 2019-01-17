rule Backdoor_Webshell_PHP_000519
{
    meta:
        description = "scan"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "set_time_limit(0)"
        $b = "function check_port($ip,$port,$timeout=0.1)"
        $c = "function getHtmlContext($url)"
        $d = "curl_setopt($ch, CURLOPT_HEADER, TRUE)"
        $e = "curl_setopt($ch, CURLOPT_NOBODY, FALSE)"
        
    condition:
        all of them
}
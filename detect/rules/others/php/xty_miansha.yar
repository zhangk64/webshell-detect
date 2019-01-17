rule Backdoor_Webshell_PHP_000552
{
    meta:
        description = "xty miansha"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "while (preg_match('/\\/\\//',$folder))"
        $b = "global $meurl,$me,$sitetitle, $lastsess, $login, $viewing, $iftop, $user, $pass, $password, $debug, $issuper"
        $c = "$file = curl_get_contents($url)"
        $d = "file_put_contents($newfname,$file)"
        $e = "$content2[$b]"
        
    condition:
        all of them
}
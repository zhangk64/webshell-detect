rule Backdoor_Webshell_PHP_000534
{
    meta:
        description = "tsn"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if(!empty($_GET['file'])) $file=$_GET['file']"
        $b = "$hardstyle = explode(\"/\", $file)"
        $c = "while($level--) chdir(\"..\")"
        $d = "$ch = curl_init()"
        $e = "if(FALSE==curl_exec($ch))"
        
    condition:
        all of them
}
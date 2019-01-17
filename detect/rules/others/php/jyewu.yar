rule Backdoor_Webshell_PHP_000065
{
    meta:
        description = "jyewu"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval('$hexdtime = \"' . $hexdtime . '\";')"
        $b = "function Mysql_shellcode("
        $c = "echo base64_decode($images[$img])"
        $d = "$conn = @mysql_connect($_COOKIE['m_eanverhost']"
        $e = "define('myaddress',__FILE__)"
        
    condition:
        all of them
}
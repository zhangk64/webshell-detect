rule Backdoor_Webshell_PHP_000025
{
    meta:
        description = "coppermine"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "error_reporting(0);"
        $b = "$datai=dechex(ord($headeri[$ii]));"
        $c = "$result = socket_connect($socket, $host, $port);"
        $d = "while ((!feof($ock)) or (!eregi(chr(0x0d).chr(0x0a).chr(0x0d).chr(0x0a),$html)))"
        $e = "$USER=$_POST[USER];$PASS=$_POST[PASS];"
        $f = "/* a short explaination:  arbitrary local inclusion issue in \"lang"
        
    condition:
        all of them
}
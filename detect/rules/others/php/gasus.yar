rule Backdoor_Webshell_PHP_000046
{
    meta:
        description = "gasus"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$onoff = ini_get('register_globals')"
        $b = "@extract($_GET, EXTR_SKIP)"
        $c = "fwrite($dosya, $metin) or die"
        $d = "while($file=$mydir->read())"
        $e = "if(file_exists(\"C:\\\\\"))"
        
    condition:
        all of them
}
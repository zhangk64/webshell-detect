rule Backdoor_Webshell_PHP_000064
{
    meta:
        description = "juhua"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a ="$ip = preg_replace('/((?:\\d+\\.){3})\\d+/','\\\\1*',$_SERVER['REMOTE_ADDR'])"
        $b ="fwrite($file,$text)"
        $c ="$data = addslashes(trim($_POST['what']))"
        $d ="if (!empty($data))"
        
    condition:
        all of them
}
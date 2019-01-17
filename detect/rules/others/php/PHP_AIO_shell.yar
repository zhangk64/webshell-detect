rule Backdoor_Webshell_PHP_000499
{
    meta:
        description = "php aio shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="error_reporting(E_ALL)"
        $b ="function read_file($file_name)"
        $c ="if (fwrite($dst_fp, $buf, strlen($buf)) == false)"
        $d ="function linux_exec($socket, $cmd)"
        $e ="function aio_main()"
        
    condition:
        all of them
}

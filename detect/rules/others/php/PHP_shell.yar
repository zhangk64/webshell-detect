rule Backdoor_Webshell_PHP_000506
{
    meta:
        description = "php shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "chdir($work_dir)"
        $b = "while ($dir = readdir($dir_handle))"
        $c = "for ($i = 0; $i < count($work_dir_splitted); $i++)"
        $d = "$dir_handle = opendir($work_dir)"
        $e = "system($command)"
        
    condition:
        all of them
}
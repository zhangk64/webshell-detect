rule Backdoor_Webshell_PHP_000501
{
    meta:
        description = "php jiance"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if(file_exists($a))"
        $b = "if(is_writable($dirFile))"
        $c = "if(is_dir($dirFile))"
        $d = "dir_File($a)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000532
{
    meta:
        description = "sqider"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$matches = array"
        $b = "if(($handle = @opendir($dir)) == NULL) return false"
        $c = "if(is_dir($path))"
        $d = "if(file_exists($_POST['dir']) && $_POST['exs'])"
        
    condition:
        all of them
}
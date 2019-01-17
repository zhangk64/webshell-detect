rule Backdoor_Webshell_PHP_000498
{
    meta:
        description = "phpspy"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "system($_POST['command'])"
        $a2 = "return implode('/', $mainpath_info)"
        $a3 = "$mtime = explode(' ', microtime())"
        $a4 = "if (get_magic_quotes_gpc()"
        
        $b1 = "$process = proc_open($_SERVER['COMSPEC'], $descriptorspec, $pipes)"
        $b2 = "@set_magic_quotes_runtime(0)"
        $b3 = "if ($doing == 'downfile' && $thefile)"
        $b4 = "<script type=\"text/javascript\">"
        $b5 = "return substr(base_convert(@fileperms($filepath),10,8),-4"
        
    condition:
        all of ($a*) or all of ($b*)
}
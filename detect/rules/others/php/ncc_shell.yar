rule Backdoor_Webshell_PHP_000484
{
    meta:
        description = "ncc shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<?if($cmd != \"\") print Shell_Exec($cmd);?>"
        $b = "<? $cmd = $_REQUEST[\"-cmd\"];?>"
        $c = "if( ini_get('safe_mode') )"
        $d = "if(@$_GET['p']==\"info\")"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000513
{
    meta:
        description = "root shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<? echo $_SERVER['DOCUMENT_ROOT']; ?>"
        $b = "<?php @$output = system($_POST['command']); ?>"
        $c = "function check_file()"
        $d = "if( ini_get('safe_mode') )"
        $e = "elseif(! file_exists($filename))"
        
    condition:
        all of them
}

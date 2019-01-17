rule Backdoor_Webshell_PHP_000545
{
    meta:
        description = "winx shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "set_magic_quotes_runtime(0)"
        $b = "move_uploaded_file($userfile, $serverfile)"
        $c = "if (is_uploaded_file($userfile))"
        $d = "if( $cmd == \"\" )"
        
    condition:
        all of them
}
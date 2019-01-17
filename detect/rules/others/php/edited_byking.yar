rule Backdoor_Webshell_PHP_000035
{
    meta:
        description = "edited byking"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "foreach ($users as $user)"
        $b = "function read_dir($path,$username)"
        $c = "unction ftp_check($login,$pass)"
        $d = "@$res=ftp_login($ftp,$login,$pass)"
        
    condition:
        all of them
}
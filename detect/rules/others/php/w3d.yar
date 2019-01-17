rule Backdoor_Webshell_PHP_000542
{
    meta:
        description = "w3d"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "setcookie(\"user\", \"$user\", time()+3600)"
        $b = "$con = @mysql_connect($host, $user, $pass)"
        $c = "$db_c = @mysql_select_db($dbn,$con)"
        $d = "$query1 = str_replace(\"\\\\\", \" \", $query)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000510
{
    meta:
        description = "postgresql"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$pgquery=stripslashes($pgquery)"
        $b = "Str = new Array(6)"
        $c = "if(!empty($pghost) && !empty($pgport))"
        $d = "while ($pgrow=pg_fetch_row($pgresult))"
        $e = "pg_free_result($pgresult)"
        
    condition:
        all of them
}
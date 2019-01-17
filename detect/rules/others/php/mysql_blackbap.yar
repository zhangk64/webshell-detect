rule Backdoor_Webshell_PHP_000482
{
    meta:
        description = "mysql blackbap"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password)"
        $b = "while($data=mysql_fetch_assoc($q3))"
        $c = "$keys=array_map('addslashes',$keys)"
        $d = "fputs($fp,$mysql)"
        $e = "mysql_select_db($mysql_database)"
        
    condition:
        all of them
}
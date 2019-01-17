rule Backdoor_Webshell_PHP_000481
{
    meta:
        description = "mysqldoor"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a ="$result = mysql_query($query, $link)  or die(mysql_error())"
        $b ="@mysql_query(\"DROP TABLE udf_temp\", $link)"
        $c ="while ($row =  @mysql_fetch_array ($result))"
        $d ="$link = mysql_connect ($mysql_hostname,$mysql_username,$mysql_passwd) or die(mysql_error())"
        
    condition:
        all of them
}
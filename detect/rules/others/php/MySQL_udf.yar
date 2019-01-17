rule Backdoor_Webshell_PHP_000483
{
    meta:
        description = "mysql udf"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-5"
        
    strings:
        $a ="while ($row =  @mysql_fetch_array ($result))"
        $b ="extract($_POST)"
        $c ="$link = mysql_connect ($mysql_hostname,$mysql_username,$_SESSION['password']) or die(mysql_error())"
        $d = "<form method=\"post\" action=\"<?echo $HTTP_SERVER_VARS['php_self'];?>?\">"
        
    condition:
        all of them
}

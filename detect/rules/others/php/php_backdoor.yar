rule Backdoor_Webshell_PHP_000500
{
    meta:
        description = "php backdoor"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "system($_REQUEST['c']);"
        $b = "<? echo $PHP_SELF; ?>"
        $c = "if(isset($_REQUEST['f']))"
        $d = "while ($row = mysql_fetch_array($result,MYSQL_ASSOC)) print_r($row)"
        
    condition:
        all of them
}
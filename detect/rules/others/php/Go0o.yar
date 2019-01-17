rule Backdoor_Webshell_PHP_000049
{
    meta:
        description = "Go0o"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$_POST[$k] = stripslashes($v)"
        $b = "eval($_POST['phpev'])"
        $c = "$fp = fopen($file,"
        $d = "$fp = @fopen($_POST['dif_name'], \"w\")"
        $e = "$sql1 .= \"# database : \".$_POST['mysql_db'].\"\\r\\n\""
        
    condition:
        all of them
}
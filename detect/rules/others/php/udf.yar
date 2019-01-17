rule Backdoor_Webshell_PHP_000535
{
    meta:
        description = "udf"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a ="session_start()"
        $b ="@mysql_select_db($_SESSION['dbname'])"
        $c ="if(strrpos($_SESSION['dllpath'],'\\\\')==false || strrpos($_SESSION['dllpath'],'\\\\')!=strlen($_SESSION['dllpath'])-1)"
        $d ="if(!empty($_POST['query']))"
        $e ="$query=stripslashes($_POST['query'])"
        
    condition:
        all of them
}

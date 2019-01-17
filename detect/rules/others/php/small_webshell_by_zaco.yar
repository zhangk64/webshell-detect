rule Backdoor_Webshell_PHP_000530
{
    meta:
        description = "small webshell by zaco"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$page=isset($_POST['page'])?$_POST['page']:(isset($_SERVER['QUERY_STRING'])?$_SERVER['QUERY_STRING']:'')"
        $b = "$winda=strpos(strtolower(php_uname()),'wind')"
        $c = "$work_dir=isset($_POST['work_dir'])?$_POST['work_dir']:getcwd()"
        $d = "$action=isset($_POST['action'])?$_POST['action']:'cmd'"
        
    condition:
        all of them
}
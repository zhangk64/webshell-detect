rule Backdoor_Webshell_PHP_000533
{
    meta:
        description = "stnc"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$code = $_POST[\"code\"]"
        $b = "eval($code)"
        $c = "error_reporting(0)"
        $d = "foreach ($_POST as $k=>$v)"
        
    condition:
        all of them
}
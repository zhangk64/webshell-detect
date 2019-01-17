rule Backdoor_Webshell_PHP_000032
{
    meta:
        description = "devilshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "echo shell_exec($_POST['rc'])"
        $b = "if($_GET['u']=='logout')"
        $c = "if(isset($_SESSION['a'])&& !isset($_GET['edit']))"
        $d = "$pv=@phpversion()"
        $e = "@ini_set('max_execution_time',0)"
        
    condition:
        all of them
}
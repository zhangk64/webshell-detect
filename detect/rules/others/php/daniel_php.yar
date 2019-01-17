rule Backdoor_Webshell_PHP_000029
{
    meta:
        description = "daniel php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if ($onoff != 1) {@extract($_POST, EXTR_SKIP);@extract($_GET, EXTR_SKIP)"
        $b = "dirtree($_POST['dir'],$_POST['mm'])"
        $c = "$dbusername = isset($_POST['dbusername']) ? $_POST['dbusername'] : 'root'"
        $d = "$cdrec .= pack('v', strlen($name) ).pack('v', 0 ).pack('v', 0 )"
        $e = "while($f=readdir($tempdir)){ if($f==\".\"||$f==\"..\")continue;  find(\"$path/$f\");}"
        
    condition:
        all of them
}
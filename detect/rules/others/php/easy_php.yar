rule Backdoor_Webshell_PHP_000034
{
    meta:
        description = "easy php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "foreach($_POST as $key => $val) $$key = $val"
        $b = "$seletefunc==\"shell_exec\")?shell_exec($shellcmd):(($seletefunc==\"passthru\")?passthru($shellcmd):system($shellcmd))))"
        $c = "echo $out=@fwrite($fd,$editfiletext)"
        $d = "if(!@rmdir($TagDir)) return false"
        $e = "if(file_exists($path)) return true"
        
    condition:
        all of them
}
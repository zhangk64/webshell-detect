rule Backdoor_Webshell_PHP_000549
{
    meta:
        description = "wpes"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$cmd = $_POST['cmd']"
        $b = "$results = shell_exec(\"$cmd 2>/dev/stdout\")"
        $c = "elseif($_POST['execType'] == \"passthru\")"
        $d = "$results = shell_exec(\"$cmd 2>/dev/stdout\")"
        
    condition:
        all of them
}
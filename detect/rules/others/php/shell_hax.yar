rule Backdoor_Webshell_PHP_000524
{
    meta:
        description = "shell hax"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "function create_directory($folder)"
        $b = "$handle = fopen($file, 'w') or die('failed<br />')"
        $c = "$ext = pathinfo($shell, PATHINFO_EXTENSION)"
        $d = "if (isset($_REQUEST['cmd']))"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000529
{
    meta:
        description = "simshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (empty($_SESSION['cwd']) || !empty($_REQUEST['reset']))"
        $b = "$p = proc_open($_REQUEST['command']"
        $c = "echo rtrim($padding . $_SESSION['output'])"
        $d = "var command_hist = new Array(<?php echo $js_command_hist ?>)"
        
    condition:
        all of them
}
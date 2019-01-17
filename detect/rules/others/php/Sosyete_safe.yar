rule Backdoor_Webshell_PHP_000531
{
    meta:
        description = "sosyete safe"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$fuck=shell_exec($_POST[sosyete])"
        $b = "$fuck=shell_exec($_POST['sosyete'])"
        $c = "$mokoko=shell_exec($_POST[fuck])"
        $d = "$mokoko=shell_exec($_POST['fuck'])"
        $e = "<span lang=\"en-us\">"
        $f = "print_r('"
        
    condition:
        ($a and $c and $e and $f) or ($b and $d and $e and $f)
}
rule Backdoor_Webshell_PHP_000074
{
    meta:
        description = "lizozim"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "print_r('"
        $b = "$liz0zim=shell_exec($_POST[liz0])"
        $c = "$server=shell_exec('uname -a')"
        $d = "echo $liz0zim"
        
    condition:
        all of them
}
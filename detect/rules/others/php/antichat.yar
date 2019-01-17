rule Backdoor_Webshell_PHP_000003
{
    meta:
        description = "antichat"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "echo eval($_POST['phpev'])"
        $b = "version 1.3 by Grinay"
        $c = "version 1.5 by Grinay"
        $d = "$fp = popen($cmd,\"r\")"
        $e = "($file = readdir($dh)) !== false"
        
    condition:
        ($a and $c) or ($b and $d and $e)
}
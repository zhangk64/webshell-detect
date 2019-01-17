rule Backdoor_Webshell_PHP_000491
{
    meta:
        description = "password hasher for php shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "Password Hasher for PHP Shell 2.1"
        $b = "$hash = $fkt . ':' . $salt . ':' . $fkt($salt . $password)"
        
    condition:
        all of them
}
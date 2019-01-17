rule Backdoor_Webshell_PHP_000492
{
    meta:
        description = "phantasmal new cmd"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if ($chdir == \"\") $chdir = getcwd( )"
        $b = "$fe = \"system\""
        $c = "$fe(\"$cmd  2>&1\")"
        $d = "$values = count($port)"
        $e = "$service = Getservbyport($port[$cont],\"tcp\")"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000515
{
    meta:
        description = "safeover"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", $file )))"
        $b = "echo system(\"$file\");"
        $c = "$safemodgec = shell_exec($evilc0der);"
        $d = "$evilc0der=$_POST['dizin'];"
        $e = "echo system(\"$file\")"
        
    condition:
        all of them
}

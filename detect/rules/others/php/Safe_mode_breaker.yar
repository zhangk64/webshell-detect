rule Backdoor_Webshell_PHP_000516
{
    meta:
        description = "safe mode breaker"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "set_error_handler(\"eh\");"
        $b = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
        $c = "foreach($D as $item) echo \"{$item}\\n\""
        $d = "{$chars[$i]}{$chars[$j]}{$chars[$p]}\""
        $e = "if (@ini_get(\"safe_mode\") or strtolower(@ini_get(\"safe_mode\")) == \"on\")"
        $f = "$free = @diskfreespace($dir);"
        $g = "$tekst = fread($zrodlo, filesize($temp))"
        $h = "$all = @disk_total_space($dir);"
        
    condition:
        ($a and $b and $c and $d) or ($e and $f and $g and $h)
}

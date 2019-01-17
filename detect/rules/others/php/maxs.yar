rule Backdoor_Webshell_PHP_000476
{
    meta:
        description = "maxs"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if(isset($res))"
        $b = " <?echo $nh;?>"
        $c = "if(isset($res)&&$count>=1)"
        $d = "$d = strtolower($ex[$i])"
        $e = "for($i=0;$i<=$count;$i++)"
        $f = "if(strstr($d,\"yahoo\")   || strstr($d,\"ymail\"))"
        
    condition:
        all of them
}
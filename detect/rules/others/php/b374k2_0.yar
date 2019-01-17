rule Backdoor_Webshell_PHP_000007
{
    meta:
        description = "b374k ver2"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval(\"?>\".gzinflate(base64_decode"
        $b = "eval(\"\\$x=gzin\".\"flate(base\".\"64_de\"."
        $c = "create_function('$x,$y','ev'.'al'.'(\"\\$s_pass=\\\"$y\\\";?>\".gz'.'inf'.'late'.'( bas'.'e64'.'_de'.'co'.'de($x)));'"
        
    condition:
        any of them
}
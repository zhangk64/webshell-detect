rule Backdoor_Webshell_PHP_000051
{
    meta:
        description = "go cgi"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if ($param{pwd} ne $pwd){print \"user invalid, please replace user\";}"
        $b = "print \"cd $param{dir}&&$param{cmd}\";"
        $c = "if (!defined$param{dir}){$param{dir}=\"/\"};"
        $d = "foreach $pair (@pairs)"
        
    condition:
        all of them
}
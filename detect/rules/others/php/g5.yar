rule Backdoor_Webshell_PHP_000043
{
    meta:
        description = "g5"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$sd = stripcslashes($_POST['evac'])"
        $b = "@eval($sd)"
        $c = "<?php"
        $d = "if(isset($_REQUEST[\"sqconf\"]) or isset($_REQUEST[\"msq1\"])){head('black')"
        $e = "@set_time_limit(0)"
        $f = "if(version_compare(phpversion(), '4.1.0') == -1)"
        
    condition:
        all of them
}
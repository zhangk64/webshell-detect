rule Backdoor_Webshell_PHP_000471
{
    meta:
        description = "lolipop beta"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<?php"
        $b = "error_reporting(0)"
        $c = "$uname = php_uname()"
        $d = "echo \"<center><table border=0 width='100%'>"
        $e = "<input type=submit value='Kay Gitsin!' ></form></center></td></tr></table></center>"
        $f = "if (!empty($mybb_dbh) && !empty($mybb_dbu) && !empty($mybb_dbn) && !empty($mybb_index)) "
        
    condition:
        all of them
}
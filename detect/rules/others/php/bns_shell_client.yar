rule Backdoor_Webshell_PHP_000012
{
    meta:
        description = "bns shell client"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<?php echo $_SERVER[\"REMOTE_ADDR\"]; ?>"
        $b = "<?php echo $expected_result; ?>"
        $c = "if (isset($_POST[\"exec\"]))"
        $d = "BnS Shell Client"
        
    condition:
        all of them
}
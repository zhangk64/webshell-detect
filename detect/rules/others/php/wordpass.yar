rule Backdoor_Webshell_PHP_000547
{
    meta:
        description = "wordpass"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$target = $_POST['ip'];"
        $b = "$sites = mbing(\"ip:$target index.php?option=com\");"
        $c = "$sites = mbing(\"ip:$target $dork\");"
        $d = "$targets = implode(\"\\n\",cln_arr(array_map(\"jos_site\",$sites)));"
        $e = "$targets = implode(\"\\n\",cln_arr(array_map(\"wp_site\",$sites)));"
        $f = "<?php"
        
    condition:
        ($a and $c and $e and $f) or ($a and $b and $d and $f)
}
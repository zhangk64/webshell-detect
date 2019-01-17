rule Backdoor_Webshell_PHP_000486
{
    meta:
        description = "news php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (isset($_POST['url']))"
        $b = "$sql = urlencode($sql)"
        $c = "<?php echo \"$_SERVER[PHP_SELF]\" ; ?>"
        $d = "$outfile = $_POST ['outfile']"
        
    condition:
        all of them
}
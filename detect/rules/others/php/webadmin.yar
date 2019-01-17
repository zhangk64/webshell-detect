rule Backdoor_Webshell_PHP_000543
{
    meta:
        description = "webadmin"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$dir = relative2absolute($dir, $_POST['olddir'])"
        $b = "chdir(dirname($file))"
        $c = "quicksort($list, 0, sizeof($list) - 1, $key)"
        $d = "quicksort($dirs, 0, sizeof($dirs) - 1, $key)"
        $e = "unction listing_page ($message = null)"
        
    condition:
        ($a and $b and $c and $e) or ($a and $b and $d and $e)
}
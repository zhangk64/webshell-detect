rule Backdoor_Webshell_PHP_000477
{
    meta:
        description = "moroccan spamers"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "$message = ereg_replace(\"%5C%22\", \"%22\", $message)"
        $a2 = "$a5 = $_SERVER['HTTP_REFERER']"
        $a3 = "Moroccan Spamers Ma-EditioN By GhOsT"
        $a4 = "john.barker446@gmail.com"
        $b1 = "$_POST['emailz'] && $_POST['wait']"
        
    condition:
        ($a1 and $b1) or (all of ($a*))
}

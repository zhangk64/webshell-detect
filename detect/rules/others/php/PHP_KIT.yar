rule Backdoor_Webshell_PHP_000502
{
    meta:
        description = "php kit"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if($_GET['cmd']) "
        $b = "system($_GET['cmd']);"
        $c = "<?"
        
    condition:
        all of them
}
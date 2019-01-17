rule Backdoor_Webshell_PHP_000027
{
    meta:
        description = "cyber shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (!empty($_GET[downloadfile])) downloadfile($_GET[downloadfile])"
        $b = "switch (ext($files[$i]))"
        $c = "if (isset($_SESSION[limit]) and ($_SESSION[limit] !== \"0\"))"
        $d = "if (!empty($_GET[mailfile])) anonim_mail($email,$email,$_GET[mailfile],'File: '.$_GET[mailfile],$_GET[mailfile])"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000068
{
    meta:
        description = "ka ushell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$uploadfile = $_POST['path'].$_FILES['file']['name']"
        $b = "if (copy($_FILES['file']['tmp_name'], $uploadfile))"
        $c = "if (empty($_POST['wser'])) {$wser = \"whois.ripe.net\";} else $wser = $_POST['wser']"
        $d = "$fp = fsockopen($wser, 43)"
        $e = "<?php"
        
    condition:
        all of them
}
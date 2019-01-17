rule Backdoor_Webshell_PHP_000485
{
    meta:
        description = "newsletter"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$testa = $_POST['veio']"
        $b = "if(mail($email[$i], $subject.$data, $message.$boundary.$boundary, $headers))"
        $c = "<?php echo $_SERVER['SERVER_ADMIN']; ?>"
        $d = "if($testa != \"\")"
        
    condition:
        all of them
}
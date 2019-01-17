rule Backdoor_Webshell_PHP_000072
{
    meta:
        description = "lifka shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "system($_GET['cmd'])"
        $b = "if (copy($_POST['archivo'],$_POST['nuevo']))"
        $c = "<?php"
        $d = "if ($descargar <> \"\" )"
        $e = "if (get_magic_quotes_gpc() == \"1\" or get_magic_quotes_gpc() == \"on\")"
        
    condition:
        all of them
}
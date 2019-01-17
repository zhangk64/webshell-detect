rule Backdoor_Webshell_PHP_000009
{
    meta:
        description = "bao cun wen jian"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$fp = @fopen($_POST['file'],'wb');"
        $b = "if(isset($_POST['file']))"
        $c = "if(get_magic_quotes_gpc()) foreach($_POST as $k=>$v) $_POST[$k] = stripslashes($v)"
        $d = "<?php"
        
    condition:
        all of them
}
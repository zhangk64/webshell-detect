rule Backdoor_Webshell_PHP_000047
{
    meta:
        description = "gfs"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$file=fopen($_POST['fname'],\"r\")"
        $b = "$filedump=fread($file,filesize($_POST['fname']))"
        $c = "$eval=str_replace(\"<?\",\"\",$_POST['php_eval'])"
        $d = "eval($eval)"
        $e = "echo (rep_char(\"&nbsp\",15))"
        
    condition:
        all of them
}
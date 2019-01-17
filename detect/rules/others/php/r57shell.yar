rule Backdoor_Webshell_PHP_000512
{
    meta:
        description = "r57shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$eval = @str_replace(\"<?\",\"\",$_POST['php_eval'])"
        $b = "$eval = @str_replace(\"<?\", \"\", $_POST['php_eval'])"
        $c = "@eval($eval)"
        $d = "eval($eval)"
        $e = "<?php"
        $f = "set_magic_quotes_runtime(0)"
        $g = "set_time_limit(0)"
        $h = "echo \"\".passthru($HTTP_POST_VARS['cmd']).\"\""
        $i = "$aliases=array"
        
    condition:
        ($a and $c and $e and $f and $g) or ($b and $d and $e and $f and $g) or ($f and $g and $h and $i)
}

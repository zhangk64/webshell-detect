rule Backdoor_Webshell_PHP_000026
{
    meta:
        description = "crystal"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "@eval(stripslashes($_POST['phpcode']));"
        $b = "echo  error_log(\""
        $c = "@set_magic_quotes_runtime(0)"
        $d = "<? echo getcwd();?>"
        
    condition:
        all of them
}
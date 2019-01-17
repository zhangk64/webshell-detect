rule Backdoor_Webshell_PHP_000526
{
    meta:
        description = "simattacker"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$cmd=$_POST['cmd'];"
        $b = "$result=shell_exec(\"$cmd\");"
        $c = "$fedit=realpath($fedit);"
        $d = "$filepath=realpath($_POST['filepath'])"
        $e = "if ($savefile <> \"\")"
        
    condition:
        all of them
}

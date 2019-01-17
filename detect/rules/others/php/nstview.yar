rule Backdoor_Webshell_PHP_000488
{
    meta:
        description = "nstview"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval($_POST['php_ev_c'])"
        $b = "$cmd = $_POST['cmd']"
        $c = "!@move_uploaded_file($_FILES['f']['tmp_name'], $_POST['wup'].\"/\".$_FILES['f']['name'])"
        $d = "phpinfo()"
        
    condition:
        all of them
}
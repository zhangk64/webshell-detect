rule Backdoor_Webshell_PHP_000075
{
    meta:
        description = "loaderzwebshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "@$cmd = $_POST['cmd']"
        $b = "@eval(stripslashes($_POST['phpcode']))"
        $c = "exec(\"perl \" . $_POST['installpath'])"
        $d = "$data = implode(\"\", file($_POST['filefrom']))"
        
    condition:
        all of them
}
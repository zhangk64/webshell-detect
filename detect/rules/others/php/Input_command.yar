rule Backdoor_Webshell_PHP_000061
{
    meta:
        description = "input command"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$pwddir = $_POST['dir']"
        $b = "passthru($cmd)"
        $c = "Uploader file :</font></div>"
        
    condition:
        all of them
}
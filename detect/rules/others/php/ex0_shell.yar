rule Backdoor_Webshell_PHP_000038
{
    meta:
        description = "ex0_shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "eval(stripslashes(trim($_REQUEST['eval'])))"
        $b = "$fp=fopen ($_REQUEST['edit'],\"w\")"
        $c = "fwrite ($fp,\"use Socket"
        $d = "$nedittxt=stripslashes($_REQUEST['edittxt'])"
        $e = "fwrite ($fp,$nedittxt)"
        
    condition:
        all of them
}
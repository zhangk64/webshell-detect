rule Backdoor_Webshell_PHP_000490
{
    meta:
        description = "otto"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "@system($_POST['cmd'])"
        $b = "$result=@fwrite($fp,$_POST['newcontent'])"
        $c = "@rename($oldname,$_POST['newname'])"
        
    condition:
        all of them
}
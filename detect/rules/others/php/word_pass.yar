rule Backdoor_Webshell_PHP_000548
{
    meta:
        description = "word pass"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "echo \"\".passthru($_POST['cmd']).\"\""
        $b = "if ((!$_POST['dir']) OR ($_POST['dir']==\"\"))"
        $c = "echo \"<input type=hidden name=dir size=70 value=\".exec(\"pwd\").\">\""
        $d = "<? if (($_POST['dir']!==\"\") AND ($_POST['dir'])) { chdir($_POST['dir']); } ?>"
        
    condition:
        all of them
}
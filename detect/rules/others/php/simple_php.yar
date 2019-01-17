rule Backdoor_Webshell_PHP_000528
{
    meta:
        description = "simple"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$text=\"\\$etext=\\\"<html><head><title>Simple PHP Mysql client</title></head>"
        $b = "if(!empty($_POST['db'])){@mysql_select_db($_POST['db'])or die(eval($text.\";echo \\$etext.\\\"</form>Could not select db<br>\\\";\"));}"
        $c = "<?php"
        $d = ".(isset($_POST['dd'])?"
        
    condition:
        all of them
}
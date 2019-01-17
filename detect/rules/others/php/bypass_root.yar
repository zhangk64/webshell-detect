rule Backdoor_Webshell_PHP_000015
{
    meta:
        description = "bypass root"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (isset($_POST['Donnazmi'])){ system('ln -s / Donnazmi.txt');"
        $b = "echo \"</form>\";  ?>"
        $c = "echo \""
        $d = "<?php"
        
    condition:
        all of them
}
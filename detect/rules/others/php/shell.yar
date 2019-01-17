rule Backdoor_Webshell_PHP_000522
{
    meta:
        description = "shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "if(rename($_POST['fileold'],$_POST['filenew']))"
        $a2 = "$sql = $_POST['query'];"
        $a3 = "exec($command,$result)"
        $a4 = "$result = mysql_query($sql);"
        
        $b1 = "if(!@move_uploaded_file(@$_FILES['f']['tmp_name'], $_POST['p3'].@$_FILES['f']['name']))"
        $b2 = "if (!function_exists(\"posix_getpwuid\")"
        $b3 = "echo '"
        $b4 = "<?php"
        
    condition:
        all of ($a*) or all of ($b*)
}
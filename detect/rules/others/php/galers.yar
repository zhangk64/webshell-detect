rule Backdoor_Webshell_PHP_000044
{
    meta:
        description = "galers"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "GaLers xh3LL"
        $b = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />"
        $c = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';"
        $d = "<font color=\"red\">File Upload Error ~_~.</font>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000030
{
    meta:
        description = "dark shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$current = htmlentities ($_SERVER ['PHP_SELF'] . \"?dir=\" . $dir);"
        $b = "if (unlink ($file))"
        $c = "if(move_uploaded_file($temp,$file))"
        $d = "$dir = $_GET ['dir'];"
        $e = "$file = $_GET ['file'];"
        
    condition:
        all of them
}
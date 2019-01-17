rule Backdoor_Webshell_PHP_000002
{
    meta:
        description = "allahshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<?php"
        $b = "$style = '<style type=\"text/css\">"
        $c = "fwrite($fh, $dt);"
        $d = "$file = $_POST['filetosave']"
        $e = "$fh = fopen($file, 'w')"
        $f = "$dt = $_POST['filecontent']"
        $h = "$functions = array('Clear Screen' => 'ClearScreen()'"
        $i = "set_time_limit(9999999)"
        
    condition:
        all of them
}
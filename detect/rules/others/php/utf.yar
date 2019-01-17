rule Backdoor_Webshell_PHP_000539
{
    meta:
        description = "utf"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "move_uploaded_file/*;*/($_FILES[\"filename\"][\"tmp_name\"], $_FILES[\"filename\"][\"name\"])"
        $b = "echo $_SERVER['REMOTE_ADDR']"
        $c = "touch/*;*/($filename, $time)"
        $d = "<?php"
        
    condition:
        all of them
}
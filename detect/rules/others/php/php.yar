rule Backdoor_Webshell_PHP_000493
{
    meta:
        description = "php shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$size = @filesize(\"$downloadfile\")"
        $b = "if (function_exists('is_dir'))"
        $c = "$dir_handle = opendir($work_dir)"
        $d = "while ($dir = readdir($dir_handle))"
        $e = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\""
        
    condition:
        all of them
}
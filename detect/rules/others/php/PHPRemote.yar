rule Backdoor_Webshell_PHP_000497
{
    meta:
        description = "php remote"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (function_exists(\"ob_start\") && (!isset($c) || $c!=\"md5crack\")) ob_start(\"ob_gzhandler\");"
        $b = "$out.=\"<a href=$self?c=l&d=\".urlencode($paths[$i]).\" class=white>\";"
        $c = "if (!realpath($d.$f) || !file_exists($d.$f)) exit(\"\".mm(\"file not found\").\"\");"
        $d = "echo \"<h3>\".mm(\"Deleting all dir/files (recursive) in\").\" <tt>$df</tt> ...</h3>\";"
        
    condition:
        all of them
}
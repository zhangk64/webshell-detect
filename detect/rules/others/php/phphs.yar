rule Backdoor_Webshell_PHP_000494
{
    meta:
        description = "phphs"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$mysql_files_str = \"/etc/passwd:/proc/cpuinfo:/etc/resolv.conf:/etc/proftpd.conf\""
        $b = "TEXTAREA { background:333333; color:CCCCCC; font-family:Verdana; font-size:8pt;}"
        $c = "echo \"<script> alert(\\\"unable to read file: $file using: file\\\"); </script>\""
        $d = "or die(\"Error uploading file\".$HTTP_POST_FILES[\"userfile\"][name]);"
        
    condition:
        all of them
}
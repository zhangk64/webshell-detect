rule Backdoor_Webshell_PHP_000040
{
    meta:
        description = "fileupload"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<table width=\"389\" border=\"1\">"
        $b = "$_FILES[\"pictures\"][\"tmp_name\"]"
        $c = "<?php eval(gzuncompress("
        $d = "<title>This shit works!</title>"
        
    condition:
        ($a and $b) or ($c and $d)
}
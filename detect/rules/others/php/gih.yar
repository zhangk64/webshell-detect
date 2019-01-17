rule Backdoor_Webshell_PHP_000048
{
    meta:
        description = "gih"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<?php"
        $b = "if (isset($_POST['eval'])){echo \"\\n result is:<br/><br/>\";eval($_POST['eval'])"
        $c = "$wrpath = $_POST['ffile']; $wrcont = $_POST['wrcont'];$fh = fopen($wrpath, 'w');if ($fh){fwrite($fh, $wrcont);fclose($fh);"
        $d = "while (($file=readdir($dir))!==false) { if ($file==\".\" || $file==\"..\") continue;"
        $e = "if (is_link($path.\"/\".$files[$i])) {$size = \"---\";} else {$size = filesize($path.\"/\".$files[$i]); $size = conv_size($size);"
        
    condition:
        all of them
}
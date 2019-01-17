rule Backdoor_Webshell_PHP_000551
{
    meta:
        description = "xindong"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (empty($lujin) || empty($neirong)) {"
        $b = "@fwrite($fh,$neirong);"
        $c = "</b><br /> <textarea name=\"neirong\" style=\"width:500px; height:400px;\"></textarea><hr/>"
        $d = "$neirong = @$_POST['neirong'];"
        
    condition:
        all of them
}
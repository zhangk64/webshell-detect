rule Backdoor_Webshell_PHP_000541
{
    meta:
        description = "vp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$fixedPath .=  ($firstPiece ? '' : $slash) . $val"
        $b = "echo (@chmod ( $_REQUEST['chm'] , 0777 ) ? \"Reassigned\" : \"Can't Reasign\")"
        $c = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]))"
        
    condition:
        all of them
}
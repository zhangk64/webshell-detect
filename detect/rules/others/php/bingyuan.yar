rule Backdoor_Webshell_PHP_000011
{
    meta:
        description = "bingyuan"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "#lujing{font-family:Georgia;width:389px;border=#0000 1px solid}"
        $b = "<input type=\"text\" name=\"lujing\" id=\"lujing\" value='<?php echo $_SERVER[\"SCRIPT_FILENAME\"]?>' />"
        $c = "#neirong{width:558px;height:250px;border=#0000 1px solid}"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000496
{
    meta:
        description = "php proxy"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "PHProxy</a> <?php echo $GLOBALS['_version'] ?>"
        $b = "Remove client-side scripting (i.e JavaScript)"
        $c = "Web Address <input id=\"address_box\" type=\"text\" name=\"<?php echo $GLOBALS['_config']['url_var_name'] ?>"
        
    condition:
        all of them
}
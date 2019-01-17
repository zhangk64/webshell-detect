rule Torjan_webshell_fire2013_php
{
    meta:
        description = "PHP Webshell Maybe False Positives"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-07-18"
        
    strings:
        $a = "eval(\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61"
        $b = "yc0CJYb+O//Xgj9/y+U/dd//vkf'\\x29\\x29\\x29\\x3B\")"
        
    condition:
        all of them
}

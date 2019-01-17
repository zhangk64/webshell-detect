rule Torjan_webshell_anuna_php
{
    meta:
        description = "PHP Webshell Maybe False Positives"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-07-18"
        
    strings:
        $a = /<\?php \$[a-z]+ = '/
        $b = /\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/
        $c = /\$[a-z]+=\([0-9]+[-+][0-9]+\)/
        $d = /if \(!function_exists\('[a-z]+'\)\)/
        
    condition:
        all of them
}

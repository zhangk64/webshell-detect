rule Torjan_webshell_chinese_spam_spreader_php
{
    meta:
        description = "Chinese Spam Spreader"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-07-18"
        
    strings:
        $a = "User-Agent: aQ0O010O"
        $b = "<font color='red'><b>Connection Error!</b></font>"
        $c = /if ?\(\$_POST\[Submit\]\) ?{/
        
    condition:
        all of them
}
rule Torjan_webshell_chinese_spam_echoer_php
{
    meta:
        description = "Chinese Spam Echoer"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-07-18"
        
    strings:
        $a = "set_time_limit(0)"
        $b = "date_default_timezone_set('PRC');"
        $c = "$Content_mb;"
        $d = "/index.php?host="
        
    condition:
        all of them
}

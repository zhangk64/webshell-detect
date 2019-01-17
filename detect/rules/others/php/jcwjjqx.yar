rule Backdoor_Webshell_PHP_000063
{
    meta:
        description = "jcwjjqx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "C:\\Documents and Settings\\All Users\\Application Data\\McAfee\\DesktopProtection<br>"
        $b = "<body bgcolor=\"#000000\" text=\"#FFFFFF\">"
        $c = "while($fileName=@readdir($dir_handle)){"
        $d = "c:\\Program Files\\Microsoft SQL Server\\90\\Shared\\ErrorDumps<br>"
        
    condition:
        all of them
}
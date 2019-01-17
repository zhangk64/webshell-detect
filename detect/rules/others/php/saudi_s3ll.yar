rule Backdoor_Webshell_PHP_000518
{
    meta:
        description = "saudi s3ll"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$port = $_POST['port']"
        $b = "$sockfd=fsockopen($ip , $port , $errno, $errstr );"
        $c = "$command= fgets($sockfd, $len);"
        $d = "fputs($sockfd , \"\\n\" . shell_exec($command) . \"\\n\\n\");"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000521
{
    meta:
        description = "serv u"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$path=str_replace('\\\\','/',$_POST['path'])"
        $b = "$upfile=$_POST['p'].$_FILES['file']['name'];"
        $c = "if (!$conn_id)"
        $d = "fputs ($fp, \"-SessionTimeOut=-1\\r\\n\");"
        $e = "echo \"$errstr ($errno)<br>\\n\";"
        
    condition:
        all of them
}
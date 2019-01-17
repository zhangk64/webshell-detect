rule Backdoor_Webshell_PHP_000495
{
    meta:
        description = "php jackal"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$combo=trim(fgets($dictionary),\" \\n\\r\")"
        $b = "$ser=fsockopen($server,43,$en,$es,5)"
        $c = "$ser=getservbyport($po,\"tcp\")"
        $d = "$domain=$_REQUEST['domain'].\"\\r\\n\""
        $e = "fwrite($filehandle,$_REQUEST['edited'])"
        $f = "move_uploaded_file($_FILES['uploadfile']['tmp_name'],$_FILES['uploadfile']['name'])"
        
    condition:
        all of them
}
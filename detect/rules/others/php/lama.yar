rule Backdoor_Webshell_PHP_000071
{
    meta:
        description = "lama"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<title>lama's'hell v. 3.0</title>"
        $b = "echo \"There was an error uploading the file, please try again!\""
        $c = "<center><h1>Linux Shells</h1></center>"
        $d = "if( $_FILES['_upl']['error'] != UPLOAD_ERR_OK )"
        
    condition:
        ($a and $b) or ($c and $d)
}
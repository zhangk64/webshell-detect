rule Backdoor_Webshell_PHP_000504
{
    meta:
        description = "kit up"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name']))"
        $b = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile'])"
        $c = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name']"
        $d = "<?"
        
    condition:
        all of them
}
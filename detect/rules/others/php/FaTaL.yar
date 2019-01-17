rule Backdoor_Webshell_PHP_000039
{
    meta:
        description = "fatal"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        //$a = "eval(base64_decode("
        $b = "isset($_POST['phpev']))$content.=eval($_POST['phpev'])"
        $c = "$file=$_POST['file']"
        $d = "move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)"
        $e = "@system($cmd)"
        
    condition:
        all of them
}
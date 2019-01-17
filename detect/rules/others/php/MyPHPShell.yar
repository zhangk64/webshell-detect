rule Backdoor_Webshell_PHP_000479
{
    meta:
        description = "myphpshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "@error_reporting(0)"
        $b = "fwrite($fp,$content)"
        $c = "move_uploaded_file( $_FILES['file']['tmp_name'], $_POST['file_path'])"
        
    condition:
        all of them
}
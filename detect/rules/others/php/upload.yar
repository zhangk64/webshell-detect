rule Backdoor_Webshell_PHP_000537
{
    meta:
        description = "upload"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "@move_uploaded_file($userfile_tmp, $qx)"
        $b = "if(isset($_FILES['image']['name']))"
        $c = "$qx = $filedir.$userfile_name"
        $d = "<?php"
        
    condition:
        all of them
}
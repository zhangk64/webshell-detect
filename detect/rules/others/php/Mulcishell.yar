rule Backdoor_Webshell_PHP_000478
{
    meta:
        description = "mulcishell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "@mkdir($_POST['newdir'])"
        $b = "echo eval(stripslashes($_POST['phpcode']))"
        $c = "eval(base64_decode("
        $d = "fputs($conn_url,$header,strlen($header))"
        $e = "@fputs($domain_handle,$header,strlen($header))"
        $f = "@fwrite($fh,stripslashes($_POST['file_contents']),strlen($_POST['file_contents']))"
        $g = "@fwrite($fh,\"<?php @eval(\\$_GET['e']) ?>\")"
        $h = "@move_uploaded_file($_FILES['u_file']['tmp_name'],$dir.'/'.$name)"
        $i = "@copy($_POST['file_bypass'],$_POST['dest'])"
        
    condition:
        all of them
}
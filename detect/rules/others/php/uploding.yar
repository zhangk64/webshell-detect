rule Backdoor_Webshell_PHP_000538
{
    meta:
        description = "uploading"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])"
        $a2 = "if( $_POST['_upl'] == \"Upload\" )"
        $a3 = "echo '"
        $a4 = "<?php"
        $a5 = "<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>"
        
        $b1 = "if ($_POST[\"pt\"]==\"\"){$uploadfile = $_FILES[\"file\"][\"name\"];}"
        $b2 = "if (copy($_FILES[\"file\"][\"tmp_name\"], $uploadfile))"
        $b3 = "$c=$_GET['cmd']"
        $b4 = "system($c)"
        
    condition:
        ($a1 and $a2 and $a3 and $a4) or ($a2 and $a3 and $a4 and $a5) or all of ($b*)
}

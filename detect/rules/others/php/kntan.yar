rule Backdoor_Webshell_PHP_000069
{
    meta:
        description = "kntan"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (file_exists($target) && get_filesize($target) <= 100000)"
        $b = "if(move_uploaded_file($file['tmp_name'],$temp_file_pre.$chunk))"
        $c = "if (!$dh = opendir($path)) return false"
        $d = "while (($file = readdir($dh)) !== false)"
        $e = "$chunk = isset($_REQUEST[\"chunk\"]) ? intval($_REQUEST[\"chunk\"]) : 0"
        $f = "$temp_file_pre = $temp_path.md5($temp_path.$file_name).'.part'"
        
    condition:
        all of them
}
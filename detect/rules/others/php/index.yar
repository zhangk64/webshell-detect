rule Backdoor_Webshell_PHP_000059
{
    meta:
        description = "index"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "class backdoor"
        $b = "if(unlink($this->del))"
        $c = "$this->file = htmlentities(highlight_file($this->file))"
        $d = "if(is_file($this->del))"
        $e = "$backdoor->ccopy($cfichier,$cdestination)"
        
    condition:
        all of them
}
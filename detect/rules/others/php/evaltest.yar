rule Backdoor_Webshell_PHP_000037
{
    meta:
        description = "evaltest"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-5"
        
    strings:
        $a ="return $type.$owner['read'].$owner['write'].$owner['execute'].$group['read'].$group['write'].$group['execute']"
        $b ="$dir_writeable = @is_writable($cwd) ? 'Writable' : 'Non-writable'"
        $c ="$dirdata=$filedata=array()"
        $d ="function getext($file)"
        
    condition:
        all of them
}
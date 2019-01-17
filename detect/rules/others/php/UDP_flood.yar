rule Backdoor_Webshell_PHP_000536
{
    meta:
        description = "udp flood"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$ip = $_SERVER['REMOTE_ADDR']"
        $b = "if(isset($_GET['host'])&&isset($_GET['time']))"
        $c = "$max_time = $time+$exec_time"
        $d = "ignore_user_abort(TRUE)"
        
    condition:
        all of them
}
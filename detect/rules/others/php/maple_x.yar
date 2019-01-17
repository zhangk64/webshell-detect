rule Backdoor_Webshell_PHP_000475
{
    meta:
        description = "maple_x"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$system=strtoupper(substr(PHP_OS, 0, 3))"
        $b = "if(($sock=socket_create(AF_INET,SOCK_STREAM,$proto))<0)"
        $c = "$process = proc_open($cmd, $descriptorspec, $pipes, $cwd, $env)"
        $d = "$msg=stream_get_contents($pipes[2])"
        $e = "if(($ret=socket_connect($sock,$host,$port))<0)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000054
{
    meta:
        description = "hacker"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$asse=$asse{0}.$asse{1}.$asse{1}.$asse{2}.$asse{3}.$asse{4}"
        $b = "@$asse($_POST[$_GET['s']])"
        $c = "$system=strtoupper(substr(PHP_OS, 0, 3))"
        $d = "if(get_magic_quotes_gpc())"
        $e = "if(isset($_GET['s'])){$s = $_GET['s']"
        
    condition:
        all of them
}
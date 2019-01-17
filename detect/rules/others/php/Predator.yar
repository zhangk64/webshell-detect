rule Backdoor_Webshell_PHP_000511
{
    meta:
        description = "predator"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$pass = fgets($dict)"
        $b = "eval(stripslashes($_POST['value']))"
        $c = "fputs(fopen($_SESSION['filename'],\"w\"),stripslashes($_POST['value']))"
        $d = "fputs($i=fopen('/tmp/shlbck','w'),base64_decode($perl))"
        $e = "fputs($i=fopen('/tmp/shlbck.c','w'),base64_decode($c))"
        
    condition:
        all of them
}
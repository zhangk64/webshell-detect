rule Backdoor_Webshell_PHP_000553
{
    meta:
        description = "xx php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if (!isset($_POST['submit'])) die()"
        $b = "$destination_folder = './';"
        $c = "$url = $_POST['url']; "
        $d = "$newfname = $destination_folder . basename($url);"
        
    condition:
        all of them
}
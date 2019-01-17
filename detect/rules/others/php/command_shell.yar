rule Backdoor_Webshell_PHP_000022
{
    meta:
        description = "command shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$file = $_POST['filetosave']"
        $b = "$fh = fopen($file, 'w')"
        $c = "$dt = $_POST['filecontent']"
        $d = "foreach($functions as $name => $execute)"
        
    condition:
        all of them
}
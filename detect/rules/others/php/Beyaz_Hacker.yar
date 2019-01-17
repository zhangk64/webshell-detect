rule Backdoor_Webshell_PHP_000010
{
    meta:
        description = "beyaz hacker"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$dir = relative2absolute($dir, $_POST['olddir'])"
        $b = "chdir(dirname($file))"
        $c = "echo '<form action=\"' . $self . '\" method=\"post\">"
        $d = "echo '	</p>"
        $e = "quicksort($dirs, 0, sizeof($dirs) - 1, $key);"
        $f = "function listing_page ($message = null)"
        $g = "echo '<h2 style=\"margin-bottom: 3pt\">' . html($file) . '</h2>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000555
{
    meta:
        description = "zorback"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "<input type='text' name='portum' size='5' value='21'><br><br>"
        $b = "$result = \"Error: didnt connect !!!\""
        $c = "fputs ($mucx, $one. system(\"whoami\") .$two. \" \" .$message.\"\\n\")"
        
    condition:
        all of them
}
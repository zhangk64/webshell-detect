rule Backdoor_Webshell_PHP_000008
{
    meta:
        description = "backdoor"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include v1.0</font></p>\");"
        $a2 = "if(!stristr($QS, \"separateur\") && $QS!=\"\") $QS .= \"&separateur\";"
        $a3 = "$code =  $_REQUEST[\"code\"];"
        $a4 = "eval($code)"
        $a5 = "href=\\\"$adresse_locale&option_file=edit&nom=$rep$file"
        
        $b1 = "<head><title>Php Backdoor v 1.0 by ^Jerem</title></head>"
        $b2 = "'Server ip:<b> '.$SERVER_ADDR.'</b> (Running on port<b> '.$SERVER_PORT.'</b>)<br>'"
        $b3 = "echo '<textarea name=\"cmd\" cols=\"50\" rows=\"10\"></textarea><br>'"
        $b4 = "echo 'Your file <b> '.$nfile.' </b> was created susellify<br><br>'"
    condition:
        all of ($a*) or all of ($b*)
}
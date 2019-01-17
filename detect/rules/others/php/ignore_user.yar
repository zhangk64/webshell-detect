rule Backdoor_Webshell_PHP_000058
{
    meta:
        description = "ignore user"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "for ($set=0; $set < $n_emails; $set++)"
        $b = "ignore_user_abort()"
        $c = "function enviando()"
        $d = "$msgrand = str_replace(\"%rand%\", $num1, $mensagem[$msg])"
        
    condition:
        all of them
}
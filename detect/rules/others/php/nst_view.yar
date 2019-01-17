rule Backdoor_Webshell_PHP_000489
{
    meta:
        description = "most"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "passthru(\"nohup perl .nst_datapipe_tmp/nst_perl_datapipe.pl &\")"
        $b = "eval(\"\\$\".$matches3[1][$i].\" = \\\"\".adds2($_POST[$matches3[1][$i]]).\"\\\";\")"
        $c = "eval(eval_sl($_POST['eval']))"
        $d = "passthru(\"nohup perl /tmp/nst_perl_proxy.pl $port &\")"
        $e = "passthru(\"nohup perl .nst_bd_tmp/nst_perl_bd.pl &\")"
        
    condition:
        all of them
}
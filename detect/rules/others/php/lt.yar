rule Backdoor_Webshell_PHP_000474
{
    meta:
        description = "it"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$mail = mail($email_go, $assunto.$data, $mensagem.$boundary.$destino, $headers);"
        $b = "for($x=0; $x<$numemails; $x++)"
        $c = "<?php echo $UNAME = @php_uname(); ?>"
        $d = "if ($enviar)"
        
    condition:
        all of them
}
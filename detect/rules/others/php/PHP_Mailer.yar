rule Backdoor_Webshell_PHP_000505
{
    meta:
        description = "php mailer"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$signoff=create_function('$smtp_conc','return '.substr($range,0).'($smtp_conc);')"
        $b = "$file = tempnam(sys_get_temp_dir(), 'mail')"
        $c = "<title> team p </title>"
        $d = "<title>Pro Mailer V2</title>"
        
    condition:
        ($a and $d) or ($b and $c)
}
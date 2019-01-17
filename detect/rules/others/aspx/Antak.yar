rule Backdoor_Webshell_ASPX_000834
{
    meta:
        description = "antak"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "A Webshell which utilizes powershell"
        $b = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;"
        $c = "Use this shell as a normal powershell console. Each command is executed in a new process, keep this in mind"
        $d = "<title>Antak Webshell</title>"
        
    condition:
        all of them
}
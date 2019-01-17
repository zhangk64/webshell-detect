rule Backdoor_Webshell_ASP_000818
{
    meta:
        description = "refresh"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "option explicit"
        $b = "objMsg.Subject=makeText(Int((50-25+1)*Rnd+25))"
        $c = "objMsg.TextBody=makeText(Int((100-50+1)*Rnd+50))"
        $d = "howlong=FormatNumber(intTime/60,2) & \" minute(s)\""
        $e = "howlong=FormatNumber(intTime/(60*60),2) & \" hour(s)\""
        $f = "Property Get CompressionMethodString()"
        
    condition:
        all of them
}
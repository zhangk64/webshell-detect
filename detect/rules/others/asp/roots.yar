rule Backdoor_Webshell_ASP_000820
{
    meta:
        description = "roots"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="Session(\"FolderPath\")=RRePath(FolderPath)"
        $b ="Sub Scan(targetip, portNum)"
        $c ="If Action=\"\" then o \"scroll=no\""
        $d ="PortArray=WSH.REGREAD(RadminPath & Port )"
        
    condition:
        all of them
}
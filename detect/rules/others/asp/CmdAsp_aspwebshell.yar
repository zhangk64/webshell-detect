rule Backdoor_Webshell_ASP_000679
{
    meta:
        description = "cmd"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")"
        $b = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")"
        $c = "The server's software"
        $d = "thisDir = getCommandOutput(\"cmd /c\" & szCMD)"
        
    condition:
        all of them
}
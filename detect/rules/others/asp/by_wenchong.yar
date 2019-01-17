rule Backdoor_Webshell_ASP_000677
{
    meta:
        description = "modify and hide files"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
    strings:
        $a = "Set shell=Server.CreateObject(\"Shell.Application\")"
        $b = "Set app_path=shell.NameSpace(server.mappath(\".\"))"
        $c = "set path=request.Form(\"path\")"
        $d = "Set shell=Server.CreateObject(\"Shell.Application\")"
        $e = "set path=request.Form(\"path\")"
        
    condition:
        all of them
}
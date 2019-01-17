rule Backdoor_Webshell_ASP_000673
{
    meta:
        description = "Asp Shell Up Client"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "gl.writetext request(\"code\")"
        $b = "gl.SaveToFile server.mappath(request(\"path\")),2 "
        $c = "set gl=nothing"
        $d = "response.redirect request(\"path\")"
        
    condition:
        all of them
}
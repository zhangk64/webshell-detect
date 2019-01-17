rule Backdoor_Webshell_ASP_000823
{
    meta:
        description = "serv u"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "f=gpath()"
        $b = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\" & ftpport & vbCrLf"
        $c = "newdomain = \"-SETDOMAIN\" & vbCrLf & \"-Domain=goldsun|0.0.0.0|\" & ftpport & \"|-1|1|0\" & vbCrLf & \"-TZOEnable=0\" & vbCrLf & \" TZOKey=\" & vbCrLf"
        $d = "if  not isnumeric(action) then response.end"
        
    condition:
        all of them
}
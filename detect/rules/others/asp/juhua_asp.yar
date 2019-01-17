rule Backdoor_Webshell_ASP_000688
{
    meta:
        description = "juhua chat room"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a ="if data<>\"\" then"
        $b ="ff = Request.ServerVariables(\"SCRIPT_NAME\")"
        $c ="Set File=Fs.OpenTextFile(Server.MapPath(ff),8,Flase)"
        $d ="uip=split(uip,\".\",-1,1)"
        
    condition:
        all of them
}
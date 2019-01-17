rule Backdoor_Webshell_ASP_000671
{
    meta:
        description = "aspwebpack"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Session.CodePage = 936"
        $b = "objStream.LoadFromFile Server.MapPath(Request(\"Down\"))"
        $c = "Response.AddHeader \"Content-Disposition\",\"attachment; filename=\" & Request(\"Down\")"
        $d = "Response.BinaryWrite objStream.Read(1024*64)"
        $e = "Session(ScriptName) = Trim(Request(\"PassWord\"))"
        $f = "server.MapPath(\"/\")"
        $g = "Sub sub_Pack(byVal sPath)"
        $h = "Public Function StreamToText(byval stream)"
        
    condition:
        all of them
}
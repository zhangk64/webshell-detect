rule Backdoor_Webshell_ASP_000682
{
    meta:
        description = "cmd shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "function RUNonclick()"
        $b = "If Request(\"writeMode\") = \"True\" Then"
        $c = "If (DSnXA <> \"\") Then"
        $d = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")"
        
    condition:
        all of them
}
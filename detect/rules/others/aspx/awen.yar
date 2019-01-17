rule Backdoor_Webshell_ASPX_000838
{
    meta:
        description = "aspx spy"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<title>awen asp.net webshell</title>"
        $b = "psi.FileName = \"D:\\\\webx\\\\test\\\\upload\\\\cmd.exe\";"
        $c = "Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)))"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASPX_000837
{
    meta:
        description = "aspx shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%@ Page Language=\"C#\" EnableViewState=\"false\" %>"
        $b = "p.StartInfo.FileName = \"cmd.exe\""
        $c = "p.StartInfo.Arguments = \"/c \" + txtCmdIn.Text"
        $d = "p.Start()"
        
    condition:
        all of them
}
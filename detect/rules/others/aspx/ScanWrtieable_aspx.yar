rule Backdoor_Webshell_ASPX_000874
{
    meta:
        description = "scan wrtieable"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<title>ScanWrtieable</title>"
        $b = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>"
        $c = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60px\">"
        $d = "Stopat <asp:TextBox ID=\"TextBox_stopat\" runat=\"server\" Text=\"5\" Width=\"60px\">"
        
    condition:
        all of them
}
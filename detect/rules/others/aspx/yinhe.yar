rule Backdoor_Webshell_ASPX_000881
{
    meta:
        description = "yin he"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<asp:Label ID=\"LbServerNameC\" runat=\"server\" BorderStyle=\"None\"></asp:Label></br>"
        $b = "<asp:Label ID=\"LbLangC\" runat=\"server\"></asp:Label></br>"
        $c = "<asp:Label ID=\"LbReg\" runat=\"server\" Width=\"319px\"></asp:Label>"
        $d = "LbScan.Text +=\"<font color='red'>\"+i.ToString()+\"<font>"
        
    condition:
        all of them
}
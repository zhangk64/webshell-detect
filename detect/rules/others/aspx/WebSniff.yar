rule Backdoor_Webshell_ASPX_000879
{
    meta:
        description = "web sniff"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<asp:Button ID=\"Button_ref\" runat=\"server\" OnClick=\"Refresh_Click\" Text=\""
        $b = "color: #336699"
        $c = "private readonly int _RawLength;"
        $d = "private const uint MAGIC = 0xA1B2C3D4;"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASPX_000875
{
    meta:
        description = "serv u"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<asp:Button id=\"BTN_Start\" onclick=\"BTN_Start_Click\" runat=\"server\" Text=\"Start\"></asp:Button>"
        $b = "Dim returndata As String = Encoding.ASCII.GetString(bytes)"
        $c = "Dim DelDomain As String = \"-DELETEDOMAIN\" & vbcrlf & \"-IP=0.0.0.0\" & vbcrlf & \" PortNo=43859\" & vbcrlf"
        $d = "<asp:TextBox id=\"Text_Name\" runat=\"server\" Width=\"152px\">LocalAdministrator</asp:TextBox>"
        
    condition:
        all of them
}
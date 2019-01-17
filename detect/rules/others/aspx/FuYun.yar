rule Backdoor_Webshell_ASPX_000847
{
    meta:
        description = "an quan fu yun"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<asp:TextBox ID=\"TextBoxReg\" runat=\"server\" Width=\"551px\">HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp</asp:TextBox>"
        $b = "//-------------------Char's Email:Hackexp#126.com----------------------------%>"
        $c = "<table align=\"center\">ASPXb4ckd00r V1.1 By:Char</table>"
        $d = "<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\"  Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>"
        
    condition:
        all of them
}
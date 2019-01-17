rule Backdoor_Webshell_ASPX_000841
{
    meta:
        description = "database connection"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Dim myProcess As New Process()"
        $b = "Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)"
        $c = "myProcessStartInfo.UseShellExecute = false"
        $d = "myProcessStartInfo.RedirectStandardOutput = true"
        $x1 = "<p><asp:Button id=\"Button\" onclick=\"runcmd\" runat=\"server\" Width=\"100px\" Text=\"Run\"></asp:Button>"
        $x2 = "<strong>PARSE WEB.CONFIGS FOR CONNECTION STRINGS</strong></a><Br>"
        
    condition:
        $a and $b and $c and $d and ($x1 or $x2)
}
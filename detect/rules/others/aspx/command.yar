rule Backdoor_Webshell_ASPX_000840
{
    meta:
        description = "command"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = ".FileName = \"cmd.exe\""
        $b = ".Arguments = \"/c \""
        $c = ".RedirectStandardOutput = true"
        $d = ".UseShellExecute = false"
        $x1 = "h1 { font-size: 16px; background-color: #000000; color: #ffffff; padding: 5px; }"
        $x2 = "<td><asp:Button ID=\"btnExecute\" runat=\"server\" OnClick=\"btnExecute_Click\" Text=\"Execute\" /></td>"
        $x3 = "Z-INDEX: 101; LEFT: 405px; POSITION: absolute; TOP: 20px"
        
    condition:
        $a and $b and $c and $d and ($x1 or $x2 or $x3)
}
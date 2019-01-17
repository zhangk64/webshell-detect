rule Backdoor_Webshell_ASPX_000832
{
    meta:
        description = "08xiaozu"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%@ Page Language=\"C#\" Debug=\"true\" trace=\"false\" validateRequest=\"false\" EnableViewStateMac=\"false\" EnableViewState=\"true\"%>"
        $b = "<script runat=\"server\">"
        $c = "protected OleDbCommand Kkvb=new OleDbCommand()"
        $d = "protected OleDbCommand TzH=new OleDbCommand()"
        $e = "ahAE.StartInfo.Arguments=bkcm.Value"
        $f = "UBNAN.StartInfo.Arguments=XwN.Value"
        $g = "ltcpClient=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)"
        
        $a1 = "<%@ Page Language=\"C#\" Debug=\"true\" trace=\"false\" validateRequest=\"false\""
        $b1 = "<script runat=\"server\">"
        $c1 = "if(path.Substring(path.Length - 1, 1)==@\"\\\")"
        $d1 = "if (path.Substring(path.Length - 1, 1) == @\"\\\")"
        $e1 = "Cmdpro.StartInfo.Arguments=Bin_CmdShellTextBox.Text"
        $f1 = "Cmdpro.StartInfo.Arguments = Bin_CmdShellTextBox.Text"
        $g1 = "<%@ import Namespace=\"System.DirectoryServices\" %>"
        
    condition:
        (($a and $b and $c and $e and $g) or ($a and $b and $d and $f and $g) or ($a1 and $b1 and $c1 and $e1 and $g1) or ($a1 and $b1 and $d1 and $f1 and $g1))
}
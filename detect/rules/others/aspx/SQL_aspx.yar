rule Backdoor_Webshell_ASPX_000877
{
    meta:
        description = "sql"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<title>SQL</title>"
        $b = "<head id=\"Head1\" runat=\"server\">"
        $c = "<%@ Page Language=\"C#\" %>"
        $d = "protected void btnExecute_Click(object sender, EventArgs e)"
        $e = "<asp:Literal ID=\"Literal1\" runat=\"server\">"
        
    condition:
        all of them
}
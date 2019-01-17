rule Backdoor_Webshell_ASPX_000876
{
    meta:
        description = "spe"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<title>Stored Procedure Execute</title>"
        $b = "<asp:Button id=\"btnGetParams\" onclick=\"btnGetParameters_Click\" runat=\"server\" Text=\"Get Parameters\">"
        $c = "sqlConnection.ConnectionString = \"Data source=\" + txtDatabaseServer.Text +"
        $d = "<param name=\"sqlCommand\"></param>"
        
    condition:
        all of them
}
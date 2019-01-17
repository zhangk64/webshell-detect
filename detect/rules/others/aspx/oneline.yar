rule Backdoor_Webshell_ASPX_000871
{
    meta:
        description = "oneline code clent"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<TITLE> ASPX one line Code Client by amxku</TITLE>"
        $b = "var nonamed=new System.IO.StreamWriter(Server.MapPath(\"nonamed.aspx\"),false)"
        $c = "<textarea name=l cols=120 rows=10 width=45>your code</textarea><BR><center><br>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASPX_000873
{
    meta:
        description = "scan wrtieable"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<script language=\"VB\" runat=\"server\">"
        $b = "Sub CloneTime(Src As Object, E As EventArgs)"
        $c = "Sub Login_click(sender As Object, E As EventArgs)"
        $d = "<script language=\"javascript\">"
        $e = "call copydir(a & xdir.name & \"\\\",b & xdir.name & \"\\\")"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASPX_000878
{
    meta:
        description = "webadmin final"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "myProcessStartInfo.UseShellExecute = False"
        $b = "for each xdir in mydir.getdirectories()"
        $c = "dim mydir as new DirectoryInfo(a)"
        $d = "<script runat=\"server\">"
        $e = "UserDomainName.Text = Environment.UserDomainName.ToString()"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASPX_000839
{
    meta:
        description = "aspx powered"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "p.StartInfo.UseShellExecute = false"
        $b = "retval += p.StandardOutput.ReadToEnd()"
        $c = "<script runat=\"server\" language=\"C#\">"
        $d = "p.StartInfo.RedirectStandardInput = true"
        
    condition:
        all of them
}
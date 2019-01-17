rule Backdoor_Webshell_ASPX_000849
{
    meta:
        description = "gif89a"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="System.IO.FileInfo fil = new System.IO.FileInfo(T1.Text)"
        $b ="System.IO.StreamWriter sw = fil.CreateText()"
        $c ="sw.Write(T2.Text)"
        $d ="<script language=\"C#\" runat=\"server\">"
        
    condition:
        all of them
}
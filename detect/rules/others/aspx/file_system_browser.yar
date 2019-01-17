rule Backdoor_Webshell_ASPX_000845
{
    meta:
        description = "file system brower"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<script Language=\"c#\" runat=\"server\">"
        $b = "Response.Write(this.DownloadFile())"
        $c = "string[] drives = Environment.GetLogicalDrives()"
        $d = "foreach (System.IO.FileInfo fileInfo in dirInfo.GetFiles(\"*.*\"))"
        $e = "Response.Write(this.OutputList())"
        
    condition:
        all of them
}
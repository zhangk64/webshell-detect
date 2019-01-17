rule Backdoor_Webshell_ASPX_000870
{
    meta:
        description = "ning ju"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "By:sunue</title>"
        $b = "<td><a href='?page=upload'><font color=\"#009900\""
        $c = "<td><a href='?page=scan'><font color=\"#009900\">"
        $d = "<td><a href='?page=clonetime'><font color=\"#009900\">"
        $e = "<a href='?page=index&src=C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\\'><font color=\"#009900\">PcAnywhere</font></a>"
        
    condition:
        all of them
}
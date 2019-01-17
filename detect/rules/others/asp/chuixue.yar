rule Backdoor_Webshell_ASP_000678
{
    meta:
        description = "chui xue"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "set thisfile = ssyss.opentextfile(wfile, 1, false)"
        $b = "set thefolder=ssyss.getfolder(cpath)"
        $c = "set thesubfolders=thefolder.subfolders"
        $d = "data_xlsf.write  request.binaryread(request.totalbytes)"
        $e = "dim oform,objfile,version"
        $f = "dim oform,objfile,version"
        $g = "on error resume next"
        $h = "<object runat=server id=ssyss scope=page classid=\"clsid:0d43fe01-f093-11cf-8940-00a0c9054228\"></object>"
        $i = "response.write \"<font color=black>\" & co.path & \"-----\" & co.size & \"</font><br>\""
        
    condition:
        all of them
}
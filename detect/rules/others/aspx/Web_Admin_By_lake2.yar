rule Backdoor_Webshell_ASPX_000880
{
    meta:
        description = "webadmin by lake"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%@ Page Language=\"VB\" Debug=\"true\" %>"
        $b = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")"
        $c = "for each xdir in mydir.getdirectories()"
        $d = "myProcess.Start()"
        $e = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text"
        
    condition:
        all of them
}
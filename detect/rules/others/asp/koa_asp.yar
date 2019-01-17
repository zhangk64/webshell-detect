rule Backdoor_Webshell_ASP_000689
{
    meta:
        description = "koa"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%If Session(\"KOA\")<>1 Then%>"
        $b = "Dim Report"
        $c = "If Request.Form(\"pwd\")=PASSWORD Then Session(\"KOA\")=1"
        $d = "If RQSact<>\"scan\" And RQSFileManager=\"\" Then"
        $e = "<%=Left(Now(),InStrRev(now(),\"-\")-1)%>"
        $f = "Set oFile=FSO.OpenTextFile(RQSFilePath)"
        $g = "<%=RQSFilePath%>"
        $h = "<%If FormRB=\"koa\" Then%>"
        $i = "Function CheckExt(FileExt)"
        
    condition:
        all of them
}
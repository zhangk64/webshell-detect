rule Backdoor_Webshell_ASP_000685
{
    meta:
        description = "file manager"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "prefix=left(session(\"currentfolder\"),len(session(\"currentfolder\"))-1)"
        $b = "<%extname=objFSO.GetExtensionName(objfile.name)%>"
        $c = "Set objRS=objConn.Execute(mysql)"
        $d = "Set objTableRS = objConn.OpenSchema(20,Array(Empty, Empty, Empty, \"TABLE\"))"
        $e = "objtext.WriteLine (request(\"content\"))"
        $f = "<%=Server.HTMLEncode(TextStream.Readall)%>"
        $g = "<%=objFSO.GetParentFolderName(request(\"filename\"))%>"
        $h = "if request(\"op\")=\"copy\" then%>"
        
    condition:
        all of them
}
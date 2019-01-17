rule Backdoor_Webshell_ASP_000687
{
    meta:
        description = "fso files"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a1 = "Server.ScriptTimeout = 999"
        $a2 = "Select Case action"
        $a3 = "If Path = \"\" Then Path = server.MapPath(\"./\")"
        $a4 = "Function ShowFolderList(folderspec)"
        $a5 = "<SCRIPT RUNAT=SERVER LANGUAGE=VBSCRIPT>"
        $a6 = "Str = \"folder>0>\"&Replace(Folder, rep, \"\")&vbCrLf"
        
        $b1 = "<% =Server.UrlEncode(Fname) %>"
        $b2 = "Server.ScriptTimeout=20"
        $b3 = "If oFile.AtEndOfStream Then"
        $b4 = "Dim conn,rs,oStream,NoPackFiles,RootPath,FailFileList"
        $b5 = "Islight=False"
        $b6 = "oFso.CreateTextFile FilePath"
        $b7 = "rs(\"FileData\")=oStream.Read()"
        
        
    condition:
        (all of ($a*)) or (all of ($b*))
}
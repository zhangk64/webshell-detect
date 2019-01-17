rule Backdoor_Webshell_ASP_000827
{
    meta:
        description = "tom blog"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")"
        $b = "set fso=nothing"
        $c = "set obj=server.createobject(\"scripting.filesystemobject\")"
        $d = "response.write objfile.path &\"<br>\""
        $e = "set objfolder=obj.getfolder(server.mappath(\"/\"))"
        
    condition:
        all of them
}
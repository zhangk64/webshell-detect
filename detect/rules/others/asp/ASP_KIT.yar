rule Backdoor_Webshell_ASP_000672
{
    meta:
        description = "Asp Kit"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "file=request(\"file\")"
        $b = "tipo=request(\"type\")"
        $c = "<INPUT TYPE=\"text\" NAME=\"file\" value=\"<%=file%>"
        $d = "Set oFich = oStr.OpenTextFile(file, 1)"
        $e = "Response.Write(oFich.ReadAll)"
        $f = "set folder = fs.GetFolder(path)"
        $g = "for each item in folder.Files"
        
    condition:
        all of them
}
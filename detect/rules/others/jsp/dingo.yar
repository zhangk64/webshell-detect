rule Backdoor_Webshell_JSP_000560
{
    meta:
        description = "dingo"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "bw.write(content)"
        $b = "response.getOutputStream().write(b, 0, len)"
        $c = "os.write(buf, 0, bytesRead)"
        $d = "fos.write(tmpdataBytes, 0, tmpdataBytes.length"
        $e = "this.exec(db, sql)"
        $f = "db.exec(database, sql)"
        
    condition:
        all of them
}

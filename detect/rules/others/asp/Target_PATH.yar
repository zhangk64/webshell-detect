rule Backdoor_Webshell_ASP_000826
{
    meta:
        description = "target path"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Value = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))"
        $b = "getString = getString & chr(AscB(MidB(StringBin,intCount,1)))"
        $c = "RequestBin = Request.BinaryRead(byteCount)"
        $d = "Set objFile = MyFileObject.CreateTextFile(filename)"
        
    condition:
        all of them
}
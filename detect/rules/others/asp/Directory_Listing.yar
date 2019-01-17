rule Backdoor_Webshell_ASP_000683
{
    meta:
        description = "directory listing"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Private Function GetFirstWord(ByVal sStr)"
        $b = "If ( Not IsEmpty(sDL) ) Then"
        $c = "If ( Not IsEmpty(sDir) ) Then"
        $d = "If ( Not FSO.GetFolder(GetCorrectPath(sDir)).IsRootFolder ) Then"
        $e = "If ( sKey <> \"\" ) Then"
        $f = "StopScript 'asd"
        $g = "Private Sub StopScript()"
        $h = "ElseIf ( iShiftBits < 0 Or iShiftBits > 31 ) Then"
        
    condition:
        all of them
}
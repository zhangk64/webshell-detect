rule Backdoor_Webshell_ASP_000819
{
    meta:
        description = "remote"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Set Drives = FileSystem.Drives"
        $b = "If Drive.DriveType = \"Remote\" Then"
        $c = "Set Folder = FileSystem.GetFolder(FolderPath)"
        $d = "If Not Folder.IsRootFolder Then"
        $e = "Dim Drive"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000659
{
    meta:
        description = "module up"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-3"
        
    strings:
        $a = "fileOut = new FileOutputStream(destFilePath)"
        $b = "fileOut.write(dataBytes, startPos, (endPos - startPos))"
        $c = "byte dataBytes[] = new byte[formDataLength]"
        $d = "String saveFileName = fileContent.substring(fileContent"
        
    condition:
        all of them
}
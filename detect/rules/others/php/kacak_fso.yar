rule Backdoor_Webshell_PHP_000067
{
    meta:
        description = "kacak fso"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "if request.querystring(\"TGH\") = \"1\" then"
        $b = "set	kaydoses=kaydospos.createtextfile(request.querystring(\"dosyakaydet\") & request(\"dosadi\"))"
        $c = "set dos=dossis.opentextfile(request.querystring(\"duzenle\"), 1)"
        $d = "Set FS = CreateObject(\"Scripting.FileSystemObject\")"
        $e = "kaydoses.write request(\"duzenx\")"
        
    condition:
        all of them
}
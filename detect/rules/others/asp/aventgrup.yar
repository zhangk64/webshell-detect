rule Backdoor_Webshell_ASP_000675
{
    meta:
        description = "Avent Grup"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a1 = "set	kaydoses=kaydospos.createtextfile(request.querystring(\"dosyakaydet\") & request(\"dosadi\"))"
        $a2 = "kaydoses.write request(\"duzenx\")"
        $a3 = "set klassis =server.createobject(\"scripting.filesystemobject\")"
        $d = "if request.querystring(\"usklas\") = \"1\" then"
        $e = "if request.querystring(\"usak\") = \"1\" then"
        $a4 = "<% For each oge in altklasorler %>"
        
    condition:
        (all of ($a*)) and ($d or $e)
}
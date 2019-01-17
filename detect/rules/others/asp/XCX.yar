rule Backdoor_Webshell_ASP_000830
{
    meta:
        description = "XCX xiaozu"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "on error resume next"
        $b = "set fso=server.createobject"
        $c = "set fos=nothing"
        $d = "set dama=fso.createtextfile(path,true)"
        $e = "set da=fso.createtextfile(path,true)"
        $f = "if path<>\"\" then"
        $g = "end if"
        $h = "path=request(\"path\")"
        $i = "server.mappath(request.servervariables(\"script_name\"))"
        $j = "<%=server.mappath(\"Phoenix.asp\")%>"
        
        $a1 = "GIF89a$"
        $b1 = "on error resume next"
        $c1 = "set fs=server.CreateObject(\"scripting.filesystemobject\")"
        $d1 = "set thisfile=fs.CreateTextFile(testfile,True)"
        $e1 = "if err =0 Then"
        $f1 = "set fs = nothing"
        $g1 = "if request(\"action\")=\"set\" then"
        $h1 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)"
        $i1 = "set file=nothing"
        $j1 = "set fs=nothing"
        
        $a2 = "server.mappath(request.servervariables(\"script_name\"))"
        $b2 = "Set objCountFile=Nothing"
        $c2 = "Set objFSO = Nothing"
        $d2 = "server.mappath(request.servervariables(\"script_name\"))"
        $e2 = "if err =0 then response.write"
        $f2 = "Set objCountFile=objFSO.CreateTextFile(request(\"syfdpath\"),True)"
        $g2 = "on error resume next"
        $h2 = "dim objFSO,fdata,objCountFile"
        $i2 = "Set objFSO = Server.CreateObject(\"Scripting.FileSystemObject\")"
        $j2 = "Set objCountFile = objFSO.OpenTextFile(Server.MapPath(user),1,True)"
        $k2 = "if pass=\"open\" then"
        $l2 = "FiletempData=Replace(FiletempData,\"exe\"&\"cute\",\"dst\")"
        
        $a3 = "on error resume next"
        $b3 = "Set FSO = Server.CreateObject(\"Scripting.FileSystemObject\")"
        $c3 = "Set objFSO = Server.CreateObject(\"Scripting.FileSystemObject\")"
        $d3 = "if Trim(request(\"path1\"))<>\"\" then"
        $e3 = "Set MyFile=FSO.CreateTextFile(request(\"path1\"),True)"
        $f3 = "Set objCountFile=objFSO.CreateTextFile(request(\"syfdpath\"),True)"
        $g3 = "if err =0 then"
        $h3 = "Set MyFile=Nothing"
        $i3 = "Set objCountFile=Nothing"
        $j3 = "Set FSO = Nothing"
        $k3 = "Set objFSO = Nothing"
        $m3 = "server.mappath(Request.ServerVariables(\"SCRIPT_NAME\"))"
        $l3 = "<%@LANGUAGE=\"VBScript\" CODEPAGE=\"936\"%>"
        
    condition:
        (($a and $b and $c and $d and $f and $g and $h and $i) or ($a and $b and $c and $e and $f and $g and $h and $i) or ($a and $b and $c and $d and $f and $g and $h and $j) or ($a and $b and $c and $e and $f and $g and $h and $j) or ($b and $c and $e and $f and $g and $h and $i) or ($a1 and $b1 and $c1 and $d1 and $e1 and $f1) or ($c1 and $g1 and $h1 and $i1 and $j1) or ($a2 and $b2 and $c2 and $d2 and $e2 and $f2 and $g2 and $h2) or ($b2 and $c2 and $i2 and $j2 and $k2 and $l2) or ($a3 and $b3 and $d3 and $e3 and $g3 and $h3 and $j3 and $m3 and $l3) or ($a3 and $c3 and $f3 and $g3 and $i3 and $k3 and $m3 ))
}

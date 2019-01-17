rule Backdoor_Webshell_ASP_000831
{
    meta:
        description = "xynu"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<%@LANGUAGE=\"JAVASCRIPT\" CODEPAGE=\"65001\"%>"
        $b = "Surl = String(Request.QueryString).match(/url=(.*)$/)[1];"
        $c = "http_request.setRequestHeader(\"Cookie\",Cookie)"
        $d = "objstream.Charset = Cset"
        $e = "Retrieval.Open(\"GET\",Surl,false)"
        $f = "Retrieval = Server.CreateObject(\"Microsoft.XMLHTTP\")"
        
    condition:
        all of them
}
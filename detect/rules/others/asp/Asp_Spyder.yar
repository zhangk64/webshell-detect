rule Backdoor_Webshell_ASP_000674
{
    meta:
        description = "Asp Spyder"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "System: <%=now%>"
        $b = "<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=session(\"txtpath\")%>"
        $c = "Response.Write \"File(s) not uploaded.\""
        $d = "<B>Listed: \" & fo & \""
        $e = "<b>Listed: \" & fi & \""
        $f = "response.Flush()"
        $g = "Function BufferContent(data)"
        $h = "<%If request.querystring(\"logoff\")=\"@\" then%>"
        $i = "<%For Each thingy in fso.Drives%>"
        $j = "<%=FormatDateTime(f.datelastmodified,1)%>&nbsp;<%=FormatDateTime(f.datelastmodified,3)%>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000663
{
    meta:
        description = "path"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2107-12-6"
        
    strings:
        $a = "File f = new File(request.getParameter(\"file\"))"
        $b = "<FONT Face=\"Courier New, Helvetica\" Color=\"Black\">"
        $c = "by: Sierra"
        $d = "list.jsp = Directory & File View"
        
    condition:
        all of them
}

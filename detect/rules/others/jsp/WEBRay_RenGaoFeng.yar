rule __webshell_1
{
    meta:
        description = "1.jspx"
        company = "WatcherLab"
        level = 4
        type = "webshell"
        date = "2018-08-24"
    strings:
        $s1 = "<%=Class.forName(\"Load\",true,new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL(request.getParameter(\"u\"))})).g" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of ($s*) ) ) or ( all of them )
}

rule __webshell_5
{
    meta:
        description = "5.jsp"
        company = "WatcherLab"
        level = 4
        type = "webshell"
        date = "2018-08-24"
    strings:
        $x1 = "<%@ page language=\"java\" import=\"java.util.*,java.io.*\"%><%!public static String excuteCmd(String c) {StringBuilder line = n" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule __webshell_5_2
{
    meta:
        description = "5.jspx"
        company = "WatcherLab"
        level = 4
        type = "webshell"
        date = "2018-08-24"
    strings:
        $x1 = "Process child = Runtime.getRuntime().exec(cmd);" fullword ascii
        $x2 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\"          xmlns=\"http://www.w3.org/1999/xhtml\"          xmlns:c=\"http://j" ascii
        $s3 = "String cmd = request.getParameter(\"wq\");" fullword ascii
        $s4 = "System.err.println(e);" fullword ascii
        $s5 = "}            </jsp:scriptlet>        </body>    </html></jsp:root>" fullword ascii
        $s6 = "InputStream in = child.getInputStream();" fullword ascii
        $s7 = "while ((c = in.read()) != -1) {" fullword ascii
        $s8 = "child.waitFor();" fullword ascii
        $s9 = "if (cmd !=null){" fullword ascii
        $s10 = "out.print((char)c);" fullword ascii
        $s11 = "e.printStackTrace();" fullword ascii
    condition:
        ( uint16(0) == 0x6a3c and filesize < 2KB and ( 1 of ($x*) and all of ($s*) ) ) or ( all of them )
}

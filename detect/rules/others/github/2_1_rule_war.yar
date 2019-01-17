rule d28b36083947a160c96561d5a328a6ac1e26545d
{
    meta:
        description = "war - file d28b36083947a160c96561d5a328a6ac1e26545d.war"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "55d18f117702a4780769deb09af57d6e93a63f9e1349b3a973046f3b4a194d0f"
    strings:
        $s1 = "Created-By: 1.5.0 (Sun Microsystems Inc.)" fullword ascii
        $s2 = "index.jsp" fullword ascii
    condition:
        ( uint16(0) == 0x4b50 and filesize < 80KB and ( all of them ) ) or ( all of them )
}

rule d05bc282e48714a5d0865e536b2eeada6b5b2a2f
{
    meta:
        description = "war - file d05bc282e48714a5d0865e536b2eeada6b5b2a2f.war"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2a95a39ae2f86f2479690a7b54ad9038be74c8b95e4a978f4975f7c8f0d028d9"
    strings:
        $s1 = "WEB-INF/weblogic.xml" fullword ascii
        $s2 = "WEB-INF/weblogic.xmlPK" fullword ascii
        $s3 = "index.jsp" fullword ascii
    condition:
        ( uint16(0) == 0x4b50 and filesize < 80KB and ( all of them ) ) or ( all of them )
}

rule sig_33619ede49164d057f27ae5d379b0b55f1b3e6f5
{
    meta:
        description = "war - file 33619ede49164d057f27ae5d379b0b55f1b3e6f5.war"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "187cf53de4bde0e8990d433f2da856a717167d3a776f446729640220076e23e0"
    strings:
        $s1 = "jsp/META-INF/context.xml<?xml version=\"1.0\" encoding=\"UTF-8\"?>" fullword ascii
        $s2 = "jsp/shell.jsp" fullword ascii
    condition:
        ( uint16(0) == 0x4b50 and filesize < 40KB and ( all of them ) ) or ( all of them )
}

rule sig_7648e4c69f0f9955d4060a9f0380c3701055a485
{
    meta:
        description = "war - file 7648e4c69f0f9955d4060a9f0380c3701055a485.war"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "947d0aebbfdfa05a00d1cf8e087b2f93a411bac74e125da4abfaa2e6ad3f8826"
    strings:
        $s1 = "shell.jsp" fullword ascii
        $s2 = "shell.jspPK" fullword ascii
        $s3 = "check.jsp" fullword ascii
    condition:
        ( uint16(0) == 0x4b50 and filesize < 30KB and ( all of them ) ) or ( all of them )
}

rule sig_246d629ae3ad980b5bfe7e941fe90b855155dbfc
{
    meta:
        description = "war - file 246d629ae3ad980b5bfe7e941fe90b855155dbfc.war"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ec37a2d841bd68da48bf8743a40bd25049ce081bfff67802900163b4b8f8f84c"
    strings:
        $x1 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii
        $x2 = "Hashtable ht = parser.processData(request.getInputStream(), bound, tempdir, clength);" fullword ascii
        $x3 = "<center><a href=\"http://www.topronet.com\" target=\"_blank\">www.topronet.com</a> ,All Rights Reserved." fullword ascii
        $s4 = "aobject.style.backgroundColor=document.getElementById(\"tabcontentcontainer\").style.backgroundColor=themecolor" fullword ascii
        $s5 = "public Hashtable processData(ServletInputStream is, String boundary, String saveInDir," fullword ascii
        $s6 = "response.setHeader(\"Content-Disposition\",\"attachment; filename=\\\"\"+f.getName()+\"\\\"\");" fullword ascii
        $s7 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s8 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - - by Steven Cee http://www.topronet.com </font>" ascii
        $s9 = "/** Convenience method to read HTTP header lines */" fullword ascii
        $s10 = "sbFolder.append(strParentFolder[languageNo]+\"</a><br>- - - - - - - - - - - </td></tr>\\r\\n \");" fullword ascii
        $s11 = "<b>\"+strDir+\"</b></td><td>\" + getDrivers() + \"</td></tr></table><br>\\r\\n\");" fullword ascii
        $s12 = "line = getLine(is); // Skip \"Content-Type:\" line" fullword ascii
        $s13 = "<input type=submit name=submit value=\"<%=strExecute[languageNo]%>\">" fullword ascii
        $s14 = "String bound = request.getContentType().substring(bstart + 8);" fullword ascii
        $s15 = "private final String lineSeparator = System.getProperty(\"line.separator\", \"\\n\");" fullword ascii
        $s16 = "* Converts some important chars (int) to the corresponding html string" fullword ascii
        $s17 = "xsi:schemaLocation=\"http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd\"" fullword ascii
        $s18 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
        $s19 = "response.setHeader(\"content-type\",\"text/html; charset=ISO-8859-1\");" fullword ascii
        $s20 = "<a href=\"http://blog.csdn.net/cqq/archive/2004/11/14/181728.aspx\" target=\"_blank\">http://blog.csdn.net/cqq/archive/2004/11/1" ascii
    condition:
        ( uint16(0) == 0x4b50 and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

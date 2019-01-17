rule Trojan_webshell_Shell_ci_Biz_was_here_c100
{
    meta:
        description = "ci biz was here c100"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri"
        $s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\""
        $s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO"
        $s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de"
        $s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER"
        
    condition:
        2 of them
}
rule Trojan_webshell_WinX_Shell_html_txt
{
    meta:
        description = "semi-auto-generated winx shell.html.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "WinX Shell"
        $s1 = "Created by greenwood from n57"
        $s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>"
        
    condition:
        2 of them
}
rule Trojan_webshell_s72_Shell_v1_1_Coding_html
{
    meta:
        description = "semi-auto-generated s72 shell v1.1 coding.html.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><"
        $s1 = "s72 Shell v1.0 Codinf by Cr@zy_King"
        $s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\""
        
    condition:
        1 of them
}
rule Trojan_webshell_DarkSecurityTeam
{
    meta:
        description = "dark security team webshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
        
    condition:
        1 of them
}
rule Trojan_webshell_Generic_1609_A
{
    meta:
        description = "auto-generated generic_1609_a"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-10"
        
    strings:
        $s1 = "return $qwery45234dws($b);" ascii
        
    condition:
        ( uint16(0) == 0x3f3c and 1 of them )
}
rule Trojan_webshell_file_shell_cmd_cfm
{
    meta:
        description = "laudanum injector tools shell.cfm"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
        
    condition:
        filesize < 20KB and 2 of them
}
rule Trojan_APT_Laudanum_Tools_Generic
{
    meta:
        description = "laudanum injector tools"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        super_rule = 1
        
    strings:
        $s1 = "***  laudanum@secureideas.net" fullword ascii
        $s2 = "*** Laudanum Project" fullword ascii
        
    condition:
        filesize < 60KB and all of them
}
rule Trojan_webshell_CN_Honker_mycode12_cmd_cfm
{
    meta:
        description = "cn honker pentest toolset mycode12.cfm"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
        
    condition:
        filesize < 4KB and all of them
}
rule Trojan_webshell_CN_Honker_xl_cmd_cfm
{
    meta:
        description = "cn honker pentest toolset xl.cfm"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "<input name=\"DESTINATION\" value=\"" ascii /* PEStudio Blacklist: strings */
        $s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii
        
    condition:
        uint16(0) == 0x433c and filesize < 13KB and all of them
}
rule Trojan_webshell_CN_Honker_nc_1_txt
{
    meta:
        description = "cn honker pentest toolset 1.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Mozilla/4.0 " ascii /* PEStudio Blacklist: agent */
        $s2 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        
    condition:
        filesize < 11KB and all of them
}
rule Trojan_webshell_CN_Honker_list_cfm
{
    meta:
        description = "cn honker pentest toolset list.cfm"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii /* PEStudio Blacklist: strings */
        $s2 = "<TD>#mydirectory.size#</TD>" fullword ascii
        
    condition:
        filesize < 10KB and all of them
}
rule Trojan_webshellCN_Honker_cfmShell_cmd_cfm
{
    meta:
        description = "cn honker pentest toolset cfmshell.cfm"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii
        
    condition:
        filesize < 4KB and all of them
}
rule Trojan_webshell_CN_Honker_cmfshell_cmf
{
    meta:
        description = "cn honker pentest toolset cmfshell.cmf"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 4KB and all of them
}
rule Trojan_webshell_CN_Honker_Linux_Exploit
{
    meta:
        description = "cn honker pentest toolset 2.6.9"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "[+] Failed to get root :( Something's wrong.  Maybe the kernel isn't vulnerable?" fullword ascii
        
    condition:
        filesize < 56KB and all of them
}
rule Trojan_webshell_InjectionParameters_vb
{
    meta:
        description = "injectionparameters.vb"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
        $s1 = "Public Class InjectionParameters" fullword ascii
        
    condition:
        filesize < 13KB and all of them
}
rule Trojan_webshell_Txt_shell_c
{
    meta:
        description = "shell.c"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
        $s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
        $s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
        $s4 = "char shell[]=\"/bin/sh\";" fullword ascii
        $s5 = "connect back door\\n\\n\");" fullword ascii
        
    condition:
        filesize < 2KB and 2 of them
}
rule Trojan_webshell_Txt_ftp_cmd_txt
{
    meta:
        description = "ftp.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
        $s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
        $s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
        $s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
        $s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
        $s6 = "ftp -s:d:\\ftp.txt " fullword ascii
        $s7 = "echo bye>>d:\\ftp.txt " fullword ascii
        
    condition:
        filesize < 2KB and 2 of them
}
rule Trojan_webshell_Txt_lcx_c
{
    meta:
        description = "lcx.c"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
        $s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
        $s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
        $s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
        $s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
        
    condition:
        filesize < 25KB and 2 of them
}
rule Trojan_webshell_Txt_xiao_large_txt
{
    meta:
        description = "xiao.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
        $s4 = "function Command(cmd, str){" fullword ascii
        $s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
        
    condition:
        filesize < 100KB and all of them
}
rule Trojan_webshell_Txt_Sql_txt
{
    meta:
        description = "sql.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
        $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
        $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
        $s4 = "session(\"login\")=\"\"" fullword ascii
        
    condition:
        filesize < 15KB and all of them
}
rule Trojan_webshell_Txt_hello_large_txt
{
    meta:
        description = "hello.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
        $s2 = "myProcess.Start()" fullword ascii
        $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
        
    condition:
        filesize < 25KB and all of them
}

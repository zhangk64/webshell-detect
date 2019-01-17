rule Backdoor_Webshell_PHP_000546
{
    meta:
        description = "win mof"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "if(!empty($_POST['submit']))"
        $a2 = "$payload = \"#pragma"
        $a3 = "$num=mysql_num_rows($result2)"
        $a4 = "while ($row = mysql_fetch_array($result2, MYSQL_NUM))"
        
        $b1 = "if(isset($_REQUEST['host'])"
        $b2 = "$payload = \"#pragma"
        $b3 = "$conn=mysql_connect($mysql_server_name,$mysql_username,$mysql_password,$mysql_database)"
        $b4 = "mysql_select_db($mysql_database,$conn)"
        
    condition:
        all of ($a*) or all of ($b*)
}

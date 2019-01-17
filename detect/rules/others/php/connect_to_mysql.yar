rule Backdoor_Webshell_PHP_000024
{
    meta:
        description = "conneect to mysql"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "while( $row = mysql_fetch_assoc( $rlt ) )"
        $b = "if( empty( $_GET[\"sql\"]"
        $c = "foreach( $row as $k => $v )"
        $d = "mysql_select_db( $_GET[\"db\"] )"
        
    condition:
        all of them
}
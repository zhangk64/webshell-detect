rule Backdoor_Webshell_PHP_000028
{
    meta:
        description = "c web2xml"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "public function Create_XML2Web()"
        $b = "public function __construct($path=NULL, $xmlfile=NULL)"
        $c = "function Array_Get_FileList($dir)"
        $d = "set_time_limit(0);"
        $e = "$do = $_POST[\"do\"]"
        
    condition:
        all of them
}
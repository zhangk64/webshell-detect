rule Backdoor_Webshell_PHP_000000
{
    meta:
        description = "ajax file"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="function ajaxFileUpload()"
        $b ="if(typeof(data.error) != 'undefined')"
        $c ="error: function (data, status, e)"
        $d =".ajaxComplete(function()"
        
    condition:
        all of them
}

rule Backdoor_Webshell_PHP_000014
{
    meta:
        description = "botw44 shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "$formcmd = $_POST[\"cmd\"]"
        $b = "$result = python_eval('import os\\npwd = os.getcwd()\\nprint pwd\\nos.system(\"$cmd\")')"
        $c = "@system($cmd);"
        $d = "@exec($cmd,$result)"
        $e = "if(!empty($_POST[\"cmd\"]))"
        
    condition:
        all of them
}
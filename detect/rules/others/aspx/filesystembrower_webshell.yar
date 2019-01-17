rule Backdoor_Webshell_ASPX_000844
{
    meta:
        description = "file system brower"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "private const string HEADER = \"<html>\\n<head>\\n<title>filesystembrowser</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,table,p,pre,form input,form select {\\n font-family: \\\"Lucida Console\\\", monospace;\\n font-size: 88%;\\n}\\n-->\\n</style></head>\\n<body>\\n\";"
        $c = "FileInfo fileInfo = new FileInfo(Request.PhysicalPath);"
        
    condition:
        all of them
}
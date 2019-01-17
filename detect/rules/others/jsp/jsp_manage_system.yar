rule Backdoor_Webshell_JSP_000570
{
    meta:
        description = "jsp manager system"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "con=DriverManager.getConnection(url,userName,passWord)"
        $b = "bos=new BufferedOutputStream(new FileOutputStream(newFilename))"
        $c = "bos=new BufferedOutputStream(new FileOutputStream(filename))"
        $d = "output = new FileOutputStream(zipPath)"
        
    condition:
        all of them
}

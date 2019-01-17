rule Backdoor_Webshell_PYTHON_000882
{
    meta:
        description = "semi-auto-generated wh_bindshell.py.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "#Use: python wh_bindshell.py [port] [password]"
        $s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\""
        $s3 = "#bugz: ctrl+c etc =script stoped="
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PYTHON_000883
{
    meta:
        description = "semi-auto-generated Phyton Shell.py.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()"
        $s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ"
        $s3 = "print \"error; help: head -n 16 d00r.py\""
        $s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PYTHON_000884
{
    meta:
        description = "semi-auto-generated cgi-python.py.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "a CGI by Fuzzyman"
        $s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + "
        $s2 = "values = map(lambda x: x.value, theform[field])     # allows for"
        
    condition:
        1 of them
}

rule Backdoor_Webshell_ASPX_000850
{
    meta:
        description = "executable program scan"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");"
        $b = "string str = Hklm.GetValue(name).ToString().ToLower();"
        $c = "RegistryKey Hklm = (RegistryKey)sack.Pop()"
        $d = "if (str.IndexOf(\":\\\\\") != -1 && str.IndexOf(\"c:\\\\program files\") == -1 && str.IndexOf(\"c:\\\\windows\") == -1)"
        
    condition:
        all of them
}
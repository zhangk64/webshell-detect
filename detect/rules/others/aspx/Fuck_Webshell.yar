rule Backdoor_Webshell_ASPX_000846
{
    meta:
        description = "an quan fu yun"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "public string RootKeys=@\"HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CURRENT_CONFIG\";"
        $b = "RegList+=\"<tr><td><a href=javascript:jump('\"+RootKey.Replace(@\"\\\",@\"\\\\\")+\"')>\"+RootKey+\"</a></td><td>RootKey</td><td></td></tr>\";"
        $c = "string subkey=Reg_Path.Substring(Reg_Path.IndexOf(\"\\\\\")+1,Reg_Path.Length-Reg_Path.IndexOf(\"\\\\\")-1);"
        
    condition:
        all of them
}
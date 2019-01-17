rule Backdoor_Webshell_ASPX_000843
{
    meta:
        description = "kexiemulusousuo"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
        $b = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");"
        $c = "Response.Write(\"<font color=red>"
        $d = "<%@ Assembly Name=\"System.Management,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\"%>"
        $e = "FileAttributes dInfo = File.GetAttributes(temp);"
        
    condition:
        all of them
}
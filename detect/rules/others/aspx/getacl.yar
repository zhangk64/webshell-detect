rule Backdoor_Webshell_ASPX_000848
{
    meta:
        description = "getacl"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-3"
        
    strings:
        $a ="<%@ Page Language=\"C#\" Debug=\"true\" Trace=\"false\" ValidateRequest=\"false\""
        $b ="<%@ Import Namespace=\"System.Management\" %>"
        $c ="<script runat=\"server\">"
        $d ="private bool _is_ShowAllUserACL = false"
        
    condition:
        all of them
}
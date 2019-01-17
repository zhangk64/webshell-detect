rule Backdoor_Webshell_ASPX_000842
{
    meta:
        description = "devshell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-4"
        
    strings:
        $a ="<%@ Page Language=\"VB\" Debug=\"true\" trace=\"false\" validateRequest=\"false\" EnableViewStateMac=\"false\" EnableViewState=\"true\"%>"
        $b ="<%@ import Namespace=\"System.Net.Sockets\" %>"
        $c ="<%@ Import Namespace=\"System.Threading\"%>"
        $d =".Arguments = port & \" \" & ip"
        $e ="<script runat=\"server\">"
        
    condition:
        all of them
}
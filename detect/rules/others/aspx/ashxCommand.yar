rule Backdoor_Webshell_ASPX_000835
{
    meta:
        description = "ashx command"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "ctx.Response.Write(\"<form method='GET'>Command: <input name='cmd' value='\"+command+\"'><input type='submit' value='Run'></form>\")"
        $b = "ProcessStartInfo psi = new ProcessStartInfo();"
        $c = "public class AverageHandler : IHttpHandler"
        $d = "psi.Arguments = \"/c \"+command;"
        
    condition:
        all of them
}
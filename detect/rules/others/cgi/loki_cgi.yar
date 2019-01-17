rule Backdoor_Webshell_CGI_000891
{
    meta:
        description = "semi-auto-generated lurm_safemod_on.cgi.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "Network security team :: CGI Shell"
        $s1 = "#########################<<KONEC>>#####################################"
        $s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_CGI_000892
{
    meta:
        description = "semi-auto-generated webshell.cgi.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "WebShell.cgi"
        $s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else"
        
    condition:
        all of them
}
rule Backdoor_Webshell_CGI_000893
{
    meta:
        description = "semi-auto-generated telnet.cgi.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s1 = "W A R N I N G: Private Server"
        $s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
        $s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_CGI_000894
{
    meta:
        description = "cn honker pentest toolset webshell.cgi"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2015-06-23"
        
    strings:
        $s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "warn \"command: '$command'\\n\";" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        filesize < 30KB and 2 of them
}

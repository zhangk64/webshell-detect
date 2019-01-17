rule Backdoor_Webshell_PL_000885
{
    meta:
        description = "semi-auto-generated perlbot.pl.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
        $s1 = "#Acesso a Shel - 1 ON 0 OFF"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PL_000886
{
    meta:
        description = "semi-auto-generated telnet.pl.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "W A R N I N G: Private Server"
        $s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "
        
    condition:
        all of them
}
rule Backdoor_Webshell_PL_000887
{
    meta:
        description = "semi-auto-generated asmodeus v0.1.pl.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "[url=http://www.governmentsecurity.org"
        $s1 = "perl asmodeus.pl client 6666 127.0.0.1"
        $s2 = "print \"Asmodeus Perl Remote Shell"
        $s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PL_000888
{
    meta:
        description = "semi-auto-generated telnetd.pl.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "0ldW0lf"
        $s1 = "However you are lucky :P"
        $s2 = "I'm FuCKeD"
        $s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#"
        $s4 = "atrix@irc.brasnet.org"
        
    condition:
        1 of them
}
rule Backdoor_Webshell_PL_000889
{
    meta:
        description = "semi-auto-generated shellbot.pl.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "ShellBOT"
        $s1 = "PacktsGr0up"
        $s2 = "CoRpOrAtIoN"
        $s3 = "# Servidor de irc que vai ser usado "
        $s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"
        
    condition:
        2 of them
}
rule Backdoor_Webshell_PL_000890
{
    meta:
        description = "semi-auto-generated connectback2.pl.txt"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        
    strings:
        $s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
        $s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
        $s2 = "ConnectBack Backdoor"
        
    condition:
        1 of them
}

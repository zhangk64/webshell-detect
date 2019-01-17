rule Backdoor_Webshell_PHP_000045
{
    meta:
        description = "gamma"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "my ($self) = @_"
        $b = "my ($self, $operation, $keywords) = @_"
        $c = "[% for entry in directory %]"
        $d = "sub compile"
        $e = "[% if error %]"
        
    condition:
        all of them
}
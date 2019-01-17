rule Backdoor_Webshell_PHP_000055
{
    meta:
        description = "haketeam"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "while($file=readdir($fdir))"
        $a2 = "function start_unzip($tmp_name,$new_name,$checked)"
        $a3 = "if ($header['mdate'] && $header['mtime'])"
        $a4 = "$header['compression'] = $data['compression'];$header['size'] = $data['size']"
        
        $b1 = "while($file=readdir($fdir))"
        $b2 = "if(realpath($dodozip ->gzfilename)!=realpath(\"$dir/$file\"))"
        $b3 = "$mypathdir[] = $path = dirname($path)"
        $b4 = "$path = @current($mypathdir)"
        
        $c1 = "if(realpath($faisunZIP ->gzfilename)!=realpath(\"$dir/$file\"))"
        
    condition:
        4 of ($a*) or 4 of ($b*) or ($b1 and $b3 and $b4 and $c1)
}
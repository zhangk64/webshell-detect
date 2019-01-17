rule Backdoor_Webshell_PHP_000006
{
    meta:
        description = "b374k"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on\""
        $a2 = "@$s_func('$x,$y','ev'.'al'.'(\"\\$s_pass=\\\"$y\\\";?>\".gz'.'inf'.'late'.'( bas'.'e64'.'_de'.'co'.'de($x)));')"
        
        $b1 = "setcookie($s_k,\"\",time() - $s_login_time)"
        $b2 = "$s_code = base64_decode($_REQUEST['eval'])"
        $b3 = "$s_code = ssc($_REQUEST['evalcode'])"
        
        $c1 = "$xSystem = trim(php_uname())"
        $c2 = "error_reporting(0)"
        $c3 = "$code = xclean($code)"
        $c4 = "@eval($code)"
        
        $d1 = "$func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on\""
        $d2 = "$func('$x','ev'.'al'.'(\"?>\".gz'.'un'.'com'.'pre'.'ss(ba'.'se'.'64'.'_de'.'co'.'de($x)));')"
        
        $e = "@create_function('$x','ev'.'al'.'(gz'.'inf'.'late'.'(bas'.'e64'.'_de'.'co'.'de($x)));')"
        
        $f = "@eval($w48c4c69("
        
        $g1 = "eval(\"?>\".base64_decode("
        $g2 = "$GLOBALS['module_to_load'] = array(\"explorer\", \"terminal\", \"eval\", \"convert\", \"database\", \"info\", \"mail\", \"network\", \"processes\")"
        $g3 = "eval($evalCode)"
        $g4 = "@system($code)"
        
        $h1 = "setcookie($s_k,\"\",time() - $s_login_time)"
        $h2 = "$s_code = base64_decode($_GP['eval'])"
        
        $i1 = "$s_fc = ssc($_REQUEST['fc'])"
        $i2 = "$s_st = @move_uploaded_file($s_tm,$s_pi)"
        $i3 = "$s_dlpath = ss($_REQUEST['dlpath'])"
        $i4 = "eval($s_code)"
        
        $j1 = "$func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on\""
        $j2 = "$func('$x','ev'.'al'.'(\"?>\".gz'.'in'.'fla'.'te(ba'.'se'.'64'.'_de'.'co'.'de($x)));')"
        
        $k1 = "setcookie($k,\"\",time() - $s_login_time)"
        $k2 = "$code = base64_decode($_REQUEST['eval'])"
        $k3 = "$code = ssc($_REQUEST['evalcode'])"
        
        $l1 = "setcookie(\"b374k\",$login,time() + $s_login_time)"
        $l2 = "error_reporting(0)"
        $l3 = "$code = base64_decode($_REQUEST['eval'])"
        
        $m1 = "setcookie(\"MetalSoftTeam\",$login,time() - 3600*24*7)"
        $m2 = "$process = proc_open($shell, $descriptorspec, $pipes)"   //php-reverse-shell
        $m3 = "error_reporting(0)"
        $m4 = "$c = ss($_REQUEST['evalcode'])"
        
        $n1 = "setcookie(\"b374k\",$login,time() - $s_login_time)"
        $n2 = "$process = proc_open($shell, $descriptorspec, $pipes)"
        $n3 = "error_reporting(0)"
        $n4 = "$c = ss($_REQUEST['evalcode'])"
        
        $o = "eval(gzinflate(base64_decode("
        
        $p = "eval(vUMmFr("
        
        $q1 = "$system = trim(php_uname())"
        $q2 = "$stat = @move_uploaded_file($tmp_name,$filepath)"
        $q3 = "$oldname = xclean($_GET['oldfilename'])"
        
        $r1 = "@$b374k("
        $r2 = "@create_function('$x,$y','ev'.'al'.'(\"\\$s_pass=\\\"$y\\\";?>\".gz'.'inf'.'late'.'( bas'.'e64'.'_de'.'co'.'de($x)));')"
        $r3 = "@eval(gzinflate(base64_decode($code)))"
        
    condition:
        all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*) or $e or $f or all of ($g*) or all of ($h*) or all of ($i*) or all of ($j*) or all of ($k*) or all of ($l*) or all of ($m*) or all of ($n*) or $o or $p or all of ($q*) or 2 of ($q*) or 2 of ($r*)
}
rule Backdoor_Webshell_PHP_000017
{
    meta:
        description = "c99shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a1 = "if (!function_exists(\"getmicrotime\")) {function getmicrotime() {list($usec, $sec) = explode(\" \", microtime()); return ((float)$usec + (float)$sec);}}"
        $a2 = "$v = $_SERVER[\"WINDIR\"].\"\\repair\\sam\""
        $a3 = "echo $v.\" - <input type=text size=50 onFocus=\\\"this.select()\\\" onMouseover=\\\"this.select()\\\" onMouseout=\\\"this.select()\\\" value=\\\"\".$v($encoder_input).\"\\\" readonly><br>\""
        $a4 = "$y = \"<a href=\\\"\".$surl.\"act=\".$dspact.\"&d=\".urlencode($d).\"&sort=\".$k.($parsesort[1] == \"a\"?\"d\":\"a\").\"\\\">\""
        $a5 = "eval($eval)"
        
        $b1 = "error_reporting(E_ERROR | E_PARSE)"
        $b2 = "$windir = $_SERVER[\"WINDIR\"]"
        $b3 = "$source = @file_get_contents($sourceurl);"
        $b4 = "if ($print) {if ($nl2br) {echo nl2br($out);} else {echo $out;}}"
        $b5 = "<?php"
        
        $c1 = "if (!function_exists(\"myshellexec\"))"
        $c2 = "$sess_cookie = \"c99shvars\""
        $c3 = "$v = $_SERVER[\"WINDIR\"]"
        $c4 = "$v($encoder_input).\"\\\" readonly>"
        $c5 = " echo \"</table><hr size=\\\"1\\\" noshade><p align=\\\"right\\\">"
        
        $d1 = "$phpeval = @$_POST['php_eval']"
        $d2 = "$eval = @str_replace(\"<?\",\"\",$phpeval)"
        $d3 = "@eval($eval)"
        $d4 = "$headers .= \"\\r\\nContent-Type: multipart/alternative; boundary=\\\"PHP-alt-\".$random_hash.\"\\"
        
        $e1 = "ini_set('memory_limit', '1000M')"
        $e2 = "curl_setopt($ch, CURLOPT_URL, $_POST[url])"
        $e3 = "if ($_POST['mode']"
        $e4 = "function getperms ($perms)"
        
        $f1 = "if (file_put_contents(__FILE__,substr_replace"
        $f2 = "if(function_exists('base64_encode') && function_exists('base64_decode')) { echo '<option>Base64</option>'"
        $f3 = "elseif ($_POST['vuln'] === 'Eval') { $AVuln = '@eval($_POST[\\'c37\\'])"
        $f4 = "foreach ($Fuckers AS $BOT)"
        
        $g1 = "<? basename($_SERVER['PHP_SELF']); ?>"
        $g2 = "$safe_mode=(@ini_get(\"safe_mode\")=='')?\"OFF\":\"ON\""
        $g3 = "if ($k > count($head)) {$k = count($head)-1;}"
        $g4 = "$t = str_replace(\"\\\\\",DIRECTORY_SEPARATOR,$t)"
        $g5 = "if (empty($a[\"text\"]) and $bool) {$found[] = $d.$f; $found_d++;}"
        
        $h1 = "$fp = fopen($file, \"w\")"
        $h2 = "while (($o = readdir($h)) !== FALSE) {$list[] = $d.$o;}"
        $h3 = "if (file_exists($thedir)) { echo \"<b>Already exists:</b> \".htmlspecialchars($thedir)"
        $h4 = "if (!chmod($arg1,$arg2)) { echo \"Failed to chmod $arg1!\\n\";}"
        
        $i1 = "if (file_exists($d.$f)) {echo \"<center><b>Permision denied (\".htmlspecialchars($d.$f).\")"
        $i2 = "while (($o = readdir($h)) !== FALSE) {$list[] = $d.$o;}"
        $i3 = "$text = file_get_contents($d.$f)"
        $i4 = "if(isset($_GET['directory']))"
        $i5 = "if (chmod($d.$f,$octet)) {$act = \"ls\"; $form = FALSE; $err = \"\";}"
        
    condition:
        all of ($a*) or all of ($b*) or all of ($c*)  or all of ($d*) or all of ($e*) or all of ($f*) or all of ($g*) or all of ($h*) or all of ($i*)
}
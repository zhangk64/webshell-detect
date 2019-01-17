rule Backdoor_Webshell_PHP_000033
{
    meta:
        description = "dx shell"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-11-29"
        
    strings:
        $a = "else {if (eval('$_POST[\\'DxProx_CKI\\']='.$_POST['DxProx_CKI'].';')===FALSE) $_POST['DxProx_CKI']=array();}"
        $b = "if (headers_sent()) $DXGLOBALSHIT=true; else $DXGLOBALSHIT=FALSE"
        $c = "function DxChmod_Oct2Str($perms)"
        $d = "if (!isset($_SERVER['PHP_AUTH_USER']))"
        $e = "if (!isset($_GET['dxmode'])) $_GET['dxmode']='DIR'; else $_GET['dxmode']=strtoupper($_GET['dxmode'])"
        $f = "if ($_GET['dxmode']=='WTF')"
        
    condition:
        all of them
}
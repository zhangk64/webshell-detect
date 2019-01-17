rule Backdoor_Webshell_JSP_000563
{
    meta:
        description = "jfolerajsp"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a1 = "private final static int languageNo="
        $a2 = "static Hashtable uploadTable = new Hashtable()"
        $a3 = "System.out.println(e.toString())"
        $a4 = "os = new FileOutputStream"
        $a5 = "new FileOutputStream(f)"
        $a6 = "FileOutputStream out1=new FileOutputStream(f_des_copy)"
        $g = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd)"
        $h = "Process p=Runtime.getRuntime().exec(strCommand,null,new File(strDir))"
        
    condition:
        all of ($a*) and ($g or $h)
}

rule Backdoor_Webshell_ASP_000824
{
    meta:
        description = "data management"
        company = "WatcherLab"
        level = 4
        type = "Backdoor.Webshell"
        date = "2017-12-6"
        
    strings:
        $a = "if request(\"key\") = \"db\" then"
        $b = "if trim(request.form(\"SchemaTable\")) <> \"\" then Call showSchema (adSchemaTables)"
        $c = "sub createdatabase()"
        $d = "Dim regEx,match,matches"
        $e = "for i = 0 to field_num - 1"
        $f = "sub create_table()"
        $g = "select case request(\"key\")"
        $h = "iif((rs(i).Attributes and adFldIsNullable)=0,\"\",\" checked\""
        
    condition:
        all of them
}
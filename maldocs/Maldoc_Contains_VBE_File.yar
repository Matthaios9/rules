
















rule Contains_VBE_File : maldoc
{
    meta:
        description = "Detect a VBE file inside a byte sequence"
        method = "Find string starting with #@~^ and ending with ^#~@"
    strings:
        $vbe = /#@~\^.+\^#~@/
    condition:
        $vbe
}

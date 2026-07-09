rule pe_executable
{
    meta:
        description = "Windows PE executable"
        severity = 5
        author = "Project Aegis"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0
}

rule elf_executable
{
    meta:
        description = "Linux ELF executable"
        severity = 5
        author = "Project Aegis"

    strings:
        $elf = { 7F 45 4C 46 }

    condition:
        $elf at 0
}

rule upx_packed_binary
{
    meta:
        description = "UPX-packed binary — commonly used by malware"
        severity = 7
        author = "Project Aegis"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_magic = "UPX!" ascii

    condition:
        any of them
}

rule autorun_inf
{
    meta:
        description = "Autorun.inf — USB auto-execution vector"
        severity = 8
        author = "Project Aegis"

    strings:
        $autorun = "[autorun]" ascii nocase

    condition:
        $autorun
}

rule encoded_powershell
{
    meta:
        description = "Base64-encoded PowerShell command"
        severity = 8
        author = "Project Aegis"

    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "FromBase64String" ascii
        $enc3 = "powershell -e " ascii nocase
        $enc4 = "powershell.exe -enc" ascii nocase

    condition:
        any of them
}

rule macro_vba_code
{
    meta:
        description = "VBA macro code in Office documents"
        severity = 6
        author = "Project Aegis"

    strings:
        $vba1 = "Sub Auto" ascii
        $vba2 = "Sub Workbook_Open" ascii
        $vba3 = "Sub Document_Open" ascii
        $vba4 = "Shell(" ascii
        $vba5 = "CreateObject" ascii

    condition:
        2 of them
}

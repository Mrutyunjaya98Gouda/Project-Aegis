/*
 * Project Aegis — Base YARA Detection Rules
 * Zero-Trust USB Security Suite
 *
 * These rules are evaluated against raw file buffers read from USB
 * mass storage devices before they are allowed to mount.
 */

rule BadUSB_Rubber_Ducky_Payload
{
    meta:
        description = "Detects common Rubber Ducky / DuckyScript payload patterns"
        author = "Project Aegis"
        severity = "HIGH"

    strings:
        $duck1 = "DELAY" fullword ascii
        $duck2 = "STRING" fullword ascii
        $duck3 = "REM " ascii
        $gui = "GUI r" ascii

    condition:
        2 of them
}

rule Ransomware_Encrypted_Extension_Renamer
{
    meta:
        description = "Detects batch/script files that mass-rename file extensions"
        author = "Project Aegis"
        severity = "CRITICAL"

    strings:
        $ren1 = "ren " nocase ascii wide
        $ren2 = "rename " nocase ascii wide
        $enc_ext = ".encrypted" ascii nocase
        $enc_ext2 = ".locked" ascii nocase
        $enc_ext3 = ".ransom" ascii nocase
        $readme = "README_DECRYPT" ascii nocase

    condition:
        ($ren1 or $ren2) and 1 of ($enc_ext, $enc_ext2, $enc_ext3, $readme)
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "Detects PowerShell download cradles often used for payload delivery"
        author = "Project Aegis"
        severity = "HIGH"

    strings:
        $ps1 = "powershell" nocase wide ascii
        $dl1 = "DownloadString" nocase ascii
        $dl2 = "DownloadFile" nocase ascii
        $dl3 = "Invoke-Expression" nocase ascii
        $dl4 = "IEX " nocase ascii
        $bypass = "-ExecutionPolicy Bypass" nocase ascii

    condition:
        $ps1 and (1 of ($dl1, $dl2, $dl3, $dl4)) and $bypass
}

rule Autorun_Persistence
{
    meta:
        description = "Detects autorun.inf files used for legacy USB auto-execution"
        author = "Project Aegis"
        severity = "MEDIUM"

    strings:
        $autorun = "[autorun]" ascii nocase
        $open = "open=" ascii nocase
        $shellexec = "shellexecute=" ascii nocase

    condition:
        $autorun and ($open or $shellexec)
}

rule HID_Injection_Script
{
    meta:
        description = "Detects HID keystroke injection scripts"
        author = "Project Aegis"
        severity = "HIGH"

    strings:
        $hidstr1 = "HidD_SetOutputReport" ascii
        $hidstr2 = "CreateFile.*HID" ascii
        $hidstr3 = "WriteFile.*keyboard" ascii nocase
        $bash_bomb = "exec bash" ascii
        $cmd_bomb = "cmd /c" ascii nocase

    condition:
        1 of ($hidstr1, $hidstr2, $hidstr3) or
        ($bash_bomb and $cmd_bomb)
}

rule Suspicious_PE_On_USB
{
    meta:
        description = "Detects Windows PE executables on USB devices (unexpected)"
        author = "Project Aegis"
        severity = "MEDIUM"

    strings:
        $mz = { 4D 5A }          // MZ header (PE file)
        $pe = { 50 45 00 00 }    // PE signature

    condition:
        $mz at 0 and $pe
}

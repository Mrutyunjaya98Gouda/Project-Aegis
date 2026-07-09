rule ransomware_note
{
    meta:
        description = "Detects common ransomware note patterns"
        severity = 10
        author = "Project Aegis"

    strings:
        $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $ransom2 = "All your files are encrypted" ascii nocase
        $ransom3 = "pay the ransom" ascii nocase
        $ransom4 = "decrypt your files" ascii nocase
        $ransom5 = "bitcoin wallet" ascii nocase
        $ransom6 = "send bitcoin" ascii nocase
        $ransom7 = "your personal decryption key" ascii nocase

    condition:
        any of them
}

rule suspicious_encryption_artifacts
{
    meta:
        description = "Detects artifacts commonly left by ransomware encryption"
        severity = 8
        author = "Project Aegis"

    strings:
        $ext1 = ".encrypted" ascii nocase
        $ext2 = ".locked" ascii nocase
        $ext3 = ".crypto" ascii nocase
        $ext4 = "HOW_TO_DECRYPT" ascii nocase
        $ext5 = "DECRYPT_INSTRUCTIONS" ascii nocase

    condition:
        2 of them
}

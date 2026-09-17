/*
 * Warden packaged YARA rules: packed executables.
 *
 * Namespace: warden_packed_binaries. Metadata schema, scopes and fast-mode constraints are
 * documented in README.md next to this file; app/analysis/rules validates them at import.
 * UPX has legitimate uses, so these rules are capability-grade (confidence below 0.7): a
 * packed executable in a Python source distribution cannot be reviewed or rebuilt from source.
 * Both rules check the executable header first, so documentation or build scripts that merely
 * mention UPX never match.
 */

rule WX_PACK_UPX_Packed_ELF
{
    meta:
        id = "WX-YARA-070"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "ELF executable carrying UPX packer markers (UPX! header plus the UPX banner)"
        severity = "medium"
        confidence = "0.6"
        attack = "T1027.002"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        false_positives = "UPX is used legitimately to shrink release binaries; inside a source distribution a packed executable is still unreviewable."
        category = "suspicious_artifact"
        capability = "obfuscation"
        cwe = "CWE-912"
        scope = "binary"

    strings:
        $upx_magic = "UPX!"
        $upx_info_banner = "$Info: This file is packed with the UPX"
        $upx_id_banner = "$Id: UPX "

    condition:
        uint32(0) == 0x464C457F and $upx_magic and ($upx_info_banner or $upx_id_banner)
}

rule WX_PACK_UPX_Packed_PE
{
    meta:
        id = "WX-YARA-071"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "PE executable whose section table contains the UPX0 and UPX1 packer sections"
        severity = "medium"
        confidence = "0.6"
        attack = "T1027.002"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        false_positives = "UPX is used legitimately to shrink release binaries (including some launcher stubs); inside a source distribution a packed executable is still unreviewable."
        category = "suspicious_artifact"
        capability = "obfuscation"
        cwe = "CWE-912"
        scope = "binary"

    strings:
        // 8-byte section names "UPX0\0\0\0\0" and "UPX1\0\0\0\0"
        $section_upx0 = { 55 50 58 30 00 00 00 00 }
        $section_upx1 = { 55 50 58 31 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550 and
        $section_upx0 and $section_upx1
}

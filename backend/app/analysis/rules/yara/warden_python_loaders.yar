/*
 * Warden X packaged YARA rules: Python decode-then-execute loaders.
 *
 * Namespace: warden_python_loaders. Metadata schema, scopes and fast-mode constraints are
 * documented in README.md next to this file; app/analysis/rules validates them at import.
 * These rules are designed to detect specific high-signal combinations (an execution
 * primitive applied *directly* to a decoder); a decoder or exec on its own never matches.
 */

rule WX_PY_Exec_Base64_Decoded_Payload
{
    meta:
        id = "WX-YARA-001"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "Python exec/eval applied directly to a base64/base32/base85/hex-decoded payload"
        severity = "critical"
        confidence = "0.9"
        attack = "T1027,T1140,T1059.006"
        reference = "https://attack.mitre.org/techniques/T1140/"
        false_positives = "Self-extracting bootstrap scripts and code-golf or minifier output occasionally exec an embedded encoded payload; decode the payload and review it."
        category = "obfuscation"
        capability = "obfuscation"
        scope = "python,shell,batch,powershell"

    strings:
        // exec( [compile(] [module-or-alias.] decoder(   e.g. exec(base64.b64decode(, eval(b.b85decode(
        $exec_decoder = /\b(exec|eval)\s{0,8}\(\s{0,8}(compile\s{0,8}\(\s{0,8})?(__import__\s{0,4}\(\s{0,4}['"][A-Za-z0-9_]{1,16}['"]\s{0,4}\)\s{0,4}\.\s{0,4}|[A-Za-z_][A-Za-z0-9_]{0,32}\s{0,4}\.\s{0,4}){0,2}(b64decode|b32decode|b32hexdecode|b85decode|b16decode|a85decode|standard_b64decode|urlsafe_b64decode|decodebytes|decodestring|a2b_base64|unhexlify|a2b_hex|fromhex)\s{0,8}\(/
        // exec(codecs.decode(<data>, "base64"))
        $exec_codecs = /\b(exec|eval)\s{0,8}\(\s{0,8}(compile\s{0,8}\(\s{0,8})?codecs\s{0,4}\.\s{0,4}decode\s{0,8}\([^\n]{1,2048}['"](base64|base_64|base-64|hex|hex_codec|rot13|rot_13|zlib|zlib_codec|bz2|bz2_codec)['"]/

    condition:
        any of them
}

rule WX_PY_Exec_Decompressed_Or_Unmarshalled_Code
{
    meta:
        id = "WX-YARA-002"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "Python exec/eval applied directly to decompressed (zlib/lzma/bz2/gzip) or unmarshalled (marshal) data"
        severity = "critical"
        confidence = "0.9"
        attack = "T1027,T1140,T1059.006"
        reference = "https://attack.mitre.org/techniques/T1027/"
        false_positives = "Frozen-application bootstraps can exec unmarshalled bytecode; normal import machinery assigns the loaded code first and does not nest exec around the loader call."
        category = "obfuscation"
        capability = "obfuscation"
        scope = "python,shell,batch,powershell"

    strings:
        $exec_decompress = /\b(exec|eval)\s{0,8}\(\s{0,8}(compile\s{0,8}\(\s{0,8})?(__import__\s{0,4}\(\s{0,4}['"][A-Za-z0-9_]{1,16}['"]\s{0,4}\)\s{0,4}\.\s{0,4}|[A-Za-z_][A-Za-z0-9_]{0,32}\s{0,4}\.\s{0,4}){0,2}decompress\s{0,8}\(/
        // exec(marshal.loads(  /  exec(__import__('marshal').loads(  /  exec(loads(  (not json.loads)
        $exec_marshal = /\b(exec|eval)\s{0,8}\(\s{0,8}(marshal\s{0,4}\.\s{0,4}|__import__\s{0,4}\(\s{0,4}['"]marshal['"]\s{0,4}\)\s{0,4}\.\s{0,4})?loads\s{0,8}\(/

    condition:
        any of them
}

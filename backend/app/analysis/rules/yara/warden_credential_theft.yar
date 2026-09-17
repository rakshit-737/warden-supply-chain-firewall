/*
 * Warden packaged YARA rules: credential theft from browsers and chat clients.
 *
 * Namespace: warden_credential_theft. Metadata schema, scopes and fast-mode constraints are
 * documented in README.md next to this file; app/analysis/rules validates them at import.
 * Every rule requires a combination of artefacts that only credential-store access needs;
 * a single browser path or API name never matches on its own.
 */

rule WX_CRED_Chromium_Master_Key_Decryption
{
    meta:
        id = "WX-YARA-010"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Reads the Chromium 'Local State' encrypted_key and decrypts it with DPAPI CryptUnprotectData (browser master-key theft)"
        severity = "critical"
        confidence = "0.85"
        attack = "T1555.003"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
        false_positives = "Cookie-export and browser-forensics utilities perform the same decryption on purpose; confirm the package's stated purpose before allowing it."
        category = "credential_access"
        capability = "credential_access"
        scope = "python,powershell,batch,javascript,shell,binary"

    strings:
        $local_state = "Local State" ascii wide
        $encrypted_key = "encrypted_key" ascii wide
        $dpapi = "CryptUnprotectData" ascii wide

    condition:
        all of them
}

rule WX_CRED_Chromium_Login_Data_Passwords
{
    meta:
        id = "WX-YARA-011"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Opens a Chromium 'Login Data' SQLite database and reads the saved password_value column"
        severity = "critical"
        confidence = "0.85"
        attack = "T1555.003"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
        false_positives = "Password-manager import tools and browser-forensics utilities read the same table; confirm the package's stated purpose before allowing it."
        category = "credential_access"
        capability = "credential_access"
        scope = "python,powershell,batch,javascript,shell,binary"

    strings:
        $login_data = "Login Data" ascii wide
        $password_value = "password_value" ascii wide
        $sqlite = "sqlite" nocase ascii wide
        $logins_query = /select\s[^;\n]{0,256}from\s{1,8}logins\b/ nocase ascii wide

    condition:
        $login_data and $password_value and ($sqlite or $logins_query)
}

rule WX_CRED_Firefox_Credential_Store
{
    meta:
        id = "WX-YARA-012"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "References both Firefox credential stores: the NSS key database key4.db and the saved-logins file logins.json"
        severity = "critical"
        confidence = "0.8"
        attack = "T1555.003"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
        false_positives = "Firefox password-recovery and export tools name both files deliberately; profile backup tools usually copy whole directories instead."
        category = "credential_access"
        capability = "credential_access"
        scope = "python,powershell,batch,javascript,shell,binary"

    strings:
        $key4 = "key4.db" ascii wide
        $logins_json = "logins.json" ascii wide

    condition:
        all of them
}

rule WX_CRED_Discord_Token_Grabber_Webhook
{
    meta:
        id = "WX-YARA-013"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Discord token harvesting (token regex, encrypted-token prefix or client LevelDB storage path) combined with a Discord webhook for exfiltration"
        severity = "critical"
        confidence = "0.9"
        attack = "T1528,T1567.004"
        reference = "https://attack.mitre.org/techniques/T1528/"
        false_positives = "Discord bots and notification code use webhooks but do not carry token-extraction regexes or read the Discord client's LevelDB store; security research tooling that documents grabbers can match."
        category = "credential_access"
        capability = "credential_access"
        scope = "python,javascript,powershell,batch,shell,binary"

    strings:
        // The text of a token regex such as [\w-]{24}\.[\w-]{6}\.[\w-]{27} (raw or escaped string).
        $token_regex = /\{2[3-6](,[0-9]{1,3})?\}(\\){1,2}\.\[[^\]\n]{1,32}\]\{6\}(\\){1,2}\./
        $mfa_token_regex = /mfa(\\){1,2}\.\[[^\]\n]{1,32}\]\{84\}/
        $encrypted_token_prefix = "dQw4w9WgXcQ:"
        $local_storage = "Local Storage" ascii wide
        $leveldb = "leveldb" ascii wide
        $discord_client_dir = /[\\\/'"](discord|discordcanary|discordptb|lightcord)[\\\/'"]/ nocase ascii wide
        $webhook = /discord(app)?\.com\/api\/webhooks\// nocase ascii wide

    condition:
        $webhook and ($token_regex or $mfa_token_regex or $encrypted_token_prefix or
                      ($local_storage and $leveldb and $discord_client_dir))
}

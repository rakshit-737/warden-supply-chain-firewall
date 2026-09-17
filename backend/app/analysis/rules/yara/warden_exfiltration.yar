/*
 * Warden packaged YARA rules: exfiltration of harvested credentials.
 *
 * Namespace: warden_exfiltration. Metadata schema, scopes and fast-mode constraints are
 * documented in README.md next to this file; app/analysis/rules validates them at import.
 * Chat webhooks and bot APIs are everyday notification channels. These rules only match when
 * the same file also serialises the whole environment or names credential stores; reading a
 * single configuration variable (such as the webhook URL itself) is deliberately not enough.
 */

rule WX_EXFIL_Telegram_Bot_Credential_Exfiltration
{
    meta:
        id = "WX-YARA-050"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Sends data through the Telegram Bot API from code that also dumps the environment or names credential stores"
        severity = "critical"
        confidence = "0.85"
        attack = "T1567,T1552.001"
        reference = "https://attack.mitre.org/techniques/T1567/"
        false_positives = "Telegram notification helpers read their own bot token from the environment; they do not serialise the whole environment or open credential files, which this rule requires."
        category = "malicious_behavior"
        capability = "credential_access"
        scope = "python,javascript,powershell,batch,shell"

    strings:
        $telegram_api = /api\.telegram\.org\/bot/ nocase
        $telegram_send = /\bsend(Document|Message|Photo|MediaGroup)\b/
        $environment_dump = /(json\s{0,4}\.\s{0,4}dumps\s{0,4}\(\s{0,4}(dict\s{0,4}\(\s{0,4})?os\s{0,4}\.\s{0,4}environ\b|\b(str|repr)\s{0,4}\(\s{0,4}os\s{0,4}\.\s{0,4}environ\s{0,4}\)|\{\s{0,4}os\s{0,4}\.\s{0,4}environ\s{0,4}\}|JSON\s{0,4}\.\s{0,4}stringify\s{0,4}\(\s{0,4}process\s{0,4}\.\s{0,4}env\s{0,4}\)|Get-ChildItem\s{1,8}env:|\bprintenv\b)/
        $credential_store = /(\.aws(\\){0,2}[\\\/]credentials|\.aws['"]\s{0,4},\s{0,4}['"]credentials['"]|\bid_(rsa|dsa|ecdsa|ed25519)\b|\.git-credentials|\.pypirc|\.npmrc|\.docker(\\){0,2}[\\\/]config\.json|\.kube(\\){0,2}[\\\/]config\b|Login Data|Local State|wallet\.dat|key4\.db|cookies\.sqlite|Network(\\){0,2}[\\\/]Cookies)/

    condition:
        $telegram_api and $telegram_send and ($environment_dump or $credential_store)
}

rule WX_EXFIL_Discord_Webhook_Credential_Exfiltration
{
    meta:
        id = "WX-YARA-051"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Posts to a Discord webhook from code that also dumps the environment or names credential stores"
        severity = "critical"
        confidence = "0.85"
        attack = "T1567.004,T1552.001"
        reference = "https://attack.mitre.org/techniques/T1567/004/"
        false_positives = "Discord notification code (for example discord.py Webhook usage) posts messages without dumping the environment or naming credential files, and does not match."
        category = "malicious_behavior"
        capability = "credential_access"
        scope = "python,javascript,powershell,batch,shell"

    strings:
        $discord_webhook = /discord(app)?\.com\/api\/webhooks\// nocase
        $environment_dump = /(json\s{0,4}\.\s{0,4}dumps\s{0,4}\(\s{0,4}(dict\s{0,4}\(\s{0,4})?os\s{0,4}\.\s{0,4}environ\b|\b(str|repr)\s{0,4}\(\s{0,4}os\s{0,4}\.\s{0,4}environ\s{0,4}\)|\{\s{0,4}os\s{0,4}\.\s{0,4}environ\s{0,4}\}|JSON\s{0,4}\.\s{0,4}stringify\s{0,4}\(\s{0,4}process\s{0,4}\.\s{0,4}env\s{0,4}\)|Get-ChildItem\s{1,8}env:|\bprintenv\b)/
        $credential_store = /(\.aws(\\){0,2}[\\\/]credentials|\.aws['"]\s{0,4},\s{0,4}['"]credentials['"]|\bid_(rsa|dsa|ecdsa|ed25519)\b|\.git-credentials|\.pypirc|\.npmrc|\.docker(\\){0,2}[\\\/]config\.json|\.kube(\\){0,2}[\\\/]config\b|Login Data|Local State|wallet\.dat|key4\.db|cookies\.sqlite|Network(\\){0,2}[\\\/]Cookies)/

    condition:
        $discord_webhook and ($environment_dump or $credential_store)
}

rule WX_EXFIL_Environment_Dump_With_Host_Identity
{
    meta:
        id = "WX-YARA-052"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Serialises the whole process environment together with host identity (hostname, user name) in code that sends HTTP requests"
        severity = "high"
        confidence = "0.8"
        attack = "T1041,T1552.001,T1082"
        reference = "https://attack.mitre.org/techniques/T1041/"
        false_positives = "Diagnostic bug-report helpers collect host details, but rarely serialise the complete environment; review the destination before allowing."
        category = "malicious_behavior"
        capability = "env_harvest"
        scope = "python,javascript"

    strings:
        $environment_dump = /(json\s{0,4}\.\s{0,4}dumps\s{0,4}\(\s{0,4}(dict\s{0,4}\(\s{0,4})?os\s{0,4}\.\s{0,4}environ\b|\b(str|repr)\s{0,4}\(\s{0,4}os\s{0,4}\.\s{0,4}environ\s{0,4}\)|\{\s{0,4}os\s{0,4}\.\s{0,4}environ\s{0,4}\}|JSON\s{0,4}\.\s{0,4}stringify\s{0,4}\(\s{0,4}process\s{0,4}\.\s{0,4}env\s{0,4}\))/
        $host_identity = /(socket\s{0,4}\.\s{0,4}gethostname|platform\s{0,4}\.\s{0,4}node|getpass\s{0,4}\.\s{0,4}getuser|os\s{0,4}\.\s{0,4}getlogin|os\s{0,4}\.\s{0,4}hostname|os\s{0,4}\.\s{0,4}userInfo)\s{0,4}\(/
        $http_send = /(requests\s{0,4}\.\s{0,4}(post|put)|urllib\s{0,4}\.\s{0,4}request\s{0,4}\.\s{0,4}(urlopen|Request)|\burlopen|httpx\s{0,4}\.\s{0,4}(post|put)|HTTPS?Connection|https?\s{0,4}\.\s{0,4}request|\bfetch)\s{0,4}\(/

    condition:
        all of them
}

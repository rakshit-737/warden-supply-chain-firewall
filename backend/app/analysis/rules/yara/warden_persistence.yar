/*
 * Warden packaged YARA rules: persistence.
 *
 * Namespace: warden_persistence. Metadata schema, scopes and fast-mode constraints are
 * documented in README.md next to this file; app/analysis/rules validates them at import.
 * Cron, systemd and shell profiles are managed by legitimate tools too, so the Unix rules
 * require the persisted command itself to download, decode or connect out. Windows Run-key
 * registration alone is capability-grade.
 */

rule WX_PERSIST_Cron_Entry_With_Remote_Payload
{
    meta:
        id = "WX-YARA-040"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Installs a cron entry whose command downloads, decodes or connects out (curl/wget pipe, /dev/tcp, base64 -d)"
        severity = "critical"
        confidence = "0.85"
        attack = "T1053.003"
        reference = "https://attack.mitre.org/techniques/T1053/003/"
        false_positives = "Legitimate cron entries rarely pipe downloads into a shell; self-updating agents installed by system administrators are the main exception."
        category = "malicious_behavior"
        capability = "persistence"
        scope = "python,shell"

    strings:
        $echo_payload_to_crontab = /(echo|printf)\s[^\n]{0,512}(\b(curl|wget)\s|\/dev\/(tcp|udp)\/|\bbase64\s{1,4}(-d|--decode)\b|\bpython[23]?\s{1,4}-c\s)[^\n]{0,512}\|\s{0,8}crontab\s{1,8}-/
        $cron_dir_payload = /\/etc\/cron\.(d|hourly|daily|weekly|monthly)\/[^\n]{0,512}(\b(curl|wget)\s|\/dev\/(tcp|udp)\/|\bbase64\s{1,4}(-d|--decode)\b)/
        $schedule_download_to_shell = /(@reboot|@hourly|@daily|(\*|[0-9]{1,2})(\/[0-9]{1,2})?\s{1,4}(\*|[0-9]{1,2})(\/[0-9]{1,2})?\s{1,4}\*\s{1,4}\*\s{1,4}\*)\s{1,8}[^\n]{0,256}\b(curl|wget)\s[^\n|]{0,512}\|\s{0,8}((\/usr)?\/bin\/)?(ba|z|da|k)?sh\b/

    condition:
        any of them
}

rule WX_PERSIST_Systemd_Service_With_Remote_Payload
{
    meta:
        id = "WX-YARA-041"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Writes a systemd unit whose ExecStart downloads, decodes, or runs from a temporary directory"
        severity = "critical"
        confidence = "0.85"
        attack = "T1543.002"
        reference = "https://attack.mitre.org/techniques/T1543/002/"
        false_positives = "Unit files legitimately start installed daemons; ExecStart commands that fetch remote content or run from /tmp or /dev/shm are rare in real services."
        category = "malicious_behavior"
        capability = "persistence"
        scope = "python,shell"

    strings:
        $unit_location = /(\/etc\/systemd\/system\/|\/lib\/systemd\/system\/|\.config\/systemd\/user\/)/
        $systemctl_enable = /\bsystemctl\s{1,8}(--user\s{1,8})?(enable|start|daemon-reload)\b/
        $execstart_payload = /ExecStart\s{0,4}=\s{0,4}[^\n]{0,512}(\b(curl|wget)\s|\/dev\/(tcp|udp)\/|\bbase64\s{1,4}(-d|--decode)\b|\bpython[23]?\s{1,4}-c\s|\/tmp\/|\/dev\/shm\/)/

    condition:
        $execstart_payload and ($unit_location or $systemctl_enable)
}

rule WX_PERSIST_Windows_Run_Key_Autostart
{
    meta:
        id = "WX-YARA-042"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Writes a value under the Windows CurrentVersion Run/RunOnce autostart registry keys"
        severity = "high"
        confidence = "0.65"
        attack = "T1547.001"
        reference = "https://attack.mitre.org/techniques/T1547/001/"
        false_positives = "Desktop applications with a 'start at login' option write the same keys; capability-grade, but unusual for a library."
        category = "capability"
        capability = "persistence"
        scope = "python,powershell,batch,javascript"

    strings:
        $run_key = /Software\\{1,2}Microsoft\\{1,2}Windows\\{1,2}CurrentVersion\\{1,2}Run(Once)?\b/ nocase
        $registry_write = /\b(SetValueEx|reg(\.exe)?\s{1,8}add|New-ItemProperty|Set-ItemProperty)\b/ nocase

    condition:
        $run_key and $registry_write
}

rule WX_PERSIST_Shell_Profile_Remote_Payload
{
    meta:
        id = "WX-YARA-043"
        version = "1.0.0"
        author = "Warden"
        date = "2026-09-16"
        description = "Appends a command that downloads, decodes or connects out to a shell start-up profile (.bashrc, .zshrc, .profile)"
        severity = "critical"
        confidence = "0.85"
        attack = "T1546.004"
        reference = "https://attack.mitre.org/techniques/T1546/004/"
        false_positives = "Tool installers append PATH or init lines to shell profiles; lines that fetch remote content or open network connections are not part of normal setup."
        category = "malicious_behavior"
        capability = "persistence"
        scope = "python,shell"

    strings:
        $echo_payload_to_profile = /(echo|printf)\s[^\n]{0,512}(\b(curl|wget)\s|\/dev\/(tcp|udp)\/|\bbase64\s{1,4}(-d|--decode)\b|\b(nc|ncat)\s{1,8}(-[a-z]{1,4}\s{1,8}){0,4}-e\s|\bpython[23]?\s{1,4}-c\s)[^\n]{0,512}>>\s{0,4}['"]?(~|\$HOME|\$\{HOME\})\/\.(bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|profile)\b/
        $python_profile_append_payload = /\.(bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|profile)['"][^\n]{0,128}['"]a\+?['"][^\n]{0,512}(\b(curl|wget)\s|\/dev\/(tcp|udp)\/|\bbase64\s{1,4}(-d|--decode)\b)/

    condition:
        any of them
}

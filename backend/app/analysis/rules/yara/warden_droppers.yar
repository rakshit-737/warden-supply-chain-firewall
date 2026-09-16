/*
 * Warden X packaged YARA rules: download-and-execute droppers.
 *
 * Namespace: warden_droppers. Metadata schema, scopes and fast-mode constraints are
 * documented in README.md next to this file; app/analysis/rules validates them at import.
 * Remote-script bootstrap one-liners are also common in legitimate tooling, so the plain
 * idioms are capability-grade (confidence below 0.7); only hidden/encoded PowerShell launch
 * and shelling out from Python code carry higher confidence.
 */

rule WX_DROP_Shell_Script_Curl_Pipe_Shell
{
    meta:
        id = "WX-YARA-030"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "Shell script pipes a curl/wget download straight into a shell interpreter"
        severity = "high"
        confidence = "0.6"
        attack = "T1105,T1059.004"
        reference = "https://attack.mitre.org/techniques/T1105/"
        false_positives = "Common in legitimate CI and toolchain bootstrap scripts (for example rustup or Homebrew installers); capability-grade, review the URL and why the package ships the script."
        category = "capability"
        capability = "shell_invocation"
        scope = "shell"

    strings:
        $pipe_to_shell = /\b(curl|wget)\s[^\n|;&]{0,512}\|\s{0,8}(sudo\s{1,8}(-[A-Za-z]{1,16}\s{1,8}){0,3})?((\/usr)?\/bin\/)?(env\s{1,8})?(ba|z|da|k)?sh\b/
        $shell_c_substitution = /\b(ba|z|da|k)?sh\s{1,8}-c\s{1,8}["']?\$\(\s{0,4}(curl|wget)\s/
        $shell_process_substitution = /\b(ba|z)?sh\s{1,8}<\s{0,4}\(\s{0,4}(curl|wget)\s/

    condition:
        any of them
}

rule WX_DROP_Python_Shell_Download_Execute
{
    meta:
        id = "WX-YARA-031"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "Python code runs a shell command that pipes a curl/wget download into a shell interpreter"
        severity = "high"
        confidence = "0.75"
        attack = "T1105,T1059.004,T1059.006"
        reference = "https://attack.mitre.org/techniques/T1105/"
        false_positives = "A few build scripts bootstrap toolchains this way (for example installing Rust from setup.py); even then the package executes unverified remote code."
        category = "malicious_behavior"
        capability = "shell_invocation"
        scope = "python"

    strings:
        // <call>( ... curl|wget ... | sh   (the call's argument may span lines up to the closing parenthesis)
        $call_pipe_to_shell = /\b(system|popen|run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s{0,4}\([^)]{0,512}\b(curl|wget)\s[^|)]{0,512}\|\s{0,8}(sudo\s{1,8})?((\/usr)?\/bin\/)?(ba|z|da|k)?sh\b/

    condition:
        $call_pipe_to_shell
}

rule WX_DROP_PowerShell_Download_Cradle
{
    meta:
        id = "WX-YARA-032"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "PowerShell download cradle: Invoke-Expression (IEX) evaluating content fetched with DownloadString, Invoke-WebRequest or Invoke-RestMethod"
        severity = "high"
        confidence = "0.65"
        attack = "T1059.001,T1105"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        false_positives = "Package-manager bootstrap one-liners (Chocolatey, Scoop) use the same idiom in CI scripts; capability-grade, review what is downloaded and when it runs."
        category = "capability"
        capability = "shell_invocation"
        scope = "powershell,batch,python,shell,javascript"

    strings:
        $iex_of_download = /\b(iex|invoke-expression)\b[^\n]{0,256}\b(downloadstring|downloaddata|invoke-webrequest|invoke-restmethod|iwr|irm)\b/ nocase
        $download_piped_to_iex = /\b(downloadstring|invoke-webrequest|invoke-restmethod|iwr|irm)\b[^\n]{0,256}\|\s{0,8}(iex|invoke-expression)\b/ nocase

    condition:
        any of them
}

rule WX_DROP_PowerShell_Hidden_Encoded_Execution
{
    meta:
        id = "WX-YARA-033"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "Launches PowerShell with a hidden window and an encoded command, or with a hidden window, execution-policy bypass and a download"
        severity = "critical"
        confidence = "0.85"
        attack = "T1059.001,T1027,T1564.003"
        reference = "https://attack.mitre.org/techniques/T1564/003/"
        false_positives = "Some enterprise deployment scripts start hidden PowerShell with encoded commands; this combination is rare in open-source packages."
        category = "malicious_behavior"
        capability = "shell_invocation"
        scope = "python,batch,powershell,shell,javascript"

    strings:
        // Flags must follow "powershell" on the same command line (shell text or a Python argv list:
        // quotes and commas are accepted as separators). Abbreviated flag spellings are included.
        $hidden_window = /\bpowershell(\.exe)?['"]?[\s,][^\n]{0,512}[\s'"][-\/]w(i|in|ind|indo|indow|indows|indowst|indowsty|indowstyl|indowstyle)?['",\s]{1,8}(h|hi|hid|hidd|hidde|hidden|1)\b/ nocase
        $encoded_command = /\bpowershell(\.exe)?['"]?[\s,][^\n]{0,512}[\s'"][-\/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?['",\s]{1,8}[A-Za-z0-9+\/]{40,4096}/ nocase
        $policy_bypass = /\bpowershell(\.exe)?['"]?[\s,][^\n]{0,512}[\s'"][-\/](ep|ex|exe|exec|execu|execut|executi|executio|execution|executionp|executionpo|executionpol|executionpoli|executionpolic|executionpolicy)['",\s]{1,8}(bypass|unrestricted)\b/ nocase
        $download = /\b(downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient)\b/ nocase

    condition:
        $hidden_window and ($encoded_command or ($policy_bypass and $download))
}

/*
 * Warden X packaged YARA rules: reverse shells.
 *
 * Namespace: warden_reverse_shells. Metadata schema, scopes and fast-mode constraints are
 * documented in README.md next to this file; app/analysis/rules validates them at import.
 * Sockets, pty.spawn and /dev/tcp each have benign uses; the rules require the redirection
 * of an outbound connection onto an interactive shell.
 */

rule WX_SHELL_Python_Socket_Reverse_Shell
{
    meta:
        id = "WX-YARA-020"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "Python reverse shell: an outbound socket wired to stdin/stdout/stderr and an interactive shell spawned"
        severity = "critical"
        confidence = "0.9"
        attack = "T1059.006,T1059.004"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        false_positives = "Remote-administration or debugging tools that deliberately expose an interactive shell over a socket; offensive-security payload generators."
        category = "malicious_behavior"
        capability = "shell_invocation"
        scope = "python"

    strings:
        $connect = /\.connect\s{0,4}\(\s{0,4}\(/
        $create_connection = /create_connection\s{0,4}\(\s{0,4}\(/
        $dup2_socket_fileno = /dup2\s{0,4}\(\s{0,4}[A-Za-z_][A-Za-z0-9_.]{0,64}\s{0,4}\.\s{0,4}fileno\s{0,4}\(\s{0,4}\)\s{0,4},\s{0,4}[012]\s{0,4}\)/
        $stdio_socket_fileno = /std(in|out|err)\s{0,4}=\s{0,4}[A-Za-z_][A-Za-z0-9_.]{0,64}\s{0,4}\.\s{0,4}fileno\s{0,4}\(\s{0,4}\)/
        $pty_spawn_shell = /pty\s{0,4}\.\s{0,4}spawn\s{0,4}\(\s{0,4}\[?\s{0,4}['"]((\/usr)?\/bin\/)?(ba|z|da|k|c|tc)?sh['"]/
        $interactive_shell_argv = /['"]((\/usr)?\/bin\/)?(ba|z|da|k)?sh['"]\s{0,4},\s{0,4}['"]-i['"]/
        $interactive_shell_cmd = /['"]((\/usr)?\/bin\/)?(ba|z|da|k)?sh\s{1,4}-i['"]/

    condition:
        ($connect or $create_connection) and
        ($dup2_socket_fileno or $stdio_socket_fileno) and
        ($pty_spawn_shell or $interactive_shell_argv or $interactive_shell_cmd)
}

rule WX_SHELL_Unix_Reverse_Shell_One_Liner
{
    meta:
        id = "WX-YARA-021"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "Unix reverse-shell one-liner: interactive shell redirected to /dev/tcp, netcat -e shell, or mkfifo shell relay"
        severity = "critical"
        confidence = "0.9"
        attack = "T1059.004"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        false_positives = "Offensive-security tooling (payload generators, CTF helpers) ships these one-liners as templates; port checks such as 'echo > /dev/tcp/host/port' do not match."
        category = "malicious_behavior"
        capability = "shell_invocation"
        scope = "python,shell,powershell,batch,javascript"

    strings:
        $dev_tcp_interactive = /\b(ba|z|k)?sh\s{1,8}-i\s{1,8}(>&|&>|>\s{0,2}&)\s{0,4}\/dev\/(tcp|udp)\/[^\s\/'"]{1,255}\/[0-9$]/
        $netcat_exec_shell = /\b(nc|ncat|netcat)(\.traditional|\.openbsd)?\s{1,8}([^\n|;&]{0,64}\s)?-e\s{1,8}['"]?((\/usr)?\/bin\/)?(ba|z|da|k)?sh\b/
        $mkfifo_shell_relay = /mkfifo\s{1,8}[^\s;]{1,128}\s{0,8};[^\n]{0,128}\|\s{0,4}((\/usr)?\/bin\/)?(ba|z|da|k)?sh\s{1,8}-i\b[^\n]{0,128}\|\s{0,4}(nc|ncat|netcat|openssl)\b/

    condition:
        any of them
}

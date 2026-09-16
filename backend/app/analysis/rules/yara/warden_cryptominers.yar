/*
 * Warden X packaged YARA rules: cryptocurrency miners.
 *
 * Namespace: warden_cryptominers. Metadata schema, scopes and fast-mode constraints are
 * documented in README.md next to this file; app/analysis/rules validates them at import.
 * A stratum URL alone appears in pool-protocol libraries and a miner name alone appears in
 * benchmarks and documentation; the rule requires pool connection details together with
 * miner software names or miner-specific options.
 */

rule WX_MINER_Stratum_Pool_With_Miner_Software
{
    meta:
        id = "WX-YARA-060"
        version = "1.0.0"
        author = "Warden X"
        date = "2026-09-16"
        description = "Mining-pool connection details (stratum URL or well-known pool host) combined with cryptocurrency-miner software names or options"
        severity = "high"
        confidence = "0.85"
        attack = "T1496"
        reference = "https://attack.mitre.org/techniques/T1496/"
        false_positives = "Mining-pool dashboards, miner wrappers that declare mining as their purpose, and blockchain research code reference pools and miner names; confirm the package's stated purpose."
        category = "malicious_behavior"
        scope = "python,shell,powershell,batch,javascript,config,binary"

    strings:
        $stratum_url = /stratum[12]?\+(tcp|ssl|tls):\/\/[A-Za-z0-9.\-]{1,253}/ nocase ascii wide
        $pool_host = /\b(supportxmr\.com|minexmr\.com|moneroocean\.stream|nanopool\.org|2miners\.com|hashvault\.pro|herominers\.com|c3pool\.com|unmineable\.com|nicehash\.com|f2pool\.com|ethermine\.org)\b/ nocase ascii wide
        $miner_software = /\b(xmrig|xmr-stak|cpuminer|minerd|ethminer|nbminer|lolminer|phoenixminer|srbminer|teamredminer|nanominer|ccminer|cgminer|bfgminer|gminer|t-rex)\b/ nocase ascii wide
        $miner_option = /(--donate-level|"donate-level"|--randomx|\brx\/0\b|--coin[= ](monero|xmr)\b)/ nocase ascii wide

    condition:
        ($stratum_url or $pool_host) and ($miner_software or $miner_option)
}

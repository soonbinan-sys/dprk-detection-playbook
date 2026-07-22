/*
 * dprk_npm_supply_chain_indicators.yar
 *
 * Two rules, deliberately kept separate in purpose.
 *
 * The first is IOC based, tied to one campaign's known artifact name.
 * Short shelf life by design, rotate or retire it as reporting moves
 * on. Useful for a fast historical sweep, not a durable detection.
 *
 * The second is a technique level heuristic for npm packages that
 * combine an install time lifecycle script with network calls or
 * common obfuscation patterns. Not tied to one campaign, meant to
 * survive the next one.
 */

rule DPRK_NPM_Known_Malicious_Package_Name
{
    meta:
        description = "Flags package.json dependency entries matching a package name publicly attributed to the March 2026 UNC1069 axios npm supply chain compromise"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package"
        author = "Sam An"
        date = "2026-07-17"
        type = "IOC, short shelf life"
    strings:
        $pkg1 = "plain-crypto-js" nocase
    condition:
        any of them
}

rule Suspicious_NPM_Package_Lifecycle_Network_Heuristic
{
    meta:
        description = "Heuristic for package.json files defining a postinstall or preinstall lifecycle script alongside code referencing raw network calls or common obfuscation patterns. Technique level, not tied to a specific campaign."
        author = "Sam An"
        date = "2026-07-17"
        type = "heuristic, technique level"
    strings:
        $lifecycle1 = "\"postinstall\"" nocase
        $lifecycle2 = "\"preinstall\"" nocase
        $net1 = "XMLHttpRequest" nocase
        $net2 = "fetch(" nocase
        $obf1 = /eval\(atob\(/ nocase
        $obf2 = "String.fromCharCode" nocase
    condition:
        (any of ($lifecycle*)) and (any of ($net*) or any of ($obf*))
}

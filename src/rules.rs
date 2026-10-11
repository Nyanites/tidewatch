//! The built-in detection rule library. See `detect.rs` for the rule format.
//!
//! Rules are translated from maintained public detection content — mainly SigmaHQ, plus
//! Splunk, Elastic and Hayabusa where Sigma has no equivalent — into the app's query
//! language. Every rule cites its sources. Where a rule had to deviate (for example to match
//! raw EVTX value formats), its description says so.
//!
//! Query language reminders: terms are ANDed; `Field=v` equals, `Field:v` contains,
//! `Field~re` is a regex; matching is case-insensitive; `-` negates a term.

use crate::detect::{Rule, Severity, Tactic, Threshold};

const SECURITY: &str = "Microsoft-Windows-Security-Auditing";
const SYSMON: &str = "Microsoft-Windows-Sysmon";
const EVENTLOG: &str = "Microsoft-Windows-Eventlog";
const DEFENDER: &str = "Microsoft-Windows-Windows Defender";
const FIREWALL: &str = "Microsoft-Windows-Windows Firewall With Advanced Security";
const POWERSHELL: &str = "Microsoft-Windows-PowerShell";
/// The classic "Windows PowerShell" log (events 400/600/800).
const POWERSHELL_CLASSIC: &str = "PowerShell";
const SCM: &str = "Service Control Manager";
const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";

/// Event 104: the cleared log is one Sigma lists as security-relevant.
const IMPORTANT_LOG: &str = r#"LogFileCleared.Channel~"^(Security|System|Windows PowerShell|Microsoft-Windows-PowerShell/Operational|PowerShellCore/Operational|Microsoft-Windows-Sysmon/Operational)$""#;

/// DS-Replication-Get-Changes(-All), Replication-Synchronize and In-Filtered-Set rights.
/// Used by DCSync (4662) and DCSync-rights backdoor (5136) rules.
macro_rules! replication_guids {
    () => {
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|9923a32a-3607-11d2-b9be-0000f87a36b2|89e95b76-444d-4c62-991a-0facbeda640c"
    };
}

/// Builds a SigmaHQ rule URL from a path under `rules/windows/`.
macro_rules! sigma {
    ($path:literal) => {
        concat!(
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/",
            $path
        )
    };
}

/// Excludes private, loopback and link-local source addresses (IPv4, IPv4-mapped IPv6 and
/// IPv6 fc00::/7, fe80::/10) and empty ones.
macro_rules! not_private_ip {
    () => {
        r#"-IpAddress~"^(::ffff:)?(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)|^::1$|^f[cd][0-9a-f]{2}:|^fe[89ab][0-9a-f]:|^-?$""#
    };
}

/// Audit subcategories Sigma treats as critical (event 4719 SubcategoryGuid):
/// Security State Change, Security System Extension, System Integrity, Logon, Special Logon,
/// Process Creation, Audit Policy Change, Authentication Policy Change, User/Computer Account
/// and Security Group Management, Credential Validation, Kerberos Service Ticket Operations
/// and Kerberos Authentication Service.
macro_rules! critical_audit_guids {
    () => {
        "0CCE92(10|11|12|15|1B|2B|2F|30|35|36|37|3F|40|42)-69AE-11D9-BED3-505054503030"
    };
}

pub const RULES: &[Rule] = &[
    // ------------------------------------------------------------------ Credential Access
    Rule {
        id: "kerberoasting_rc4",
        name: "Kerberoasting: RC4 service ticket requested",
        author: "@kostastsale",
        tactic: Tactic::CredentialAccess,
        mitre: "T1558.003",
        severity: Severity::Medium,
        description: "A Kerberos service ticket was issued with RC4 encryption (0x17) for a user \
            service account. Attackers request RC4 tickets because they can be cracked offline \
            to recover the service account's password. Logged on domain controllers. \
            Does not catch Kerberoasting that requests AES tickets.",
        providers: &[SECURITY],
        event_ids: &[4769],
        any_of: &[r#"TicketEncryptionType=0x17 Status=0x0 -ServiceName~"\$$" -ServiceName~"krbtgt$" -TargetUserName:$@"#],
        threshold: None,
        false_positives: "Legacy applications or service accounts that only support RC4.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberoasting_activity.yml",
            "https://github.com/splunk/security_content/blob/develop/detections/endpoint/kerberoasting_spn_request_with_rc4_encryption.yml",
        ],
    },
    Rule {
        id: "asrep_roasting",
        name: "AS-REP Roasting: TGT issued without pre-authentication",
        author: "ANosir",
        tactic: Tactic::CredentialAccess,
        mitre: "T1558.004",
        severity: Severity::Medium,
        description: "A Kerberos TGT was issued with RC4 encryption to an account that does not \
            require pre-authentication (PreAuthType 0). Such responses can be cracked offline \
            to recover the account's password.",
        providers: &[SECURITY],
        event_ids: &[4768],
        any_of: &["TicketEncryptionType=0x17 ServiceName=krbtgt PreAuthType=0"],
        threshold: None,
        false_positives: "Accounts that legitimately have Kerberos pre-authentication disabled; legacy RC4 clients.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml",
        ],
    },
    Rule {
        id: "kerberos_password_spray",
        name: "Password spraying: Kerberos pre-auth failures for many users from one source",
        author: "Mauricio Velazco, frack113",
        tactic: Tactic::CredentialAccess,
        mitre: "T1110.003",
        severity: Severity::Medium,
        description: "More than 10 different user accounts failed Kerberos pre-authentication \
            with a wrong password (0x18) from the same IP address within 24 hours. Computer \
            accounts are excluded because stale machine passwords produce these failures \
            routinely. Threshold from Sigma; Splunk uses more than 30 accounts in 5 minutes.",
        providers: &[SECURITY],
        event_ids: &[4771],
        any_of: &[r#"Status=0x18 -TargetUserName~"\$$""#],
        threshold: Some(Threshold { group_by: &["IpAddress"], distinct: Some("TargetUserName"), min: 11, window_secs: 86_400 }),
        false_positives: "Vulnerability scanners, VPN concentrators, NAT gateways and shared hosts such as Citrix.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/unsupported/windows/win_security_susp_failed_logons_single_source_kerberos.yml",
            "https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_multiple_users_failed_to_authenticate_using_kerberos.yml",
        ],
    },
    Rule {
        id: "account_name_guessing",
        name: "User enumeration: many nonexistent accounts tried from one source",
        author: "Mauricio Velazco, frack113",
        tactic: Tactic::CredentialAccess,
        mitre: "T1110.003, T1087.002",
        severity: Severity::Medium,
        description: "More than 10 different account names that do not exist were tried from the \
            same source within 24 hours: Kerberos 'principal unknown' (4768 status 0x6) grouped \
            by IP address, or NTLM 'no such user' (4776 status 0xc0000064) grouped by \
            workstation. Threshold from Sigma.",
        providers: &[SECURITY],
        event_ids: &[4768, 4776],
        any_of: &[
            r#"Status=0x6 -TargetUserName~"\$$""#,
            r#"Status~"0xc0000064$" -TargetUserName~"\$$""#,
        ],
        threshold: Some(Threshold { group_by: &["IpAddress", "Workstation"], distinct: Some("TargetUserName"), min: 11, window_secs: 86_400 }),
        false_positives: "Misconfigured applications or scripts using wrong account names; scanners.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/unsupported/windows/win_security_susp_failed_logons_single_source_kerberos3.yml",
            "https://github.com/SigmaHQ/sigma/blob/master/unsupported/windows/win_security_susp_failed_logons_single_source_ntlm2.yml",
        ],
    },
    Rule {
        id: "logon_failure_spray",
        name: "Password spraying: network logon failures for many users from one source",
        author: "Mauricio Velazco",
        tactic: Tactic::CredentialAccess,
        mitre: "T1110.003",
        severity: Severity::Medium,
        description: "More than 10 different user accounts failed a network logon (type 3) from \
            the same IP address within 24 hours. Threshold from Sigma; Splunk uses more than \
            30 accounts in 5 minutes.",
        providers: &[SECURITY],
        event_ids: &[4625],
        any_of: &[r#"LogonType=3 -IpAddress=- -TargetUserName~"\$$""#],
        threshold: Some(Threshold { group_by: &["IpAddress"], distinct: Some("TargetUserName"), min: 11, window_secs: 86_400 }),
        false_positives: "Terminal servers, jump hosts, NAT gateways, vulnerability scanners.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/unsupported/windows/win_security_susp_failed_remote_logons_single_source.yml",
            "https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_multiple_users_remotely_failed_to_authenticate_from_host.yml",
        ],
    },
    Rule {
        id: "ntlm_password_spray",
        name: "Password spraying: NTLM wrong-password failures for many users from one workstation",
        author: "Mauricio Velazco",
        tactic: Tactic::CredentialAccess,
        mitre: "T1110.003",
        severity: Severity::Medium,
        description: "More than 10 different user accounts failed NTLM credential validation \
            with a wrong password (0xc000006a) from the same workstation within 24 hours. \
            Threshold from Sigma; Splunk uses more than 30 accounts in 5 minutes.",
        providers: &[SECURITY],
        event_ids: &[4776],
        any_of: &[r#"Status~"0xc000006a$" -TargetUserName~"\$$""#],
        threshold: Some(Threshold { group_by: &["Workstation"], distinct: Some("TargetUserName"), min: 11, window_secs: 86_400 }),
        false_positives: "Shared workstations and terminal servers; misconfigured services.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/unsupported/windows/win_security_susp_failed_logons_single_source_ntlm.yml",
            "https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_multiple_users_failed_to_authenticate_from_host_using_ntlm.yml",
        ],
    },
    Rule {
        id: "password_guessing_single_account",
        name: "Password guessing: repeated wrong passwords for one account",
        author: "Zach Mathis",
        tactic: Tactic::CredentialAccess,
        mitre: "T1110.001",
        severity: Severity::Medium,
        description: "At least 5 logon failures with a wrong password (0xc000006a) for the same \
            account from the same IP address within 5 minutes. Threshold from Hayabusa.",
        providers: &[SECURITY],
        event_ids: &[4625],
        any_of: &[r#"SubStatus=0xc000006a -IpAddress=- -TargetUserName~"\$$""#],
        threshold: Some(Threshold { group_by: &["TargetUserName", "IpAddress"], distinct: None, min: 5, window_secs: 300 }),
        false_positives: "A user repeatedly mistyping a password; a service with an outdated stored password.",
        references: &[
            "https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml",
        ],
    },
    Rule {
        id: "failed_logon_suspicious_reason",
        name: "Logon attempts against disabled, expired or restricted accounts",
        author: "Florian Roth (Nextron Systems)",
        tactic: Tactic::CredentialAccess,
        mitre: "T1078",
        severity: Severity::Medium,
        description: "A logon failed because the account is disabled (0xc0000072), outside its \
            allowed hours (0xc000006f), restricted to other workstations (0xc0000070), blocked \
            by the authentication firewall (0xc0000413), hit a broken trust (0xc000018c) or was \
            not granted the logon type (0xc000015b). Attackers often try dormant or disabled \
            accounts.",
        providers: &[SECURITY],
        event_ids: &[4625, 4776],
        any_of: &[
            r#"Status~"^0xc0000(072|06f|070|413|18c|15b)$" -SubjectUserSid=S-1-0-0"#,
            r#"SubStatus~"^0xc0000(072|06f|070|413|18c|15b)$" -SubjectUserSid=S-1-0-0"#,
        ],
        threshold: None,
        false_positives: "Users or services with expired or disabled accounts still trying to log on.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_failed_logon_reasons.yml",
        ],
    },
    Rule {
        id: "dcsync_non_machine_account",
        name: "DCSync: directory replication requested by a user account",
        author: "Roberto Rodriguez @Cyb3rWard0g",
        tactic: Tactic::CredentialAccess,
        mitre: "T1003.006",
        severity: Severity::Medium,
        description: "A directory replication right (DS-Replication-Get-Changes and related) \
            was exercised by an account that is not a computer account. Only domain controllers \
            normally replicate; a user account doing so can indicate DCSync, which copies \
            password hashes from Active Directory. Requires Directory Service Access auditing \
            on the domain controller.",
        providers: &[SECURITY],
        event_ids: &[4662],
        any_of: &[concat!(
            r#"Properties~""#,
            replication_guids!(),
            r#"" -SubjectUserName~"\$$" -SubjectUserName~"^(MSOL_|NT AUT)" -SubjectDomainName="Window Manager""#
        )],
        threshold: None,
        false_positives: "Azure AD Connect (MSOL_ accounts) and other directory synchronisation tools.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml",
            "https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_dcsync_replication_rights.toml",
        ],
    },
    Rule {
        id: "dcsync_rights_granted",
        name: "DCSync rights granted on a directory object",
        author: "Samir Bousseaden, Roberto Rodriguez @Cyb3rWard0g, oscd.community, Tim Shelton, Maxence Fossat",
        tactic: Tactic::CredentialAccess,
        mitre: "T1003.006, T1098",
        severity: Severity::High,
        description: "A directory object's security descriptor was changed to include \
            replication rights. Granting these rights to an account lets it perform DCSync \
            later, a common persistence step after domain compromise.",
        providers: &[SECURITY],
        event_ids: &[5136],
        any_of: &[concat!(
            r#"AttributeLDAPDisplayName=ntSecurityDescriptor AttributeValue~""#,
            replication_guids!(),
            r#"" -ObjectClass~"^(dnsNode|dnsZoneScope|dnsZone)$""#
        )],
        threshold: None,
        false_positives: "Adding a new domain controller.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml",
        ],
    },
    Rule {
        id: "dpapi_backup_key_access",
        name: "DPAPI domain backup key read",
        author: "Roberto Rodriguez @Cyb3rWard0g",
        tactic: Tactic::CredentialAccess,
        mitre: "T1552.004",
        severity: Severity::High,
        description: "The domain's DPAPI backup key secret (BCKUPKEY) was read. With this key an \
            attacker can decrypt DPAPI-protected secrets, such as saved browser passwords, for \
            every user in the domain.",
        providers: &[SECURITY],
        event_ids: &[4662],
        any_of: &["ObjectType=SecretObject AccessMask=0x2 ObjectName:BCKUPKEY"],
        threshold: None,
        false_positives: "None commonly known.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_dpapi_domain_backupkey_extraction.yml",
        ],
    },
    Rule {
        id: "lsass_memory_access",
        name: "LSASS memory read with dump-style access",
        author: "Samir Bousseaden, Michael Haag",
        tactic: Tactic::CredentialAccess,
        mitre: "T1003.001",
        severity: Severity::Medium,
        description: "A process opened LSASS with access rights typical of memory dumping, \
            through debugging or system DLLs. LSASS holds credentials of logged-on users. \
            Requires Sysmon process-access logging (event 10).",
        providers: &[SYSMON],
        event_ids: &[10],
        any_of: &[r#"TargetImage~"\\lsass\.exe$" GrantedAccess~"0x1038|0x1438|0x143a|0x1fffff" CallTrace~"dbgcore\.dll|dbghelp\.dll|kernel32\.dll|kernelbase\.dll|ntdll\.dll" -SourceUser~"AUTHORI|AUTORI" -SourceImage~"\\sysmon64\.exe$""#],
        threshold: None,
        false_positives: "Antivirus and EDR products, backup and monitoring agents.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml",
        ],
    },
    // ------------------------------------------------------------------ Defense Evasion
    Rule {
        id: "security_log_cleared",
        name: "Security event log cleared",
        author: "Florian Roth (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1070.001",
        severity: Severity::High,
        description: "The Security event log was cleared. Attackers clear logs to remove \
            evidence. The event records which account cleared it (UserData.LogFileCleared).",
        providers: &[EVENTLOG],
        event_ids: &[1102],
        any_of: &[],
        threshold: None,
        false_positives: "Rolling out a log collection agent; preparing a golden image.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_audit_log_cleared.yml",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102",
        ],
    },
    Rule {
        id: "important_log_cleared",
        name: "Security-relevant event log cleared (System, PowerShell, Sysmon)",
        author: "Florian Roth (Nextron Systems), Tim Shelton, Nasreddine Bencherchali (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1070.001",
        severity: Severity::High,
        description: "A security-relevant log (Security, System, Windows PowerShell, PowerShell \
            Operational or Sysmon) was cleared. Event 104 is written to the System log and names \
            the cleared log in UserData.LogFileCleared.Channel.",
        providers: &[EVENTLOG],
        event_ids: &[104],
        any_of: &[IMPORTANT_LOG],
        threshold: None,
        false_positives: "Administrators clearing logs during maintenance.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_susp_eventlog_cleared.yml",
        ],
    },
    Rule {
        id: "other_log_cleared",
        name: "Event log cleared",
        author: "Florian Roth (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1070.001",
        severity: Severity::Medium,
        description: "An event log other than the security-relevant ones was cleared.",
        providers: &[EVENTLOG],
        event_ids: &[104],
        any_of: &[concat!("-", r#"LogFileCleared.Channel~"^(Security|System|Windows PowerShell|Microsoft-Windows-PowerShell/Operational|PowerShellCore/Operational|Microsoft-Windows-Sysmon/Operational)$""#)],
        threshold: None,
        false_positives: "Administrators clearing logs during maintenance.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml",
        ],
    },
    Rule {
        id: "log_cleared_via_command_line",
        name: "Event logs cleared or resized from the command line",
        author: "Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105, Swachchhanda Shrawan Poudel (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1070.001",
        severity: Severity::High,
        description: "wevtutil, PowerShell or WMI was used to clear, remove or shrink event logs. \
            Needs process creation logging (Security 4688 with command lines, or Sysmon 1). \
            Deviation from Sigma: the msiexec exclusion applies to the whole wevtutil branch.",
        providers: &[SECURITY, SYSMON],
        event_ids: &[4688, 1],
        any_of: &[
            r#"process~"\\wevtutil\.exe$" CommandLine~"clear-log | cl |set-log | sl |lfn:" -parentprocess~"\\msiexec\.exe$""#,
            r#"process~"\\(powershell|powershell_ise|pwsh)\.exe$" CommandLine~"Clear-EventLog |Remove-EventLog |Limit-EventLog |Clear-WinEvent ""#,
            r#"process~"\\(powershell|powershell_ise|pwsh)\.exe$" CommandLine:Eventing.Reader.EventLogSession CommandLine:ClearLog"#,
            r#"process~"\\(powershell|powershell_ise|pwsh|wmic)\.exe$" CommandLine:ClearEventLog"#,
        ],
        threshold: None,
        false_positives: "Administrative or maintenance scripts.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml",
        ],
    },
    Rule {
        id: "critical_auditing_disabled",
        name: "Critical audit policy disabled",
        author: "Nasreddine Bencherchali (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.002",
        severity: Severity::High,
        description: "Success or failure auditing was removed (%%8448 / %%8450) for a critical \
            subcategory, such as Logon, Process Creation, Account Management, Credential \
            Validation, Kerberos or Audit Policy Change. Attackers disable auditing so their \
            next actions leave no trace.",
        providers: &[SECURITY],
        event_ids: &[4719],
        any_of: &[
            concat!(r#"AuditPolicyChanges~"%%8448|%%8450" SubcategoryGuid~""#, critical_audit_guids!(), r#"""#),
            r#"SubcategoryGuid:0CCE9217-69AE-11D9-BED3-505054503030 AuditPolicyChanges:%%8448"#,
        ],
        threshold: None,
        false_positives: "Unlikely.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_disable_event_auditing_critical.yml",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719",
        ],
    },
    Rule {
        id: "auditing_disabled",
        name: "Audit policy disabled",
        author: "@neu5ron, Nasreddine Bencherchali (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.002",
        severity: Severity::Low,
        description: "Success or failure auditing was removed for an audit subcategory that is \
            not in the critical list.",
        providers: &[SECURITY],
        event_ids: &[4719],
        any_of: &[concat!(
            r#"AuditPolicyChanges~"%%8448|%%8450" -SubcategoryGuid~""#,
            critical_audit_guids!(),
            r#"" -SubcategoryGuid:0CCE9217-69AE-11D9-BED3-505054503030"#
        )],
        threshold: None,
        false_positives: "Group Policy changes.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_disable_event_auditing.yml",
        ],
    },
    Rule {
        id: "defender_protection_disabled",
        name: "Microsoft Defender protection turned off",
        author: "Ján Trenčanský, frack113",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.001",
        severity: Severity::High,
        description: "Microsoft Defender real-time protection (5001), malware and PUA scanning \
            (5010) or virus scanning (5012) was disabled.",
        providers: &[DEFENDER],
        event_ids: &[5001, 5010, 5012],
        any_of: &[],
        threshold: None,
        false_positives: "Administrators troubleshooting; some Defender platform updates briefly report this.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml",
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml",
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_virus_scan_disabled.yml",
        ],
    },
    Rule {
        id: "defender_exclusion_added",
        name: "Microsoft Defender exclusion added",
        author: "Christian Burkard (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.001",
        severity: Severity::Medium,
        description: "A path, extension, process or IP address was added to Microsoft Defender's \
            exclusions. Attackers exclude their tools' folders so Defender ignores them.",
        providers: &[DEFENDER],
        event_ids: &[5007],
        any_of: &[r#"NewValue:"\Microsoft\Windows Defender\Exclusions""#],
        threshold: None,
        false_positives: "Administrators adding exclusions for legitimate software.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_config_change_exclusion_added.yml",
        ],
    },
    Rule {
        id: "defender_config_tampered",
        name: "Microsoft Defender protection settings weakened",
        author: "Nasreddine Bencherchali (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.001",
        severity: Severity::High,
        description: "A Microsoft Defender setting that weakens protection was changed: \
            DisableAntiSpyware, removable drive or mapped drive scanning, Block at First Sight, \
            or cloud (SpyNet) reporting.",
        providers: &[DEFENDER],
        event_ids: &[5007],
        any_of: &[r#"NewValue~"\\Windows Defender\\DisableAntiSpyware |\\Windows Defender\\Scan\\DisableRemovableDriveScanning |\\Windows Defender\\Scan\\DisableScanningMappedNetworkDrivesForFullScan |\\Windows Defender\\SpyNet\\DisableBlockAtFirstSeen |\\Real-Time Protection\\SpyNetReporting ""#],
        threshold: None,
        false_positives: "Administrators changing Defender configuration.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_suspicious_features_tampering.yml",
        ],
    },
    Rule {
        id: "defender_threat_detected",
        name: "Microsoft Defender detected malware",
        author: "Ján Trenčanský",
        tactic: Tactic::Execution,
        mitre: "",
        severity: Severity::High,
        description: "Microsoft Defender detected malware or potentially unwanted software \
            (1006, 1015, 1116) or took action against it (1117). See Threat Name, Path, Process \
            Name and Action Name in the event.",
        providers: &[DEFENDER],
        event_ids: &[1006, 1015, 1116, 1117],
        any_of: &[],
        threshold: None,
        false_positives: "Unlikely; test files such as EICAR.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_threat.yml",
            "https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus",
        ],
    },
    Rule {
        id: "defender_history_deleted",
        name: "Microsoft Defender detection history deleted",
        author: "Cian Heasley",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1070",
        severity: Severity::Info,
        description: "Microsoft Defender's malware detection history was deleted.",
        providers: &[DEFENDER],
        event_ids: &[1013],
        any_of: &[],
        threshold: None,
        false_positives: "Routine history cleanup.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_history_delete.yml",
        ],
    },
    Rule {
        id: "powershell_defender_exclusion",
        name: "Defender exclusion added with PowerShell",
        author: "Tim Rauch, Elastic (idea)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.001",
        severity: Severity::Medium,
        description: "Add-MpPreference or Set-MpPreference was used with an -Exclusion* \
            parameter, in a PowerShell script block (4104) or a process command line.",
        providers: &[POWERSHELL, SECURITY, SYSMON],
        event_ids: &[4104, 4688, 1],
        any_of: &[
            r#"ScriptBlockText~"(Add|Set)-MpPreference " ScriptBlockText~" -Exclusion(Path|Extension|Process|IpAddress) ""#,
            r#"CommandLine~"(Add|Set)-MpPreference " CommandLine~" -Exclusion(Path|Extension|Process|IpAddress) ""#,
        ],
        threshold: None,
        false_positives: "Administrators adding exclusions for legitimate software.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_win_defender_exclusions_added.yml",
        ],
    },
    Rule {
        id: "powershell_defender_disabled",
        name: "Defender protection disabled with PowerShell",
        author: "frack113, elhoim, Tim Shelton (fps, alias support), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.001",
        severity: Severity::High,
        description: "Set-MpPreference was used to turn off a Microsoft Defender protection \
            feature (real-time, behaviour, script or archive scanning, IOAV, Block at First \
            Sight, network protection).",
        providers: &[POWERSHELL],
        event_ids: &[4104],
        any_of: &[r#"ScriptBlockText:Set-MpPreference ScriptBlockText~"-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|BlockAtFirstSeen|IntrusionPreventionSystem|ArchiveScanning|ScanningNetworkFiles|RemovableDriveScanning|ScanningMappedNetworkDrivesForFullScan)\s+(\$true|1)""#],
        threshold: None,
        false_positives: "Troubleshooting scripts.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp.yml",
        ],
    },
    Rule {
        id: "amsi_bypass",
        name: "AMSI bypass attempt in PowerShell",
        author: "Florian Roth (Nextron Systems), Markus Neis, @Kostastsale",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.001",
        severity: Severity::High,
        description: "PowerShell code that disables the Antimalware Scan Interface (AMSI) through \
            .NET reflection, which stops Defender from inspecting later script content.",
        providers: &[POWERSHELL, SECURITY, SYSMON],
        event_ids: &[4104, 4688, 1],
        any_of: &[
            r#"ScriptBlockText:System.Management.Automation.AmsiUtils ScriptBlockText:amsiInitFailed"#,
            r#"ScriptBlockText:"[Ref].Assembly.GetType" ScriptBlockText:"SetValue($null,$true)" ScriptBlockText:"NonPublic,Static""#,
            r#"CommandLine:System.Management.Automation.AmsiUtils CommandLine:amsiInitFailed"#,
        ],
        threshold: None,
        false_positives: "Security testing.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml",
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_amsi_init_failed_bypass.yml",
        ],
    },
    Rule {
        id: "firewall_all_rules_deleted",
        name: "All Windows Firewall rules deleted",
        author: "frack113, Nasreddine Bencherchali (Nextron Systems)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.004",
        severity: Severity::High,
        description: "Every Windows Firewall rule was deleted by an application other than the \
            Windows service host or Defender.",
        providers: &[FIREWALL],
        event_ids: &[2033, 2059],
        any_of: &[r#"-ModifyingApplication~"\\svchost\.exe$|\\MsMpEng\.exe$""#],
        threshold: None,
        false_positives: "Firewall resets during troubleshooting.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml",
        ],
    },
    Rule {
        id: "firewall_rule_suspicious_folder",
        name: "Firewall rule added for a program in a suspicious folder",
        author: "frack113",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.004",
        severity: Severity::High,
        description: "A non-blocking Windows Firewall rule was added for a program in a temp, \
            public or other folder commonly used by malware.",
        providers: &[FIREWALL],
        event_ids: &[2004, 2071, 2097],
        any_of: &[r#"ApplicationPath~":\\PerfLogs\\|:\\Temp\\|:\\Tmp\\|:\\Users\\Public\\|:\\Windows\\Tasks\\|:\\Windows\\Temp\\|\\AppData\\Local\\Temp\\" -Action=2"#],
        threshold: None,
        false_positives: "Installers running from temp folders.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/firewall_as/win_firewall_as_add_rule_susp_folder.yml",
        ],
    },
    Rule {
        id: "firewall_disabled_command_line",
        name: "Windows Firewall turned off from the command line",
        author: "Fatih Sirin, Tim Rauch, Elastic (idea)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.004",
        severity: Severity::Medium,
        description: "netsh or PowerShell (Set-NetFirewallProfile -Enabled False) was used to \
            turn off the Windows Firewall.",
        providers: &[SECURITY, SYSMON, POWERSHELL],
        event_ids: &[4688, 1, 4104],
        any_of: &[
            r#"process~"\\netsh\.exe$" CommandLine:firewall CommandLine:set CommandLine:opmode CommandLine:disable"#,
            r#"process~"\\netsh\.exe$" CommandLine:advfirewall CommandLine:set CommandLine:state CommandLine:off"#,
            r#"CommandLine:"Set-NetFirewallProfile " CommandLine:" -Enabled " CommandLine:" False""#,
            r#"ScriptBlockText:"Set-NetFirewallProfile " ScriptBlockText:" -Enabled " ScriptBlockText:" False""#,
        ],
        threshold: None,
        false_positives: "Administrators.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_netsh_fw_disable.yml",
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_disable_firewall.yml",
        ],
    },
    Rule {
        id: "powershell_downgrade",
        name: "PowerShell version 2 engine started (downgrade)",
        author: "Florian Roth (Nextron Systems), Lee Holmes (idea), Harish Segar (improvements)",
        tactic: Tactic::DefenseEvasion,
        mitre: "T1562.010",
        severity: Severity::Medium,
        description: "A PowerShell 2.0 engine was started from a newer host. PowerShell 2 has no \
            script block logging or AMSI, so attackers downgrade to avoid both.",
        providers: &[POWERSHELL_CLASSIC],
        event_ids: &[400],
        any_of: &[r#""EngineVersion=2." -"HostVersion=2.""#],
        threshold: None,
        false_positives: "Legacy scripts that explicitly require PowerShell 2.",
        references: &[
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_classic/posh_pc_downgrade_attack.yml",
        ],
    },
    // ------------------------------------------------------------------ Lateral Movement
    Rule {
        id: "pass_the_hash",
        name: "Possible pass-the-hash logon",
        author: "Dave Kennedy, Jeff Warren (method) / David Vassallo (rule)",
        tactic: Tactic::LateralMovement,
        mitre: "T1550.002",
        severity: Severity::Medium,
        description: "A network logon through NTLM with no session key (KeyLength 0) and a null \
            subject, or a new-credentials logon (type 9) through seclogo. Both patterns appear \
            when stolen password hashes are used instead of passwords. Noisy on its own: many \
            legitimate NTLM logons look similar, so check the account and source.",
        providers: &[SECURITY],
        event_ids: &[4624],
        any_of: &[
            r#"SubjectUserSid=S-1-0-0 LogonType=3 LogonProcessName~"^NtLmSsp\s*$" KeyLength=0 -TargetUserName="ANONYMOUS LOGON""#,
            r#"LogonType=9 LogonProcessName~"^seclogo\s*$" -TargetUserName="ANONYMOUS LOGON""#,
        ],
        threshold: None,
        false_positives: "Administrator activity; legitimate NTLM network logons.",
        references: &[sigma!("builtin/security/account_management/win_security_pass_the_hash_2.yml")],
    },
    Rule {
        id: "overpass_the_hash",
        name: "Logon with new credentials (overpass-the-hash or runas /netonly)",
        author: "Roberto Rodriguez (source), Dominik Schaudel (rule)",
        tactic: Tactic::LateralMovement,
        mitre: "T1550.002",
        severity: Severity::High,
        description: "A type 9 (new credentials) logon through seclogo with Negotiate \
            authentication. Tools that inject stolen Kerberos keys or hashes into a new session \
            produce this pattern; so does runas /netonly.",
        providers: &[SECURITY],
        event_ids: &[4624],
        any_of: &[r#"LogonType=9 LogonProcessName~"^seclogo\s*$" AuthenticationPackageName=Negotiate"#],
        threshold: None,
        false_positives: "Administrators using runas /netonly.",
        references: &[sigma!("builtin/security/account_management/win_security_overpass_the_hash.yml")],
    },
    Rule {
        id: "psexec_service_installed",
        name: "PsExec service installed",
        author: "Thomas Patzke",
        tactic: Tactic::LateralMovement,
        mitre: "T1569.002, T1021.002",
        severity: Severity::Medium,
        description: "The PsExec service (PSEXESVC) was installed, which happens when PsExec runs \
            commands on this machine from another computer.",
        providers: &[SCM],
        event_ids: &[7045],
        any_of: &["ServiceName=PSEXESVC", r#"ImagePath~"\\PSEXESVC\.exe$""#],
        threshold: None,
        false_positives: "Administrators using PsExec.",
        references: &[sigma!("builtin/system/service_control_manager/win_system_service_install_sysinternals_psexec.yml")],
    },
    Rule {
        id: "remote_execution_tool_service",
        name: "Remote execution tool service installed (PAExec, RemCom, CSExec)",
        author: "Nasreddine Bencherchali (Nextron Systems)",
        tactic: Tactic::LateralMovement,
        mitre: "T1569.002, T1021.002",
        severity: Severity::Medium,
        description: "A service used by a PsExec-like remote execution tool was installed.",
        providers: &[SCM],
        event_ids: &[7045],
        any_of: &[
            r#"ServiceName~"^PAExec-""#,
            r#"ImagePath~"^C:\\WINDOWS\\PAExec-""#,
            "ServiceName=RemComSvc",
            r#"ImagePath~"\\RemComSvc\.exe$""#,
            "ServiceName=csexecsvc",
            r#"ImagePath~"\\csexecsvc\.exe$""#,
        ],
        threshold: None,
        false_positives: "Administrators using these tools.",
        references: &[
            sigma!("builtin/system/service_control_manager/win_system_service_install_paexec.yml"),
            sigma!("builtin/system/service_control_manager/win_system_service_install_remcom.yml"),
            sigma!("builtin/system/service_control_manager/win_system_service_install_csexecsvc.yml"),
        ],
    },
    Rule {
        id: "renamed_psexec_pipes",
        name: "PsExec-style named pipes under a renamed service",
        author: "Samir Bousseaden",
        tactic: Tactic::LateralMovement,
        mitre: "T1021.002, T1570",
        severity: Severity::High,
        description: "Named pipes ending in -stdin, -stdout or -stderr were opened over IPC$ by a \
            service not named PSEXESVC, which suggests PsExec run with a renamed service to \
            avoid detection. Needs 'Audit Detailed File Share' (5145).",
        providers: &[SECURITY],
        event_ids: &[5145],
        any_of: &[r#"ShareName~"\\IPC\$$" RelativeTargetName~"-(stdin|stdout|stderr)$" -RelativeTargetName~"^PSEXESVC""#],
        threshold: None,
        false_positives: "Other legitimate tools using similarly named pipes.",
        references: &[sigma!("builtin/security/win_security_susp_psexec.yml")],
    },
    Rule {
        id: "impacket_psexec_pipes",
        name: "Impacket psexec named pipes",
        author: "Bhabesh Raj",
        tactic: Tactic::LateralMovement,
        mitre: "T1021.002, T1570",
        severity: Severity::High,
        description: "The RemCom_stdin/stdout/stderr named pipes used by Impacket's psexec were \
            opened over IPC$. Needs 'Audit Detailed File Share' (5145).",
        providers: &[SECURITY],
        event_ids: &[5145],
        any_of: &[r#"ShareName~"\\IPC\$$" RelativeTargetName~"RemCom_std(in|out|err)""#],
        threshold: None,
        false_positives: "Unknown.",
        references: &[sigma!("builtin/security/win_security_impacket_psexec.yml")],
    },
    Rule {
        id: "random_name_service",
        name: "Service with a random name installed from %systemroot% (Impacket / Metasploit psexec)",
        author: "Bartlomiej Czyz, Relativity",
        tactic: Tactic::LateralMovement,
        mitre: "T1021.002, T1569.002",
        severity: Severity::High,
        description: "A demand-start service with a random 4, 8 or 16-letter name was installed, \
            running a random 8-letter .exe from %systemroot%. This is how Impacket and \
            Metasploit psexec run commands remotely. The 7045 variant is an adaptation of \
            Sigma's 4697 rule to the System log.",
        providers: &[SECURITY, SCM],
        event_ids: &[4697, 7045],
        any_of: &[
            r#"ServiceFileName~"^%systemroot%\\[a-zA-Z]{8}\.exe$" ServiceName~"^([a-zA-Z]{4}|[a-zA-Z]{8}|[a-zA-Z]{16})$" ServiceStartType=3 ServiceType=0x10 -ServiceName=PSEXESVC"#,
            r#"ImagePath~"^%systemroot%\\[a-zA-Z]{8}\.exe$" ServiceName~"^([a-zA-Z]{4}|[a-zA-Z]{8}|[a-zA-Z]{16})$" -ServiceName=PSEXESVC"#,
        ],
        threshold: None,
        false_positives: "Unknown.",
        references: &[sigma!("builtin/security/win_security_metasploit_or_impacket_smb_psexec_service_install.yml")],
    },
    Rule {
        id: "smbexec_service",
        name: "Impacket smbexec service installed",
        author: "Omer Faruk Celik",
        tactic: Tactic::LateralMovement,
        mitre: "T1021.002, T1569.002",
        severity: Severity::High,
        description: "A service was installed whose command echoes a command into a batch file, \
            runs it and deletes it — the way Impacket's smbexec executes each command. The \
            third pattern matches current Impacket versions, whose output file name changed.",
        providers: &[SCM],
        event_ids: &[7045],
        any_of: &[
            "ServiceName=BTOBTO",
            r#"ImagePath:".bat & del ""#,
            r#"ImagePath:"__output 2^>^&1 >""#,
            r#"ImagePath:"%COMSPEC% /Q /c echo" ImagePath:\__output"#,
        ],
        threshold: None,
        false_positives: "Unknown.",
        references: &[
            sigma!("builtin/system/service_control_manager/win_system_hack_smbexec.yml"),
            "https://github.com/fortra/impacket/blob/master/examples/smbexec.py",
        ],
    },
    Rule {
        id: "impacket_remote_command",
        name: "Remote command execution through WMI, DCOM, services or tasks (Impacket style)",
        author: "Ecco, oscd.community, Jonhnathan Ribeiro, Tim Rauch",
        tactic: Tactic::LateralMovement,
        mitre: "T1047, T1021.003, T1053.005",
        severity: Severity::High,
        description: "cmd.exe was started by WmiPrvSE, mmc, explorer or services with output \
            redirected to \\\\127.0.0.1\\ (wmiexec, dcomexec, smbexec), or by the task scheduler \
            with output redirected to Windows\\Temp (atexec). Needs process creation logging.",
        providers: &[SECURITY, SYSMON],
        event_ids: &[4688, 1],
        any_of: &[
            r#"parentprocess~"\\(wmiprvse|mmc|explorer|services)\.exe$" CommandLine:cmd.exe CommandLine:/Q CommandLine:/c CommandLine:"\\127.0.0.1\" CommandLine:&1"#,
            r#"ParentCommandLine~"svchost\.exe -k netsvcs|taskeng\.exe" CommandLine:cmd.exe CommandLine:/C CommandLine:"Windows\Temp\" CommandLine:&1"#,
        ],
        threshold: None,
        false_positives: "Unknown.",
        references: &[sigma!("process_creation/proc_creation_win_hktl_impacket_lateral_movement.yml")],
    },
    Rule {
        id: "rdp_from_localhost",
        name: "RDP logon from localhost (tunnelled RDP)",
        author: "Thomas Patzke",
        tactic: Tactic::LateralMovement,
        mitre: "T1021.001, T1090",
        severity: Severity::High,
        description: "A Remote Desktop logon (type 10) came from the machine itself (::1 or \
            127.0.0.1). This usually means RDP is being tunnelled, for example through SSH or \
            a proxy tool, to reach a machine that isn't directly reachable.",
        providers: &[SECURITY],
        event_ids: &[4624],
        any_of: &[r#"LogonType=10 IpAddress~"^(::1|127\.0\.0\.1)$""#],
        threshold: None,
        false_positives: "Unknown.",
        references: &[sigma!("builtin/security/account_management/win_security_rdp_localhost_login.yml")],
    },
    Rule {
        id: "rdp_from_public_ip",
        name: "RDP logon from a public IP address",
        author: "Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity)",
        tactic: Tactic::LateralMovement,
        mitre: "T1133, T1078",
        severity: Severity::Medium,
        description: "A Remote Desktop logon (type 10) came from an address outside private, \
            loopback and link-local ranges, meaning RDP is reachable from the internet.",
        providers: &[SECURITY],
        event_ids: &[4624],
        any_of: &[concat!("LogonType=10 IpAddress: ", not_private_ip!())],
        threshold: None,
        false_positives: "Legitimate remote access by administrators over the internet.",
        references: &[sigma!("builtin/security/account_management/win_security_successful_external_remote_rdp_login.yml")],
    },
    Rule {
        id: "smb_from_public_ip",
        name: "Network (SMB) logon from a public IP address",
        author: "Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity)",
        tactic: Tactic::LateralMovement,
        mitre: "T1133, T1078",
        severity: Severity::High,
        description: "A network logon (type 3) came from an address outside private, loopback \
            and link-local ranges, meaning file sharing or similar services are reachable from \
            the internet.",
        providers: &[SECURITY],
        event_ids: &[4624],
        any_of: &[concat!("LogonType=3 IpAddress: ", not_private_ip!())],
        threshold: None,
        false_positives: "Legitimate access from the internet.",
        references: &[sigma!("builtin/security/account_management/win_security_successful_external_remote_smb_login.yml")],
    },
    Rule {
        id: "rdp_through_ngrok",
        name: "RDP session through ngrok",
        author: "Florian Roth (Nextron Systems)",
        tactic: Tactic::LateralMovement,
        mitre: "T1090",
        severity: Severity::High,
        description: "A Remote Desktop session logon recorded an address typical of connections \
            tunnelled through ngrok.",
        providers: &[LSM],
        event_ids: &[21],
        any_of: &["Address:16777216"],
        threshold: None,
        false_positives: "Unknown.",
        references: &[sigma!("builtin/terminalservices/win_terminalservices_rdp_ngrok.yml")],
    },
    Rule {
        id: "remote_task_via_atsvc",
        name: "Scheduled task created remotely through the ATSVC pipe",
        author: "Samir Bousseaden",
        tactic: Tactic::LateralMovement,
        mitre: "T1053.002",
        severity: Severity::Medium,
        description: "The atsvc named pipe was written to over IPC$, which is how scheduled tasks \
            are created on this machine from another computer. Raw logs record WriteData as \
            %%4417, so both forms are matched.",
        providers: &[SECURITY],
        event_ids: &[5145],
        any_of: &[r#"ShareName~"\\IPC\$$" RelativeTargetName=atsvc AccessList~"WriteData|%%4417""#],
        threshold: None,
        false_positives: "Administrators creating scheduled tasks remotely.",
        references: &[sigma!("builtin/security/win_security_atsvc_task.yml")],
    },
    Rule {
        id: "remote_service_via_svcctl",
        name: "Service controlled remotely through the SVCCTL pipe",
        author: "Samir Bousseaden",
        tactic: Tactic::LateralMovement,
        mitre: "T1021.002",
        severity: Severity::Medium,
        description: "The svcctl named pipe was written to over IPC$, which is how services are \
            created or changed on this machine from another computer. Raw logs record WriteData \
            as %%4417, so both forms are matched.",
        providers: &[SECURITY],
        event_ids: &[5145],
        any_of: &[r#"ShareName~"\\IPC\$$" RelativeTargetName=svcctl AccessList~"WriteData|%%4417""#],
        threshold: None,
        false_positives: "Administrators managing services remotely.",
        references: &[sigma!("builtin/security/win_security_svcctl_remote_service.yml")],
    },
    Rule {
        id: "admin_share_access",
        name: "ADMIN$ share accessed by a user account",
        author: "Florian Roth (Nextron Systems)",
        tactic: Tactic::LateralMovement,
        mitre: "T1021.002",
        severity: Severity::Low,
        description: "The hidden ADMIN$ share was accessed by an account that is not a computer \
            account. Raw logs record the share as \\\\*\\ADMIN$, so this rule matches the end of \
            the name rather than Sigma's exact 'Admin$'.",
        providers: &[SECURITY],
        event_ids: &[5140],
        any_of: &[r#"ShareName~"\\ADMIN\$$" -SubjectUserName~"\$$""#],
        threshold: None,
        false_positives: "Legitimate administration.",
        references: &[sigma!("builtin/security/win_security_admin_share_access.yml")],
    },
    Rule {
        id: "admin_share_file_written",
        name: "File written to the C$ admin share by a user account",
        author: "Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research)",
        tactic: Tactic::LateralMovement,
        mitre: "T1021.002, T1570",
        severity: Severity::High,
        description: "A file on the hidden C$ share was opened for writing (access mask 0x2) by \
            an account that is not a computer account, from another machine. Attackers copy \
            tools to remote machines this way.",
        providers: &[SECURITY],
        event_ids: &[5145],
        any_of: &[r#"ShareName~"C\$$" AccessMask=0x2 -SubjectUserName~"\$$" -IpAddress=::1"#],
        threshold: None,
        false_positives: "Unknown.",
        references: &[sigma!("builtin/security/win_security_smb_file_creation_admin_shares.yml")],
    },
    Rule {
        id: "explicit_credentials_from_shell",
        name: "Explicit credentials used from a shell or admin tool",
        author: "oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Tim Shelton",
        tactic: Tactic::LateralMovement,
        mitre: "T1078, T1021",
        severity: Severity::Medium,
        description: "cmd, PowerShell, winrs, wmic, net or reg logged on with explicitly supplied \
            credentials to another machine. Excludes logons to localhost and logons between \
            computer accounts.",
        providers: &[SECURITY],
        event_ids: &[4648],
        any_of: &[
            r#"ProcessName~"\\(cmd|powershell|pwsh|winrs|wmic|net|net1|reg)\.exe$" -TargetServerName=localhost -SubjectUserName~"\$$""#,
            r#"ProcessName~"\\(cmd|powershell|pwsh|winrs|wmic|net|net1|reg)\.exe$" -TargetServerName=localhost -TargetUserName~"\$$""#,
        ],
        threshold: None,
        false_positives: "Administrators using runas or scheduled tasks.",
        references: &[sigma!("builtin/security/win_security_susp_logon_explicit_credentials.yml")],
    },
    Rule {
        id: "wmi_logon",
        name: "Logon through WMI",
        author: "Thomas Patzke",
        tactic: Tactic::LateralMovement,
        mitre: "T1047",
        severity: Severity::Low,
        description: "A logon was performed by the WMI provider host (WmiPrvSE.exe), for example \
            when commands are run on this machine through WMI from another computer.",
        providers: &[SECURITY],
        event_ids: &[4624],
        any_of: &[r#"ProcessName~"\\WmiPrvSE\.exe$""#],
        threshold: None,
        false_positives: "Monitoring tools that use WMI.",
        references: &[sigma!("builtin/security/account_management/win_security_susp_wmi_login.yml")],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::run;
    use crate::model::{build, KeyInterner, Record};
    use serde_json::{json, Value};

    /// Build a Security-log style event.
    fn event(provider: &str, id: u32, time: &str, data: Value) -> Value {
        json!({"Event": {
            "System": {"Provider": {"#attributes": {"Name": provider}}, "EventID": id, "Level": 0,
                       "TimeCreated": {"#attributes": {"SystemTime": time}}},
            "EventData": data,
        }})
    }

    /// IDs of the rules that fire on each event, evaluated as one log.
    fn fired(events: Vec<Value>) -> Vec<Vec<&'static str>> {
        let mut keys = KeyInterner::default();
        let recs: Vec<Record> = events
            .into_iter()
            .enumerate()
            .map(|(i, e)| build(i as u64, e, &mut keys))
            .collect();
        let keys_lc: Vec<Box<str>> = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        let (hits, errors) = run(&crate::detect::builtin_rules(), &recs, &keys_lc);
        assert!(errors.is_empty(), "{errors:?}");
        let mut out = vec![Vec::new(); recs.len()];
        for h in hits {
            for i in h.records {
                out[i as usize].push(RULES[h.rule].id);
            }
        }
        out
    }

    fn one(e: Value) -> Vec<&'static str> {
        fired(vec![e]).remove(0)
    }

    const T: &str = "2024-05-21T03:18:09.459682Z";

    #[test]
    fn kerberoasting() {
        let tgs = |svc: &str, user: &str, enc: &str, status: &str| {
            event(
                SECURITY,
                4769,
                T,
                json!({"ServiceName": svc, "TargetUserName": user,
                "TicketEncryptionType": enc, "Status": status, "TicketOptions": "0x40810000"}),
            )
        };
        assert_eq!(
            one(tgs("MSSQLService", "alice@CONTOSO.LOCAL", "0x17", "0x0")),
            ["kerberoasting_rc4"]
        );
        assert!(
            one(tgs("MSSQLService", "alice@CONTOSO.LOCAL", "0x12", "0x0")).is_empty(),
            "AES"
        );
        assert!(
            one(tgs("DC01$", "alice@CONTOSO.LOCAL", "0x17", "0x0")).is_empty(),
            "machine service"
        );
        assert!(
            one(tgs("krbtgt", "alice@CONTOSO.LOCAL", "0x17", "0x0")).is_empty(),
            "krbtgt"
        );
        assert!(
            one(tgs("MSSQLService", "DC01$@CONTOSO.LOCAL", "0x17", "0x0")).is_empty(),
            "machine requester"
        );
        assert!(
            one(tgs("MSSQLService", "alice@CONTOSO.LOCAL", "0x17", "0x1b")).is_empty(),
            "failed request"
        );
    }

    #[test]
    fn asrep_roasting() {
        let tgt = |preauth: &str| {
            event(
                SECURITY,
                4768,
                T,
                json!({"ServiceName": "krbtgt", "TargetUserName": "svc_backup",
                "TicketEncryptionType": "0x17", "PreAuthType": preauth, "Status": "0x0"}),
            )
        };
        assert_eq!(one(tgt("0")), ["asrep_roasting"]);
        assert!(one(tgt("2")).is_empty());
    }

    #[test]
    fn kerberos_spray_needs_many_users_and_ignores_computers() {
        let fail = |n: u32, user: String| {
            event(
                SECURITY,
                4771,
                &format!("2024-05-21T03:{:02}:00Z", n),
                json!({
                "TargetUserName": user, "IpAddress": "::ffff:10.20.30.40", "Status": "0x18"}),
            )
        };
        // 11 different users from one IP within 24h: spray.
        let spray = fired((0..11).map(|n| fail(n, format!("user{n}"))).collect());
        assert!(spray.iter().all(|r| r == &["kerberos_password_spray"]));
        // 10 users: below threshold.
        assert!(
            fired((0..10).map(|n| fail(n, format!("user{n}"))).collect())
                .iter()
                .all(Vec::is_empty)
        );
        // A computer account with a stale password failing over and over.
        assert!(fired((0..50).map(|n| fail(n, "WKSTN01$".into())).collect())
            .iter()
            .all(Vec::is_empty));
    }

    #[test]
    fn password_guessing() {
        let fail = |sec: u32, user: &str| {
            event(
                SECURITY,
                4625,
                &format!("2024-05-21T03:00:{:02}Z", sec),
                json!({
                "TargetUserName": user, "IpAddress": "10.0.0.5", "LogonType": "3",
                "Status": "0xc000006d", "SubStatus": "0xc000006a"}),
            )
        };
        assert!(fired((0..5).map(|s| fail(s * 10, "admin")).collect())
            .iter()
            .all(|r| r.contains(&"password_guessing_single_account")));
        assert!(fired((0..4).map(|s| fail(s * 10, "admin")).collect())
            .iter()
            .all(Vec::is_empty));
    }

    #[test]
    fn failed_logon_reasons() {
        let fail = |status: &str, sub: &str| {
            event(
                SECURITY,
                4625,
                T,
                json!({"TargetUserName": "olduser", "Status": status, "SubStatus": sub,
                "SubjectUserSid": "S-1-5-18", "IpAddress": "10.0.0.5", "LogonType": "3"}),
            )
        };
        assert_eq!(
            one(fail("0xc000006e", "0xc0000072")),
            ["failed_logon_suspicious_reason"]
        );
        assert!(one(fail("0xc000006d", "0xc000006a")).is_empty());
    }

    #[test]
    fn dcsync() {
        let repl = |user: &str| {
            event(
                SECURITY,
                4662,
                T,
                json!({"SubjectUserName": user, "SubjectDomainName": "CONTOSO",
                "AccessMask": "0x100",
                "Properties": "%%7688\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}"}),
            )
        };
        assert_eq!(one(repl("alice")), ["dcsync_non_machine_account"]);
        assert!(one(repl("DC01$")).is_empty(), "domain controller");
        assert!(one(repl("MSOL_1234abcd")).is_empty(), "AAD Connect");
    }

    #[test]
    fn dcsync_rights_granted() {
        let change = |class: &str| {
            event(
                SECURITY,
                5136,
                T,
                json!({"AttributeLDAPDisplayName": "nTSecurityDescriptor", "ObjectClass": class,
                "AttributeValue": "O:BAG:BAD:(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-1-2-3-1105)"}),
            )
        };
        assert_eq!(one(change("domainDNS")), ["dcsync_rights_granted"]);
        assert!(one(change("dnsNode")).is_empty());
    }

    #[test]
    fn lsass_access() {
        let access = |source: &str, mask: &str, user: &str| {
            event(
                SYSMON,
                10,
                T,
                json!({"SourceImage": source, "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                "GrantedAccess": mask, "SourceUser": user,
                "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2c13e"}),
            )
        };
        assert_eq!(
            one(access("C:\\Users\\Public\\x.exe", "0x1fffff", "CORP\\bob")),
            ["lsass_memory_access"]
        );
        assert!(
            one(access("C:\\Users\\Public\\x.exe", "0x1000", "CORP\\bob")).is_empty(),
            "query-only access"
        );
        assert!(one(access(
            "C:\\Windows\\Sysmon64.exe",
            "0x1fffff",
            "NT AUTHORITY\\SYSTEM"
        ))
        .is_empty());
    }

    fn log_cleared(id: u32, cleared: Option<&str>) -> Value {
        let mut user_data =
            json!({"LogFileCleared": {"SubjectUserName": "admin", "SubjectDomainName": "CORP"}});
        if let Some(c) = cleared {
            user_data["LogFileCleared"]["Channel"] = json!(c);
        }
        json!({"Event": {
            "System": {"Provider": {"#attributes": {"Name": EVENTLOG}}, "EventID": id, "Level": 4,
                       "Channel": if id == 104 { "System" } else { "Security" },
                       "TimeCreated": {"#attributes": {"SystemTime": T}}},
            "UserData": user_data,
        }})
    }

    #[test]
    fn log_clearing() {
        assert_eq!(one(log_cleared(1102, None)), ["security_log_cleared"]);
        assert_eq!(
            one(log_cleared(
                104,
                Some("Microsoft-Windows-Sysmon/Operational")
            )),
            ["important_log_cleared"]
        );
        // The event's own channel is "System"; only the cleared log's name may decide.
        assert_eq!(
            one(log_cleared(104, Some("Application"))),
            ["other_log_cleared"]
        );
    }

    fn sysmon_proc(image: &str, cmd: &str, parent: &str) -> Value {
        event(
            SYSMON,
            1,
            T,
            json!({"Image": image, "CommandLine": cmd, "ParentImage": parent}),
        )
    }
    fn security_proc(image: &str, cmd: &str, parent: &str) -> Value {
        event(
            SECURITY,
            4688,
            T,
            json!({"NewProcessName": image, "CommandLine": cmd, "ParentProcessName": parent}),
        )
    }

    #[test]
    fn log_clearing_command_line_both_log_sources() {
        let explorer = "C:\\Windows\\explorer.exe";
        for mk in [sysmon_proc, security_proc] {
            assert_eq!(
                one(mk(
                    "C:\\Windows\\System32\\wevtutil.exe",
                    "wevtutil.exe cl Security",
                    explorer
                )),
                ["log_cleared_via_command_line"]
            );
            assert_eq!(
                one(mk(
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell Clear-EventLog -LogName System",
                    explorer
                )),
                ["log_cleared_via_command_line"]
            );
            assert!(
                one(mk(
                    "C:\\Windows\\System32\\wevtutil.exe",
                    "wevtutil.exe qe Security /c:5",
                    explorer
                ))
                .is_empty(),
                "query only"
            );
            assert!(
                one(mk(
                    "C:\\Windows\\System32\\wevtutil.exe",
                    "wevtutil.exe sl Foo /ms:1024",
                    "C:\\Windows\\System32\\msiexec.exe"
                ))
                .is_empty(),
                "installer"
            );
        }
    }

    #[test]
    fn audit_policy() {
        let change = |guid: &str, changes: &str| {
            event(
                SECURITY,
                4719,
                T,
                json!({"SubcategoryGuid": guid, "AuditPolicyChanges": changes}),
            )
        };
        // Process Creation (0CCE922B): critical.
        assert_eq!(
            one(change(
                "{0CCE922B-69AE-11D9-BED3-505054503030}",
                "%%8448, %%8450"
            )),
            ["critical_auditing_disabled"]
        );
        // File System (0CCE921D): not critical.
        assert_eq!(
            one(change("{0CCE921D-69AE-11D9-BED3-505054503030}", "%%8448")),
            ["auditing_disabled"]
        );
        // Auditing added, not removed.
        assert!(one(change("{0CCE922B-69AE-11D9-BED3-505054503030}", "%%8449")).is_empty());
    }

    #[test]
    fn defender() {
        let config = |new: &str| {
            event(
                DEFENDER,
                5007,
                T,
                json!({"Old Value": "", "New Value": new}),
            )
        };
        assert_eq!(
            one(config(
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp = 0x0"
            )),
            ["defender_exclusion_added"]
        );
        assert_eq!(
            one(config(
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiSpyware = 0x1"
            )),
            ["defender_config_tampered"]
        );
        assert!(one(config(
            "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\ScheduleDay = 0x8"
        ))
        .is_empty());
        assert_eq!(
            one(event(DEFENDER, 5001, T, json!({"Product Name": "%%827"}))),
            ["defender_protection_disabled"]
        );
        assert_eq!(
            one(event(
                DEFENDER,
                1116,
                T,
                json!({"Threat Name": "Trojan:Win32/Test"})
            )),
            ["defender_threat_detected"]
        );
        // Same event ID from another provider must not match.
        assert!(one(event(SECURITY, 5001, T, json!({}))).is_empty());
    }

    #[test]
    fn powershell_defender_and_amsi() {
        let block = |text: &str| {
            event(
                POWERSHELL,
                4104,
                T,
                json!({"ScriptBlockText": text, "MessageNumber": 1, "MessageTotal": 1}),
            )
        };
        assert_eq!(
            one(block("Add-MpPreference -ExclusionPath C:\\Temp")),
            ["powershell_defender_exclusion"]
        );
        assert_eq!(
            one(block("Set-MpPreference -DisableRealtimeMonitoring $true")),
            ["powershell_defender_disabled"]
        );
        assert!(one(block("Set-MpPreference -DisableRealtimeMonitoring $false")).is_empty());
        assert_eq!(
            one(block("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")),
            ["amsi_bypass"]
        );
        assert!(one(block("Get-MpPreference | Select ExclusionPath")).is_empty());
    }

    #[test]
    fn firewall() {
        let added = |path: &str, action: &str| {
            event(
                FIREWALL,
                2097,
                T,
                json!({"RuleName": "x", "ApplicationPath": path, "Action": action}),
            )
        };
        assert_eq!(
            one(added("C:\\Users\\Public\\svc.exe", "3")),
            ["firewall_rule_suspicious_folder"]
        );
        assert!(
            one(added("C:\\Users\\Public\\svc.exe", "2")).is_empty(),
            "block rule"
        );
        assert!(one(added("C:\\Program Files\\App\\app.exe", "3")).is_empty());
        let deleted = |app: &str| event(FIREWALL, 2033, T, json!({"ModifyingApplication": app}));
        assert_eq!(
            one(deleted("C:\\Users\\bob\\x.exe")),
            ["firewall_all_rules_deleted"]
        );
        assert!(one(deleted("C:\\Windows\\System32\\svchost.exe")).is_empty());
        assert_eq!(
            one(security_proc(
                "C:\\Windows\\System32\\netsh.exe",
                "netsh advfirewall set allprofiles state off",
                "cmd.exe"
            )),
            ["firewall_disabled_command_line"]
        );
    }

    #[test]
    fn powershell_downgrade() {
        let engine = |host: &str, engine: &str| {
            event(
                POWERSHELL_CLASSIC,
                400,
                T,
                json!({"Data": ["Available", "None",
                format!("\tNewEngineState=Available\n\tHostVersion={host}\n\tEngineVersion={engine}\n")]}),
            )
        };
        assert_eq!(one(engine("5.1.19041.1", "2.0")), ["powershell_downgrade"]);
        assert!(one(engine("5.1.19041.1", "5.1.19041.1")).is_empty());
        assert!(one(engine("2.0", "2.0")).is_empty(), "a genuine v2 host");
    }

    fn logon(data: Value) -> Value {
        event(SECURITY, 4624, T, data)
    }

    #[test]
    fn hash_and_new_credential_logons() {
        let pth = json!({"SubjectUserSid": "S-1-0-0", "LogonType": "3", "LogonProcessName": "NtLmSsp ",
            "KeyLength": "0", "TargetUserName": "admin", "AuthenticationPackageName": "NTLM"});
        assert_eq!(one(logon(pth)), ["pass_the_hash"]);
        let anon = json!({"SubjectUserSid": "S-1-0-0", "LogonType": "3", "LogonProcessName": "NtLmSsp",
            "KeyLength": "0", "TargetUserName": "ANONYMOUS LOGON"});
        assert!(one(logon(anon)).is_empty());
        let netonly = json!({"LogonType": "9", "LogonProcessName": "seclogo", "AuthenticationPackageName": "Negotiate",
            "TargetUserName": "bob"});
        let mut fired = one(logon(netonly));
        fired.sort_unstable();
        assert_eq!(fired, ["overpass_the_hash", "pass_the_hash"]);
    }

    #[test]
    fn remote_execution_services() {
        let svc = |name: &str, path: &str| {
            event(
                SCM,
                7045,
                T,
                json!({"ServiceName": name, "ImagePath": path,
            "ServiceType": "user mode service", "StartType": "demand start", "AccountName": "LocalSystem"}),
            )
        };
        assert_eq!(
            one(svc("PSEXESVC", "%SystemRoot%\\PSEXESVC.exe")),
            ["psexec_service_installed"]
        );
        assert_eq!(
            one(svc("RemComSvc", "C:\\Windows\\RemComSvc.exe")),
            ["remote_execution_tool_service"]
        );
        assert_eq!(
            one(svc("kXzQ", "%systemroot%\\aBcDeFgH.exe")),
            ["random_name_service"]
        );
        let smbexec = "%COMSPEC% /Q /c echo whoami ^> \\\\%COMPUTERNAME%\\C$\\__output_AbCdEfGh 2^>^&1 > %SYSTEMROOT%\\AbCdEfGh.bat & %COMSPEC% /Q /c %SYSTEMROOT%\\AbCdEfGh.bat & del %SYSTEMROOT%\\AbCdEfGh.bat";
        assert!(one(svc("AbCdEfGh", smbexec)).contains(&"smbexec_service"));
        assert!(one(svc("Spooler", "C:\\Windows\\System32\\spoolsv.exe")).is_empty());
        // 4697 (Security) flavour of the random-name pattern.
        let sec = event(
            SECURITY,
            4697,
            T,
            json!({"ServiceName": "QwErTyUi", "ServiceFileName": "%systemroot%\\zXcVbNmA.exe",
            "ServiceStartType": "3", "ServiceType": "0x10"}),
        );
        assert_eq!(one(sec), ["random_name_service"]);
    }

    #[test]
    fn named_pipes_and_shares() {
        let pipe = |name: &str, access: &str| {
            event(
                SECURITY,
                5145,
                T,
                json!({"ShareName": "\\\\*\\IPC$",
            "RelativeTargetName": name, "AccessList": access, "SubjectUserName": "bob", "IpAddress": "10.0.0.9"}),
            )
        };
        assert_eq!(
            one(pipe("svc-stdin", "%%4416\n\t\t")),
            ["renamed_psexec_pipes"]
        );
        assert!(
            one(pipe("PSEXESVC-HOST-1234-stdin", "%%4416")).is_empty(),
            "default PsExec has its own rule"
        );
        assert_eq!(
            one(pipe("RemCom_stdinAbCd", "%%4416")),
            ["impacket_psexec_pipes"]
        );
        assert_eq!(
            one(pipe("atsvc", "%%4417\n\t\t\t\t")),
            ["remote_task_via_atsvc"]
        );
        assert_eq!(
            one(pipe("svcctl", "WriteData")),
            ["remote_service_via_svcctl"]
        );
        assert!(one(pipe("svcctl", "%%4416")).is_empty(), "read only");

        let share = |name: &str, user: &str| {
            event(
                SECURITY,
                5140,
                T,
                json!({"ShareName": name, "SubjectUserName": user}),
            )
        };
        assert_eq!(one(share("\\\\*\\ADMIN$", "bob")), ["admin_share_access"]);
        assert!(one(share("\\\\*\\ADMIN$", "WKSTN01$")).is_empty());
        let write = |user: &str| {
            event(
                SECURITY,
                5145,
                T,
                json!({"ShareName": "\\\\*\\C$", "AccessMask": "0x2",
            "RelativeTargetName": "Windows\\Temp\\x.exe", "SubjectUserName": user, "IpAddress": "10.0.0.9"}),
            )
        };
        assert_eq!(one(write("bob")), ["admin_share_file_written"]);
        assert!(one(write("WKSTN01$")).is_empty());
    }

    #[test]
    fn remote_command_execution() {
        let wmi = "cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1716261392.5 2>&1";
        for mk in [sysmon_proc, security_proc] {
            assert_eq!(
                one(mk(
                    "C:\\Windows\\System32\\cmd.exe",
                    wmi,
                    "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
                )),
                ["impacket_remote_command"]
            );
            assert!(one(mk(
                "C:\\Windows\\System32\\cmd.exe",
                "cmd.exe /c dir",
                "C:\\Windows\\explorer.exe"
            ))
            .is_empty());
        }
    }

    #[test]
    fn rdp_and_external_logons() {
        let l = |t: &str, ip: &str| {
            logon(json!({"LogonType": t, "IpAddress": ip, "TargetUserName": "bob"}))
        };
        assert_eq!(one(l("10", "127.0.0.1")), ["rdp_from_localhost"]);
        assert_eq!(one(l("10", "203.0.113.7")), ["rdp_from_public_ip"]);
        assert_eq!(one(l("3", "198.51.100.20")), ["smb_from_public_ip"]);
        for private in [
            "10.1.2.3",
            "192.168.1.5",
            "172.20.0.1",
            "::ffff:10.20.30.40",
            "fe80::1",
            "fd12:3456::1",
            "-",
            "169.254.3.3",
        ] {
            assert!(one(l("3", private)).is_empty(), "{private} is not public");
        }
        assert!(
            one(l("3", "172.32.0.1")).contains(&"smb_from_public_ip"),
            "172.32/16 is public"
        );
        let ngrok = event(
            LSM,
            21,
            T,
            json!({"User": "CORP\\bob", "SessionID": "3", "Address": "16777216"}),
        );
        assert_eq!(one(ngrok), ["rdp_through_ngrok"]);
    }

    #[test]
    fn explicit_credentials() {
        let ec = |proc: &str, subj: &str, target: &str, server: &str| {
            event(
                SECURITY,
                4648,
                T,
                json!({
            "ProcessName": proc, "SubjectUserName": subj, "TargetUserName": target, "TargetServerName": server}),
            )
        };
        assert_eq!(
            one(ec("C:\\Windows\\System32\\cmd.exe", "bob", "admin", "DC01")),
            ["explicit_credentials_from_shell"]
        );
        assert!(one(ec(
            "C:\\Windows\\System32\\cmd.exe",
            "bob",
            "admin",
            "localhost"
        ))
        .is_empty());
        assert!(
            one(ec(
                "C:\\Windows\\System32\\cmd.exe",
                "WK1$",
                "DC01$",
                "DC01"
            ))
            .is_empty(),
            "computer to computer"
        );
        assert!(one(ec(
            "C:\\Windows\\System32\\svchost.exe",
            "bob",
            "admin",
            "DC01"
        ))
        .is_empty());
    }

    /// Prints rule hits for a real file: `EVTX_SAMPLE=file cargo test rules_on_sample -- --nocapture`
    #[test]
    fn rules_on_sample() {
        let Ok(path) = std::env::var("EVTX_SAMPLE") else {
            return;
        };
        let mut parser = evtx::EvtxParser::from_path(path).unwrap();
        let mut keys = KeyInterner::default();
        let recs: Vec<Record> = parser
            .records_json_value()
            .filter_map(Result::ok)
            .map(|r| {
                crate::model::Draft::new(r.event_record_id, 0, r.timestamp.to_string(), r.data)
                    .finish(&mut keys)
            })
            .collect();
        let keys_lc: Vec<Box<str>> = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        let (hits, errors) = run(&crate::detect::builtin_rules(), &recs, &keys_lc);
        assert!(errors.is_empty(), "{errors:?}");
        println!("{} records, {} rules", recs.len(), RULES.len());
        for h in hits {
            let ids: Vec<u64> = h
                .records
                .iter()
                .map(|&i| recs[i as usize].record_id)
                .collect();
            println!(
                "{:35} {:4} hits  records {:?}",
                RULES[h.rule].id,
                ids.len(),
                &ids[..ids.len().min(10)]
            );
        }
    }
}

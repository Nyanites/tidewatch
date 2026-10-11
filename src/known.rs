//! Built-in knowledge about common Windows events, so that records are readable without
//! the message DLLs that only exist on Windows.

use std::collections::HashMap;
use std::sync::OnceLock;

const SECURITY: &str = "Microsoft-Windows-Security-Auditing";
const EVENTLOG: &str = "Microsoft-Windows-Eventlog";
const SCM: &str = "Service Control Manager";
const SYSMON: &str = "Microsoft-Windows-Sysmon";
const PS: &str = "Microsoft-Windows-PowerShell";
const TASKS: &str = "Microsoft-Windows-TaskScheduler";
const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
const RCM: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager";
const DEFENDER: &str = "Microsoft-Windows-Windows Defender";
const FIREWALL: &str = "Microsoft-Windows-Windows Firewall With Advanced Security";

#[rustfmt::skip]
const DESCRIPTIONS: &[(&str, u32, &str)] = &[
    (SECURITY, 1100, "The event logging service has shut down"),
    (SECURITY, 1102, "The audit log was cleared"),
    (SECURITY, 4608, "Windows is starting up"),
    (SECURITY, 4609, "Windows is shutting down"),
    (SECURITY, 4610, "An authentication package has been loaded by the LSA"),
    (SECURITY, 4611, "A trusted logon process has been registered with the LSA"),
    (SECURITY, 4614, "A notification package has been loaded by the SAM"),
    (SECURITY, 4616, "The system time was changed"),
    (SECURITY, 4622, "A security package has been loaded by the LSA"),
    (SECURITY, 4624, "An account was successfully logged on"),
    (SECURITY, 4625, "An account failed to log on"),
    (SECURITY, 4627, "Group membership information"),
    (SECURITY, 4634, "An account was logged off"),
    (SECURITY, 4647, "User initiated logoff"),
    (SECURITY, 4648, "A logon was attempted using explicit credentials"),
    (SECURITY, 4656, "A handle to an object was requested"),
    (SECURITY, 4657, "A registry value was modified"),
    (SECURITY, 4658, "The handle to an object was closed"),
    (SECURITY, 4660, "An object was deleted"),
    (SECURITY, 4661, "A handle to an object was requested (SAM/AD)"),
    (SECURITY, 4662, "An operation was performed on an object"),
    (SECURITY, 4663, "An attempt was made to access an object"),
    (SECURITY, 4670, "Permissions on an object were changed"),
    (SECURITY, 4672, "Special privileges assigned to new logon"),
    (SECURITY, 4673, "A privileged service was called"),
    (SECURITY, 4674, "An operation was attempted on a privileged object"),
    (SECURITY, 4688, "A new process has been created"),
    (SECURITY, 4689, "A process has exited"),
    (SECURITY, 4696, "A primary token was assigned to process"),
    (SECURITY, 4697, "A service was installed in the system"),
    (SECURITY, 4698, "A scheduled task was created"),
    (SECURITY, 4699, "A scheduled task was deleted"),
    (SECURITY, 4700, "A scheduled task was enabled"),
    (SECURITY, 4701, "A scheduled task was disabled"),
    (SECURITY, 4702, "A scheduled task was updated"),
    (SECURITY, 4703, "A user right was adjusted"),
    (SECURITY, 4704, "A user right was assigned"),
    (SECURITY, 4705, "A user right was removed"),
    (SECURITY, 4706, "A new trust was created to a domain"),
    (SECURITY, 4713, "Kerberos policy was changed"),
    (SECURITY, 4715, "The audit policy (SACL) on an object was changed"),
    (SECURITY, 4716, "Trusted domain information was modified"),
    (SECURITY, 4717, "System security access was granted to an account"),
    (SECURITY, 4718, "System security access was removed from an account"),
    (SECURITY, 4719, "System audit policy was changed"),
    (SECURITY, 4720, "A user account was created"),
    (SECURITY, 4722, "A user account was enabled"),
    (SECURITY, 4723, "An attempt was made to change an account's password"),
    (SECURITY, 4724, "An attempt was made to reset an account's password"),
    (SECURITY, 4725, "A user account was disabled"),
    (SECURITY, 4726, "A user account was deleted"),
    (SECURITY, 4727, "A security-enabled global group was created"),
    (SECURITY, 4728, "A member was added to a security-enabled global group"),
    (SECURITY, 4729, "A member was removed from a security-enabled global group"),
    (SECURITY, 4730, "A security-enabled global group was deleted"),
    (SECURITY, 4731, "A security-enabled local group was created"),
    (SECURITY, 4732, "A member was added to a security-enabled local group"),
    (SECURITY, 4733, "A member was removed from a security-enabled local group"),
    (SECURITY, 4734, "A security-enabled local group was deleted"),
    (SECURITY, 4735, "A security-enabled local group was changed"),
    (SECURITY, 4737, "A security-enabled global group was changed"),
    (SECURITY, 4738, "A user account was changed"),
    (SECURITY, 4739, "Domain policy was changed"),
    (SECURITY, 4740, "A user account was locked out"),
    (SECURITY, 4741, "A computer account was created"),
    (SECURITY, 4742, "A computer account was changed"),
    (SECURITY, 4743, "A computer account was deleted"),
    (SECURITY, 4754, "A security-enabled universal group was created"),
    (SECURITY, 4755, "A security-enabled universal group was changed"),
    (SECURITY, 4756, "A member was added to a security-enabled universal group"),
    (SECURITY, 4757, "A member was removed from a security-enabled universal group"),
    (SECURITY, 4758, "A security-enabled universal group was deleted"),
    (SECURITY, 4764, "A group's type was changed"),
    (SECURITY, 4765, "SID History was added to an account"),
    (SECURITY, 4766, "An attempt to add SID History to an account failed"),
    (SECURITY, 4767, "A user account was unlocked"),
    (SECURITY, 4768, "A Kerberos authentication ticket (TGT) was requested"),
    (SECURITY, 4769, "A Kerberos service ticket was requested"),
    (SECURITY, 4770, "A Kerberos service ticket was renewed"),
    (SECURITY, 4771, "Kerberos pre-authentication failed"),
    (SECURITY, 4772, "A Kerberos authentication ticket request failed"),
    (SECURITY, 4776, "The computer attempted to validate the credentials for an account (NTLM)"),
    (SECURITY, 4778, "A session was reconnected to a Window Station"),
    (SECURITY, 4779, "A session was disconnected from a Window Station"),
    (SECURITY, 4781, "The name of an account was changed"),
    (SECURITY, 4794, "An attempt was made to set the Directory Services Restore Mode password"),
    (SECURITY, 4797, "An attempt was made to query the existence of a blank password"),
    (SECURITY, 4798, "A user's local group membership was enumerated"),
    (SECURITY, 4799, "A security-enabled local group membership was enumerated"),
    (SECURITY, 4800, "The workstation was locked"),
    (SECURITY, 4801, "The workstation was unlocked"),
    (SECURITY, 4802, "The screen saver was invoked"),
    (SECURITY, 4803, "The screen saver was dismissed"),
    (SECURITY, 4817, "Auditing settings on object were changed"),
    (SECURITY, 4826, "Boot Configuration Data loaded"),
    (SECURITY, 4902, "The Per-user audit policy table was created"),
    (SECURITY, 4904, "An attempt was made to register a security event source"),
    (SECURITY, 4905, "An attempt was made to unregister a security event source"),
    (SECURITY, 4906, "The CrashOnAuditFail value has changed"),
    (SECURITY, 4907, "Auditing settings on object were changed"),
    (SECURITY, 4912, "Per User Audit Policy was changed"),
    (SECURITY, 4946, "A rule was added to the Windows Firewall exception list"),
    (SECURITY, 4947, "A rule was modified in the Windows Firewall exception list"),
    (SECURITY, 4948, "A rule was deleted from the Windows Firewall exception list"),
    (SECURITY, 4950, "A Windows Firewall setting has changed"),
    (SECURITY, 4964, "Special groups have been assigned to a new logon"),
    (SECURITY, 5024, "The Windows Firewall service started successfully"),
    (SECURITY, 5025, "The Windows Firewall service was stopped"),
    (SECURITY, 5033, "The Windows Firewall Driver started successfully"),
    (SECURITY, 5038, "Code integrity determined that the image hash of a file is not valid"),
    (SECURITY, 5058, "Key file operation"),
    (SECURITY, 5059, "Key migration operation"),
    (SECURITY, 5061, "Cryptographic operation"),
    (SECURITY, 5136, "A directory service object was modified"),
    (SECURITY, 5137, "A directory service object was created"),
    (SECURITY, 5140, "A network share object was accessed"),
    (SECURITY, 5142, "A network share object was added"),
    (SECURITY, 5143, "A network share object was modified"),
    (SECURITY, 5144, "A network share object was deleted"),
    (SECURITY, 5145, "A network share object was checked for access"),
    (SECURITY, 5152, "The Windows Filtering Platform blocked a packet"),
    (SECURITY, 5154, "The Windows Filtering Platform permitted an application to listen on a port"),
    (SECURITY, 5156, "The Windows Filtering Platform permitted a connection"),
    (SECURITY, 5157, "The Windows Filtering Platform blocked a connection"),
    (SECURITY, 5158, "The Windows Filtering Platform permitted a bind to a local port"),
    (SECURITY, 5379, "Credential Manager credentials were read"),
    (SECURITY, 5381, "Vault credentials were read"),
    (SECURITY, 6416, "A new external device was recognized by the system"),

    (EVENTLOG, 104, "The log file was cleared"),
    (EVENTLOG, 1100, "The event logging service has shut down"),
    (EVENTLOG, 1102, "The audit log was cleared"),
    (EVENTLOG, 1104, "The security log is now full"),
    (EVENTLOG, 1105, "Event log automatic backup"),
    ("EventLog", 6005, "The Event log service was started"),
    ("EventLog", 6006, "The Event log service was stopped"),
    ("EventLog", 6008, "The previous system shutdown was unexpected"),
    ("EventLog", 6009, "Operating system version at boot"),
    ("EventLog", 6013, "System uptime"),

    ("Microsoft-Windows-Kernel-General", 1, "The system time was changed"),
    ("Microsoft-Windows-Kernel-General", 12, "The operating system started"),
    ("Microsoft-Windows-Kernel-General", 13, "The operating system is shutting down"),
    ("Microsoft-Windows-Kernel-Power", 41, "The system rebooted without cleanly shutting down first"),
    ("Microsoft-Windows-Kernel-Power", 42, "The system is entering sleep"),
    ("Microsoft-Windows-Kernel-Power", 107, "The system has resumed from sleep"),
    ("User32", 1074, "A process initiated a shutdown or restart"),
    ("Microsoft-Windows-Winlogon", 7001, "User logon notification (Customer Experience Improvement Program)"),
    ("Microsoft-Windows-Winlogon", 7002, "User logoff notification (Customer Experience Improvement Program)"),

    (SCM, 7000, "A service failed to start"),
    (SCM, 7001, "A service depends on a service that failed to start"),
    (SCM, 7009, "A timeout was reached waiting for a service to connect"),
    (SCM, 7011, "A timeout was reached waiting for a transaction response from a service"),
    (SCM, 7022, "A service hung on starting"),
    (SCM, 7023, "A service terminated with an error"),
    (SCM, 7024, "A service terminated with a service-specific error"),
    (SCM, 7026, "A boot-start or system-start driver failed to load"),
    (SCM, 7030, "A service is marked as interactive"),
    (SCM, 7031, "A service terminated unexpectedly (recovery action taken)"),
    (SCM, 7034, "A service terminated unexpectedly"),
    (SCM, 7035, "A service was sent a control"),
    (SCM, 7036, "A service entered a new state"),
    (SCM, 7040, "The start type of a service was changed"),
    (SCM, 7045, "A service was installed in the system"),

    (SYSMON, 1, "Process creation"),
    (SYSMON, 2, "A process changed a file creation time"),
    (SYSMON, 3, "Network connection"),
    (SYSMON, 4, "Sysmon service state changed"),
    (SYSMON, 5, "Process terminated"),
    (SYSMON, 6, "Driver loaded"),
    (SYSMON, 7, "Image loaded"),
    (SYSMON, 8, "CreateRemoteThread"),
    (SYSMON, 9, "RawAccessRead"),
    (SYSMON, 10, "Process accessed"),
    (SYSMON, 11, "File created"),
    (SYSMON, 12, "Registry object added or deleted"),
    (SYSMON, 13, "Registry value set"),
    (SYSMON, 14, "Registry object renamed"),
    (SYSMON, 15, "File stream created"),
    (SYSMON, 16, "Sysmon configuration change"),
    (SYSMON, 17, "Named pipe created"),
    (SYSMON, 18, "Named pipe connected"),
    (SYSMON, 19, "WMI event filter activity"),
    (SYSMON, 20, "WMI event consumer activity"),
    (SYSMON, 21, "WMI event consumer-to-filter activity"),
    (SYSMON, 22, "DNS query"),
    (SYSMON, 23, "File delete archived"),
    (SYSMON, 24, "Clipboard changed"),
    (SYSMON, 25, "Process tampering"),
    (SYSMON, 26, "File delete logged"),
    (SYSMON, 27, "File block executable"),
    (SYSMON, 28, "File block shredding"),
    (SYSMON, 29, "File executable detected"),
    (SYSMON, 255, "Sysmon error"),

    (PS, 4100, "PowerShell error"),
    (PS, 4103, "Module logging (pipeline execution)"),
    (PS, 4104, "Script block logging"),
    (PS, 4105, "Script block invocation started"),
    (PS, 4106, "Script block invocation completed"),
    (PS, 40961, "PowerShell console is starting up"),
    (PS, 40962, "PowerShell console is ready for user input"),
    (PS, 53504, "PowerShell IPC listening thread started"),
    ("PowerShell", 400, "PowerShell engine state changed to Available"),
    ("PowerShell", 403, "PowerShell engine state changed to Stopped"),
    ("PowerShell", 600, "PowerShell provider started"),
    ("PowerShell", 800, "Pipeline execution details"),

    (TASKS, 100, "Task started"),
    (TASKS, 102, "Task completed"),
    (TASKS, 106, "Task registered"),
    (TASKS, 129, "Task launched a process"),
    (TASKS, 140, "Task updated"),
    (TASKS, 141, "Task deleted"),
    (TASKS, 200, "Task action started"),
    (TASKS, 201, "Task action completed"),

    (LSM, 21, "Remote Desktop session logon succeeded"),
    (LSM, 22, "Remote Desktop shell start notification received"),
    (LSM, 23, "Remote Desktop session logoff succeeded"),
    (LSM, 24, "Remote Desktop session has been disconnected"),
    (LSM, 25, "Remote Desktop session reconnection succeeded"),
    (LSM, 39, "Session was disconnected by another session"),
    (LSM, 40, "Session was disconnected (reason code)"),
    (RCM, 261, "Listener received a connection"),
    (RCM, 1149, "Remote Desktop user authentication succeeded"),

    (DEFENDER, 1006, "Malware or potentially unwanted software detected"),
    (DEFENDER, 1007, "Action taken to protect the system from malware"),
    (DEFENDER, 1008, "Action to protect the system from malware failed"),
    (DEFENDER, 1116, "Malware or potentially unwanted software detected"),
    (DEFENDER, 1117, "Action taken to protect the system from malware"),
    (DEFENDER, 1118, "Action to protect the system from malware failed"),
    (DEFENDER, 1119, "Critical error taking action on malware"),
    (DEFENDER, 5001, "Real-time protection was disabled"),
    (DEFENDER, 5007, "Antimalware platform configuration changed"),
    (DEFENDER, 5010, "Scanning for malware and unwanted software is disabled"),
    (DEFENDER, 5012, "Scanning for viruses is disabled"),

    (FIREWALL, 2004, "A firewall rule was added"),
    (FIREWALL, 2005, "A firewall rule was changed"),
    (FIREWALL, 2006, "A firewall rule was deleted"),
    (FIREWALL, 2033, "All firewall rules were deleted"),

    ("Microsoft-Windows-WMI-Activity", 5857, "WMI provider started"),
    ("Microsoft-Windows-WMI-Activity", 5858, "WMI operation error"),
    ("Microsoft-Windows-WMI-Activity", 5860, "Temporary WMI event consumer registered"),
    ("Microsoft-Windows-WMI-Activity", 5861, "Permanent WMI event consumer registered"),
    ("Microsoft-Windows-Bits-Client", 59, "BITS transfer job started"),
    ("Microsoft-Windows-Bits-Client", 60, "BITS transfer job stopped"),
    ("Application Error", 1000, "Application crashed"),
    ("Application Hang", 1002, "Application stopped responding"),
    ("Windows Error Reporting", 1001, "Windows Error Reporting fault bucket"),
    ("MsiInstaller", 1033, "Windows Installer installed a product"),
    ("MsiInstaller", 1034, "Windows Installer removed a product"),
    ("MsiInstaller", 11707, "Product installation completed successfully"),
    ("MsiInstaller", 11724, "Product removal completed successfully"),
];

fn table() -> &'static HashMap<(String, u32), &'static str> {
    static T: OnceLock<HashMap<(String, u32), &'static str>> = OnceLock::new();
    T.get_or_init(|| {
        DESCRIPTIONS
            .iter()
            .map(|(p, id, d)| ((p.to_ascii_lowercase(), *id), *d))
            .collect()
    })
}

/// A short human description of an event, if it is a well-known one.
pub fn describe(provider: &str, event_id: u32) -> &'static str {
    table()
        .get(&(provider.to_ascii_lowercase(), event_id))
        .copied()
        .unwrap_or("")
}

/// Human-readable meaning of a raw field value, e.g. `LogonType=3` -> "Network".
/// `key` is the field's last path segment.
pub fn annotate(key: &str, value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if let Some(s) = msobjs(value) {
        return Some(s.into());
    }
    let k = key.to_ascii_lowercase();
    let s: &str = match k.as_str() {
        "level" => match value {
            "0" => "Information",
            "1" => "Critical",
            "2" => "Error",
            "3" => "Warning",
            "4" => "Information",
            "5" => "Verbose",
            _ => return None,
        },
        "opcode" => match value {
            "0" => "Info",
            "1" => "Start",
            "2" => "Stop",
            "3" => "DC Start",
            "4" => "DC Stop",
            "5" => "Extension",
            "6" => "Reply",
            "7" => "Resume",
            "8" => "Suspend",
            "9" => "Send",
            "240" => "Receive",
            _ => return None,
        },
        "keywords" => return keywords(value),
        "logontype" => match value {
            "0" => "System",
            "2" => "Interactive",
            "3" => "Network",
            "4" => "Batch",
            "5" => "Service",
            "7" => "Unlock",
            "8" => "NetworkCleartext",
            "9" => "NewCredentials",
            "10" => "RemoteInteractive (RDP)",
            "11" => "CachedInteractive",
            "12" => "CachedRemoteInteractive",
            "13" => "CachedUnlock",
            _ => return None,
        },
        "status" | "substatus" | "failurecode" | "errorcode" | "result" => {
            status(&value.to_ascii_lowercase())?
        }
        "ticketencryptiontype" => match value.to_ascii_lowercase().as_str() {
            "0x1" => "DES-CBC-CRC",
            "0x3" => "DES-CBC-MD5",
            "0x11" => "AES128-CTS-HMAC-SHA1-96",
            "0x12" => "AES256-CTS-HMAC-SHA1-96",
            "0x17" => "RC4-HMAC",
            "0x18" => "RC4-HMAC-EXP",
            "0xffffffff" => "Failure",
            _ => return None,
        },
        _ if k.ends_with("sid") || k == "userid" => return sid(value),
        _ => return None,
    };
    Some(s.into())
}

fn keywords(value: &str) -> Option<String> {
    let v = u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()?;
    const BITS: &[(u64, &str)] = &[
        (0x0010_0000_0000_0000, "Audit Failure"),
        (0x0020_0000_0000_0000, "Audit Success"),
        (0x0080_0000_0000_0000, "Classic"),
        (0x0040_0000_0000_0000, "Correlation Hint"),
        (0x0001_0000_0000_0000, "Response Time"),
        (0x0002_0000_0000_0000, "WDI Context"),
        (0x0004_0000_0000_0000, "WDI Diagnostic"),
        (0x0008_0000_0000_0000, "SQM"),
    ];
    let names: Vec<&str> = BITS
        .iter()
        .filter(|(b, _)| v & b != 0)
        .map(|(_, n)| *n)
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
}

fn status(v: &str) -> Option<&'static str> {
    Some(match v {
        "0x0" => "Success",
        "0xc0000064" => "User name does not exist",
        "0xc000006a" => "Correct user name but wrong password",
        "0xc000006d" => "Bad user name or authentication information",
        "0xc000006e" => "Account restriction",
        "0xc000006f" => "Logon outside authorized hours",
        "0xc0000070" => "Logon from unauthorized workstation",
        "0xc0000071" => "Password expired",
        "0xc0000072" => "Account disabled",
        "0xc00000dc" => "Server in wrong state",
        "0xc0000133" => "Clock out of sync with DC",
        "0xc000015b" => "Logon type not granted",
        "0xc000018c" => "Trust relationship failed",
        "0xc0000192" => "NetLogon service not started",
        "0xc0000193" => "Account expired",
        "0xc0000224" => "User must change password at next logon",
        "0xc0000225" => "Windows bug, not a risk",
        "0xc0000234" => "Account locked out",
        "0xc00002ee" => "Failure reason: an error occurred during logon",
        "0xc0000413" => "Authentication firewall: machine not allowed",
        "0xc000005e" => "No logon servers available",
        "0x6" => "Kerberos: client not found in database",
        "0x12" => "Kerberos: client credentials revoked (disabled/locked/expired)",
        "0x17" => "Kerberos: password has expired",
        "0x18" => "Kerberos: pre-authentication failed (bad password)",
        "0x25" => "Kerberos: clock skew too great",
        _ => return None,
    })
}

fn sid(v: &str) -> Option<String> {
    let s = match v {
        "S-1-0-0" => "NULL SID",
        "S-1-1-0" => "Everyone",
        "S-1-2-0" => "Local",
        "S-1-3-0" => "Creator Owner",
        "S-1-5-2" => "Network",
        "S-1-5-4" => "Interactive",
        "S-1-5-6" => "Service",
        "S-1-5-7" => "Anonymous Logon",
        "S-1-5-9" => "Enterprise Domain Controllers",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-18" => "SYSTEM",
        "S-1-5-19" => "LOCAL SERVICE",
        "S-1-5-20" => "NETWORK SERVICE",
        "S-1-5-32-544" => "BUILTIN\\Administrators",
        "S-1-5-32-545" => "BUILTIN\\Users",
        "S-1-5-32-546" => "BUILTIN\\Guests",
        "S-1-5-32-547" => "BUILTIN\\Power Users",
        "S-1-5-32-548" => "BUILTIN\\Account Operators",
        "S-1-5-32-549" => "BUILTIN\\Server Operators",
        "S-1-5-32-550" => "BUILTIN\\Print Operators",
        "S-1-5-32-551" => "BUILTIN\\Backup Operators",
        "S-1-5-32-552" => "BUILTIN\\Replicators",
        "S-1-5-32-555" => "BUILTIN\\Remote Desktop Users",
        "S-1-5-32-556" => "BUILTIN\\Network Configuration Operators",
        "S-1-5-32-562" => "BUILTIN\\Distributed COM Users",
        "S-1-5-32-573" => "BUILTIN\\Event Log Readers",
        "S-1-5-32-578" => "BUILTIN\\Hyper-V Administrators",
        "S-1-5-32-580" => "BUILTIN\\Remote Management Users",
        _ if v.starts_with("S-1-5-80-") => "NT SERVICE account",
        _ if v.starts_with("S-1-5-90-") => "Window Manager (DWM)",
        _ if v.starts_with("S-1-5-96-") => "Font Driver Host (UMFD)",
        _ if v.starts_with("S-1-5-21-") => {
            return match v.rsplit('-').next()? {
                "500" => Some("Administrator (built-in)".into()),
                "501" => Some("Guest (built-in)".into()),
                "502" => Some("krbtgt".into()),
                "512" => Some("Domain Admins".into()),
                "513" => Some("Domain Users".into()),
                "514" => Some("Domain Guests".into()),
                "515" => Some("Domain Computers".into()),
                "516" => Some("Domain Controllers".into()),
                "518" => Some("Schema Admins".into()),
                "519" => Some("Enterprise Admins".into()),
                "544" => Some("Administrators".into()),
                _ => None,
            }
        }
        _ => return None,
    };
    Some(s.into())
}

/// Common `%%NNNN` message-table placeholders from msobjs.dll.
fn msobjs(v: &str) -> Option<&'static str> {
    Some(match v {
        "%%1832" => "Identification",
        "%%1833" => "Impersonation",
        "%%1840" => "Delegation",
        "%%1842" => "Yes",
        "%%1843" => "No",
        "%%1936" => "Type 1: full token, no privileges removed (UAC off or built-in admin)",
        "%%1937" => "Type 2: elevated token",
        "%%1938" => "Type 3: limited token",
        "%%2307" => "Account locked out",
        "%%2308" => "Account disabled",
        "%%2309" => "Account expired",
        "%%2310" => "Account restricted",
        "%%2311" => "Logon outside authorized hours",
        "%%2312" => "Workstation restriction",
        "%%2313" => "Unknown user name or bad password",
        "%%4416" => "ReadData (or ListDirectory)",
        "%%4417" => "WriteData (or AddFile)",
        "%%4418" => "AppendData (or AddSubdirectory)",
        "%%4423" => "ReadAttributes",
        "%%4424" => "WriteAttributes",
        "%%1537" => "DELETE",
        "%%1538" => "READ_CONTROL",
        "%%1539" => "WRITE_DAC",
        "%%1540" => "WRITE_OWNER",
        "%%1541" => "SYNCHRONIZE",
        "%%8100" => "Enabled",
        "%%8101" => "Disabled",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes() {
        assert_eq!(
            describe("microsoft-windows-security-auditing", 4624),
            "An account was successfully logged on"
        );
        assert_eq!(
            annotate("Keywords", "0x8020000000000000").as_deref(),
            Some("Audit Success")
        );
        assert_eq!(
            annotate("LogonType", "10").as_deref(),
            Some("RemoteInteractive (RDP)")
        );
        assert_eq!(
            annotate("SubjectUserSid", "S-1-5-18").as_deref(),
            Some("SYSTEM")
        );
        assert_eq!(
            annotate("SubStatus", "0xC000006A").as_deref(),
            Some("Correct user name but wrong password")
        );
        assert_eq!(
            annotate("TargetSid", "S-1-5-21-1-2-3-500").as_deref(),
            Some("Administrator (built-in)")
        );
        assert_eq!(annotate("ProcessId", "0x4"), None);
    }
}

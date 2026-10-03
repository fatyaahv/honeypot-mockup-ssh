"""MITRE ATT&CK mapping data for observed honeypot behaviors.

IDs, names, and tactic labels are taken from the MITRE ATT&CK Enterprise matrix.
Mappings are associations for triage, not claims of adversary intent or impact.
"""

TECHNIQUES = {
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1033/",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1016/",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1003.008": {
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1003/008/",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
    },
    "T1059.006": {
        "name": "Command and Scripting Interpreter: Python",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/006/",
    },
    "T1222.002": {
        "name": "File and Directory Permissions Modification: Linux and Mac Permissions",
        "tactic": "Defense Impairment",
        "url": "https://attack.mitre.org/techniques/T1222/002/",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1095/",
    },
}

# Each entry links one detected behavior to one technique and explains the limits
# of that association. Unlisted detections intentionally remain unmapped.
BEHAVIOR_MAPPINGS = {
    "repeated_failed_ssh_authentication": {
        "technique_id": "T1110.001",
        "explanation": "Repeated SSH password failures are consistent with password guessing; the alert does not establish intent.",
    },
    "successful_ssh_authentication": {
        "technique_id": "T1078",
        "explanation": "An accepted SSH login can be associated with Valid Accounts; Cowrie acceptance does not verify a real host account or credential.",
    },
    "system_user_discovery": {
        "technique_id": "T1033",
        "explanation": "whoami and id can reveal the current user or account context.",
    },
    "system_information_discovery": {
        "technique_id": "T1082",
        "explanation": "uname can reveal operating-system and system information.",
    },
    "network_configuration_discovery": {
        "technique_id": "T1016",
        "explanation": "ip addr and ifconfig can reveal local network configuration.",
    },
    "file_directory_discovery": {
        "technique_id": "T1083",
        "explanation": "ls and find can enumerate files and directories.",
    },
    "passwd_file_access": {
        "technique_id": "T1003.008",
        "explanation": "An attempt to read /etc/passwd is related to this credential-file technique; it does not prove hashes were obtained.",
    },
    "download_command": {
        "technique_id": "T1105",
        "explanation": "wget or curl may transfer a tool into a system; the observed command alone does not prove a transfer succeeded.",
    },
    "unix_shell_execution": {
        "technique_id": "T1059.004",
        "explanation": "Invoking bash is associated with Unix shell command execution; the command alone does not establish malicious intent.",
    },
    "python_interpreter_execution": {
        "technique_id": "T1059.006",
        "explanation": "Invoking Python is associated with Python command or script execution; the command alone does not establish malicious intent.",
    },
    "permission_modification": {
        "technique_id": "T1222.002",
        "explanation": "chmod can modify Linux file permissions; observed invocation does not establish that a change succeeded.",
    },
    "network_utility_usage": {
        "technique_id": "T1095",
        "explanation": "nc can be used for non-application-layer communication, but its invocation alone does not identify protocol or purpose.",
    },
}

DETECTION_MAPPINGS = {
    "brute_force": "repeated_failed_ssh_authentication",
    "success_after_repeated_failures": "successful_ssh_authentication",
}

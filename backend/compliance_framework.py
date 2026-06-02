# compliance_framework.py
# Sentri OT - DESC & IEC 62443-3-3 Compliance Framework
# Evaluates BMS/OT cybersecurity posture via passive BACnet monitoring data
#
# Frameworks:
#   DESC  - Dubai Electronic Security Center ICS/OT Standard
#   IEC   - ISA/IEC 62443-3-3 (Security Requirements for IACS)
#
# Observability levels:
#   network - Assessable from passive BACnet traffic analysis
#   config  - Requires device configuration review
#   manual  - Requires physical inspection or document review
#   policy  - Requires policy/documentation review

import json
from datetime import datetime, timezone
from typing import Any


# ═══════════════════════════════════════════════════════════════════
# DESC FRAMEWORK - Dubai ICS/OT Security Standard Controls
# ═══════════════════════════════════════════════════════════════════

DESC_FRAMEWORK: list[dict] = [
    # ─── AST: Asset Management (AST-01 through AST-05) ────────────
    {
        "id": "AST-01",
        "framework": "DESC",
        "category": "Asset Management",
        "title": "OT Asset Inventory Maintained",
        "description": "The organization shall maintain an accurate, up-to-date inventory of all OT assets including BACnet controllers, sensors, actuators, gateways, and workstations connected to the BMS network.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.8",
        "observability": "network",
        "evidence_rules": {
            "bacnet_devices_found": {"weight": 3, "operator": "gte", "threshold": 1},
            "bacnet_device_details": {"weight": 2, "operator": "pct", "threshold": 80}
        },
        "default_status": "FAIL",
        "remediation": "Deploy BACnet device discovery to identify all BMS controllers, sensors, and gateways. Maintain a centralized asset register with device IDs, locations, firmware versions, and IP addresses. Use passive BACnet monitoring to auto-detect new devices and flag unregistered ones."
    },
    {
        "id": "AST-02",
        "framework": "DESC",
        "category": "Asset Management",
        "title": "Asset Criticality Classification",
        "description": "All OT assets shall be classified based on criticality to building operations, safety, and security. Critical systems must be identified for prioritized protection.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.8",
        "observability": "config",
        "evidence_rules": {
            "bacnet_device_details": {"weight": 2, "operator": "pct", "threshold": 90},
            "bacnet_device_types_identified": {"weight": 1, "operator": "gte", "threshold": 3}
        },
        "default_status": "FAIL",
        "remediation": "Categorize all BMS assets by criticality (HVAC, fire/life safety, lighting, access control, elevators). Tag BACnet devices with criticality levels. Critical assets must have enhanced monitoring and stricter access controls."
    },
    {
        "id": "AST-03",
        "framework": "DESC",
        "category": "Asset Management",
        "title": "Firmware and Software Version Tracking",
        "description": "Current firmware and software versions of all OT assets shall be tracked and maintained in an asset inventory system with version history.",
        "mapping_to_iec": "IEC 62443-3-3 SR 3.3",
        "observability": "network",
        "evidence_rules": {
            "bacnet_device_details": {"weight": 3, "operator": "pct", "threshold": 70},
            "firmware_versions_found": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Configure BACnet devices to report firmware versions via Device Object properties. Implement automated firmware version collection through BACnet ReadProperty requests. Establish a firmware version database and alert on outdated versions."
    },
    {
        "id": "AST-04",
        "framework": "DESC",
        "category": "Asset Management",
        "title": "Asset Lifecycle Management",
        "description": "OT assets shall be managed throughout their lifecycle including procurement, deployment, maintenance, and decommissioning with end-of-life tracking.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.8",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Implement asset lifecycle management process for all BMS components. Track procurement dates, warranty periods, end-of-life dates, and decommissioning status. Conduct quarterly lifecycle reviews for BACnet controllers and gateways."
    },
    {
        "id": "AST-05",
        "framework": "DESC",
        "category": "Asset Management",
        "title": "Configuration Baseline Management",
        "description": "A configuration baseline shall be established and maintained for all OT assets covering firmware, settings, network parameters, and BACnet object configurations.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.6",
        "observability": "network",
        "evidence_rules": {
            "bacnet_device_details": {"weight": 2, "operator": "pct", "threshold": 70},
            "bacnet_vendor_uniformity": {"weight": 3, "operator": "gte", "threshold": 90}
        },
        "default_status": "FAIL",
        "remediation": "Establish configuration baselines for each BACnet device model. Monitor for configuration drift using passive BACnet traffic analysis. Alert when devices deviate from their baseline configuration. Standardize configuration across multiple devices from the same vendor."
    },

    # ─── IAM: Identity & Access Management (IAM-01 through IAM-06) ──
    {
        "id": "IAM-01",
        "framework": "DESC",
        "category": "Identity and Access Management",
        "title": "Unique User Identification",
        "description": "Each user accessing the BMS/OT network shall be assigned a unique identifier. Shared or generic accounts are prohibited for OT systems.",
        "mapping_to_iec": "IEC 62443-3-3 SR 1.1",
        "observability": "config",
        "evidence_rules": {
            "unique_users_found": {"weight": 3, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Configure all BACnet workstations and BMS servers to enforce unique user accounts. Audit existing accounts to identify and eliminate shared or generic accounts. Implement directory service integration (LDAP/AD) for centralized user management."
    },
    {
        "id": "IAM-02",
        "framework": "DESC",
        "category": "Identity and Access Management",
        "title": "Least Privilege Access Control",
        "description": "Users, processes, and devices shall be granted the minimum access rights necessary to perform their authorized functions on the OT network.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.1",
        "observability": "config",
        "evidence_rules": {
            "user_role_counts": {"weight": 3, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Implement role-based access control (RBAC) for all BMS workstations and BACnet management tools. Define minimum-required roles for operators, engineers, and administrators. Review and remove excessive privileges quarterly."
    },
    {
        "id": "IAM-03",
        "framework": "DESC",
        "category": "Identity and Access Management",
        "title": "Default Credential Management",
        "description": "All default credentials on OT devices, including BACnet controllers, gateways, and management interfaces, shall be changed before deployment.",
        "mapping_to_iec": "IEC 62443-3-3 SR 1.5",
        "observability": "network",
        "evidence_rules": {
            "default_credentials_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "FAIL",
        "remediation": "Change all default passwords on BACnet controllers, BMS servers, and network devices. Check for known default credentials (e.g., 'admin/admin', 'BACnet/BACnet', 'metasys/metasys'). Implement password complexity requirements and regular password rotation policies."
    },
    {
        "id": "IAM-04",
        "framework": "DESC",
        "category": "Identity and Access Management",
        "title": "Remote Access Control",
        "description": "Remote access to the OT network shall be controlled, monitored, and restricted through secure gateways with multi-factor authentication.",
        "mapping_to_iec": "IEC 62443-3-3 SR 1.13",
        "observability": "network",
        "evidence_rules": {
            "remote_access_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "vpn_gateway_present": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Implement a jump box or VPN gateway for all remote access to the BMS network. Enforce multi-factor authentication (MFA) for remote connections. Log and monitor all remote access sessions. Disable direct remote access to BACnet controllers."
    },
    {
        "id": "IAM-05",
        "framework": "DESC",
        "category": "Identity and Access Management",
        "title": "Authentication Mechanisms",
        "description": "Strong authentication mechanisms shall be implemented for all OT system access, supporting password policies, certificate-based authentication, or biometrics where appropriate.",
        "mapping_to_iec": "IEC 62443-3-3 SR 1.3",
        "observability": "config",
        "evidence_rules": {
            "auth_mechanisms_count": {"weight": 3, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Disable plaintext authentication protocols on BMS interfaces. Implement certificate-based or token-based authentication for BACnet/SC if available. Enforce strong password policies (minimum 12 characters, complexity requirements, expiration)."
    },
    {
        "id": "IAM-06",
        "framework": "DESC",
        "category": "Identity and Access Management",
        "title": "Session Management",
        "description": "User sessions on OT systems shall be managed with timeout controls, concurrent session limits, and termination upon logout.",
        "mapping_to_iec": "IEC 62443-3-3 SR 1.11",
        "observability": "config",
        "evidence_rules": {
            "session_timeouts_enabled": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Configure inactivity timeouts (max 15 minutes) on all BMS workstations and BACnet management consoles. Enable automatic session termination after idle periods. Implement concurrent session limits per user account."
    },

    # ─── NWS: Network Security (NWS-01 through NWS-08) ──────────
    {
        "id": "NWS-01",
        "framework": "DESC",
        "category": "Network Security",
        "title": "Network Segmentation and Zoning",
        "description": "The BMS/OT network shall be segmented from corporate IT networks using firewalls and/or physical separation. OT zones shall be defined based on criticality and function.",
        "mapping_to_iec": "IEC 62443-3-3 SR 5.1",
        "observability": "network",
        "evidence_rules": {
            "bacnet_it_ot_cross_traffic": {"weight": 3, "operator": "eq", "threshold": False},
            "bacnet_broadcast_domains": {"weight": 2, "operator": "lte", "threshold": 2},
            "zones_detected": {"weight": 1, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Segment BACnet BMS traffic onto dedicated VLANs physically or logically separated from corporate IT networks. Implement firewalls between OT zones with whitelist rules. Use BACnet/SC or BACnet/IP with proper VLAN segmentation. Detect and alert on BACnet traffic crossing zone boundaries."
    },
    {
        "id": "NWS-02",
        "framework": "DESC",
        "category": "Network Security",
        "title": "Firewall and Access Control Lists",
        "description": "Firewalls and ACLs shall be deployed at OT network boundaries and between OT zones to enforce traffic filtering based on least privilege principles.",
        "mapping_to_iec": "IEC 62443-3-3 SR 5.2",
        "observability": "network",
        "evidence_rules": {
            "acls_detected": {"weight": 3, "operator": "eq", "threshold": True},
            "bacnet_port_restricted": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Deploy firewalls at all OT network boundaries. Configure ACLs to restrict BACnet traffic (UDP 47808) to authorized source IPs only. Implement whitelist-based firewall rules for BMS traffic. Block all non-essential ports and protocols at OT boundaries."
    },
    {
        "id": "NWS-03",
        "framework": "DESC",
        "category": "Network Security",
        "title": "Wireless Network Security",
        "description": "Wireless networks used for BMS communications shall be secured with strong encryption, authentication, and monitoring controls.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.12",
        "observability": "network",
        "evidence_rules": {
            "wireless_ssids_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Implement WPA2-Enterprise or WPA3 for all wireless BMS connections. Use separate SSID for OT devices with strong pre-shared keys. Deploy wireless intrusion detection. Disable WPS and legacy wireless protocols on BMS wireless gateways."
    },
    {
        "id": "NWS-04",
        "framework": "DESC",
        "category": "Network Security",
        "title": "Data-in-Transit Protection",
        "description": "Data transmitted across OT networks, especially across zone boundaries, shall be protected using encryption and integrity mechanisms.",
        "mapping_to_iec": "IEC 62443-3-3 SR 4.1",
        "observability": "network",
        "evidence_rules": {
            "bacnet_plaintext_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "encrypted_protocols_detected": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Upgrade BACnet/IP deployments to BACnet/SC (BACnet Secure Connect) which provides TLS 1.3 encryption for all BACnet communications. For BACnet/IP existing installations, use VPN tunnels or IPsec between segments. Verify no plaintext BACnet traffic crosses untrusted networks."
    },
    {
        "id": "NWS-05",
        "framework": "DESC",
        "category": "Network Security",
        "title": "Remote Access Security",
        "description": "Remote access to OT systems shall be secured through encrypted tunnels, MFA, access logging, and time-limited approvals.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.13",
        "observability": "network",
        "evidence_rules": {
            "remote_access_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "remote_access_vpn": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Implement site-to-site VPN with IPsec/TLS for remote BMS connections. Use jump host architecture with session recording for vendor remote access. Enforce time-limited, approved access requests. Log all remote access sessions with user identification."
    },
    {
        "id": "NWS-06",
        "framework": "DESC",
        "category": "Network Security",
        "title": "Network Monitoring and Traffic Analysis",
        "description": "OT network traffic shall be continuously monitored to detect anomalies, unauthorized access, and security events using passive and active monitoring tools.",
        "mapping_to_iec": "IEC 62443-3-3 SR 6.1",
        "observability": "network",
        "evidence_rules": {
            "traffic_monitoring_active": {"weight": 3, "operator": "eq", "threshold": True},
            "bbmd_exposure_detected": {"weight": 2, "operator": "eq", "threshold": False}
        },
        "default_status": "FAIL",
        "remediation": "Deploy passive BACnet traffic monitoring on all OT network segments. Analyze traffic patterns for anomalies, unauthorized devices, and protocol violations. Monitor BBMD (BACnet Broadcast Management Device) traffic to detect misconfigurations. Implement network behavior analytics for BACnet-specific patterns."
    },
    {
        "id": "NWS-07",
        "framework": "DESC",
        "category": "Network Security",
        "title": "Network Device Hardening",
        "description": "All network devices (switches, routers, firewalls) in the OT environment shall be hardened by disabling unnecessary services, changing default passwords, and applying security configurations.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.6",
        "observability": "config",
        "evidence_rules": {
            "network_device_hardening_verified": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Disable unused ports (CDP, LLDP, HTTP, SNMP read/write) on OT network switches. Enable port security and MAC address filtering. Disable DHCP on OT switchports where static assignments are used. Configure SNMPv3 with encryption instead of SNMPv1/v2c."
    },
    {
        "id": "NWS-08",
        "framework": "DESC",
        "category": "Network Security",
        "title": "IP and Port Management",
        "description": "IP address allocation and port usage on the OT network shall be managed with static assignments, port security, and regular audits.",
        "mapping_to_iec": "IEC 62443-3-3 SR 5.3",
        "observability": "network",
        "evidence_rules": {
            "bacnet_port_47808_detected": {"weight": 2, "operator": "eq", "threshold": True},
            "unexpected_ports_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Assign static IP addresses to all BACnet devices. Implement DHCP snooping to prevent rogue DHCP servers. Document all IP-to-MAC mappings for the BMS subnet. Audit open ports on BACnet devices monthly. Block ports other than BACnet/UDP 47808 on BMS VLANs."
    },

    # ─── SCP: System & Communication Protection (SCP-01 through SCP-05) ──
    {
        "id": "SCP-01",
        "framework": "DESC",
        "category": "System and Communication Protection",
        "title": "Encryption Standards Implementation",
        "description": "Encryption standards shall be implemented for all OT communications with key management, certificate handling, and algorithm selection according to approved standards.",
        "mapping_to_iec": "IEC 62443-3-3 SR 4.1",
        "observability": "network",
        "evidence_rules": {
            "bacnet_plaintext_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "encryption_mechanisms_count": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Migrate from BACnet/IP to BACnet/SC (BACnet Secure Connect) which mandates TLS 1.3 encryption. For legacy BACnet/IP devices, deploy a BACnet/SC gateway to encrypt traffic at zone boundaries. Implement certificate lifecycle management for all BACnet/SC devices."
    },
    {
        "id": "SCP-02",
        "framework": "DESC",
        "category": "System and Communication Protection",
        "title": "Protocol Security Hardening",
        "description": "OT protocols including BACnet shall be hardened by disabling insecure features, enabling security extensions, and following secure implementation guidelines.",
        "mapping_to_iec": "IEC 62443-3-3 SR 3.1",
        "observability": "network",
        "evidence_rules": {
            "bacnet_secure_connect_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "bacnet_protocol_anomalies": {"weight": 2, "operator": "eq", "threshold": False}
        },
        "default_status": "FAIL",
        "remediation": "Enable BACnet/SC (Secure Connect) with TLS 1.3 on all capable devices. Disable BACnet/IP on devices that support BACnet/SC. For BACnet/IP deployments, restrict to dedicated VLANs and monitor for protocol anomalies. Disable unused BACnet services (e.g., WritePropertyMultiple if not needed)."
    },
    {
        "id": "SCP-03",
        "framework": "DESC",
        "category": "System and Communication Protection",
        "title": "Port and Service Hardening",
        "description": "Unnecessary network ports and services on OT devices shall be disabled to reduce the attack surface, with only required services enabled.",
        "mapping_to_iec": "IEC 62443-3-3 SR 5.3",
        "observability": "network",
        "evidence_rules": {
            "unexpected_ports_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Conduct port scans on all BMS subnets. Disable HTTP, Telnet, and FTP on BACnet controllers and gateways. Enable only BACnet/UDP 47808 (or BACnet/SC on TCP 1962). Disable SNMP public/private community strings on BMS devices."
    },
    {
        "id": "SCP-04",
        "framework": "DESC",
        "category": "System and Communication Protection",
        "title": "Secure Device Configuration",
        "description": "All OT devices shall be configured securely following vendor hardening guidelines and industry best practices, with security features enabled.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.6",
        "observability": "config",
        "evidence_rules": {
            "secure_config_verified_pct": {"weight": 3, "operator": "pct", "threshold": 80}
        },
        "default_status": "FAIL",
        "remediation": "Apply vendor hardening guides to all BACnet controllers and gateways. Enable password protection on BACnet device objects. Disable BACnet WriteProperty for unauthorized services on critical devices. Configure access lists on BACnet devices to restrict which IPs can communicate with them."
    },
    {
        "id": "SCP-05",
        "framework": "DESC",
        "category": "System and Communication Protection",
        "title": "Time Synchronization Security",
        "description": "Time synchronization across OT devices shall be implemented securely using authenticated NTP, with BACnet devices configured for time synchronization.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.3",
        "observability": "network",
        "evidence_rules": {
            "time_sync_detected": {"weight": 3, "operator": "eq", "threshold": True},
            "ntp_authentication_verified": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Configure all BACnet devices to synchronize time using the BACnet TimeSynchronization service or authenticated NTP. Use dedicated NTP servers for the OT network. Enable NTP authentication to prevent time spoofing. Verify accurate time synchronization across all BACnet devices."
    },

    # ─── LOG: Logging & Monitoring (LOG-01 through LOG-04) ─────
    {
        "id": "LOG-01",
        "framework": "DESC",
        "category": "Logging and Monitoring",
        "title": "Security Event Logging",
        "description": "Security events including authentication attempts, configuration changes, and network events shall be logged with accurate timestamps and relevant metadata.",
        "mapping_to_iec": "IEC 62443-3-3 SR 4.3",
        "observability": "network",
        "evidence_rules": {
            "event_logging_detected": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Enable security logging on all BMS servers, BACnet management consoles, and network gateways. Log all authentication events, configuration changes to BACnet objects, BACnet WriteProperty operations, and device reboots. Forward logs to a centralized SIEM with accurate timestamps."
    },
    {
        "id": "LOG-02",
        "framework": "DESC",
        "category": "Logging and Monitoring",
        "title": "Log Retention and Protection",
        "description": "Security logs shall be retained for a minimum period of 12 months with integrity protection to prevent tampering or deletion.",
        "mapping_to_iec": "IEC 62443-3-3 SR 4.3",
        "observability": "config",
        "evidence_rules": {
            "log_retention_policy": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Implement log retention policies for BMS security events (minimum 12 months for OT audit logs). Use immutable or append-only log storage for BACnet event logs. Implement log integrity verification (checksums or digital signatures). Secure log storage with access controls."
    },
    {
        "id": "LOG-03",
        "framework": "DESC",
        "category": "Logging and Monitoring",
        "title": "Continuous Security Monitoring",
        "description": "OT network traffic and system events shall be monitored continuously with real-time alerting for security-relevant events and anomalies.",
        "mapping_to_iec": "IEC 62443-3-3 SR 6.1",
        "observability": "network",
        "evidence_rules": {
            "continuous_monitoring_active": {"weight": 3, "operator": "eq", "threshold": True},
            "bacnet_cov_subscriptions": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Deploy 24/7 passive BACnet traffic monitoring on all BMS segments. Subscribe to BACnet Change-of-Value (COV) notifications for critical objects. Monitor BACnet device status and communication health. Set up real-time alerts for device failures, configuration changes, and network anomalies."
    },
    {
        "id": "LOG-04",
        "framework": "DESC",
        "category": "Logging and Monitoring",
        "title": "Anomaly Detection and Alerting",
        "description": "Anomaly detection mechanisms shall be deployed to identify deviations from normal OT network behavior with automated alerting and escalation.",
        "mapping_to_iec": "IEC 62443-3-3 SR 3.2",
        "observability": "network",
        "evidence_rules": {
            "anomaly_detection_active": {"weight": 3, "operator": "eq", "threshold": True},
            "bacnet_traffic_baseline": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Deploy anomaly detection tools that learn normal BACnet traffic patterns (source IPs, services used, message rates, object types accessed). Configure alerts for deviations from baselines. Implement automated alert routing to SOC or OT security team with severity-based escalation."
    },

    # ─── VLM: Vulnerability Management (VLM-01 through VLM-04) ──
    {
        "id": "VLM-01",
        "framework": "DESC",
        "category": "Vulnerability Management",
        "title": "Vulnerability Scanning and Assessment",
        "description": "Regular vulnerability scanning and assessment shall be conducted on OT assets using OT-safe scanning tools and techniques.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.10",
        "observability": "network",
        "evidence_rules": {
            "vulnerability_scans_available": {"weight": 3, "operator": "eq", "threshold": True},
            "known_vulnerable_protocols": {"weight": 2, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Conduct passive vulnerability assessments using BACnet traffic analysis to identify known-vulnerable device models and firmware versions. Perform OT-safe active scanning during maintenance windows. Correlate detected device types with CVE databases. Map BACnet protocol version usage against known vulnerabilities."
    },
    {
        "id": "VLM-02",
        "framework": "DESC",
        "category": "Vulnerability Management",
        "title": "Patch Management",
        "description": "A documented patch management process shall be implemented for OT assets with testing, approval, and scheduled deployment in maintenance windows.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.12",
        "observability": "config",
        "evidence_rules": {
            "firmware_versions_found": {"weight": 3, "operator": "gte", "threshold": 1},
            "outdated_firmware_devices": {"weight": 2, "operator": "eq", "threshold": False}
        },
        "default_status": "FAIL",
        "remediation": "Establish a patch management process for BACnet controllers and BMS servers. Test patches in a staging environment before OT deployment. Schedule patching during approved maintenance windows. Track firmware versions and apply vendor security patches within 30 days of release for critical vulnerabilities."
    },
    {
        "id": "VLM-03",
        "framework": "DESC",
        "category": "Vulnerability Management",
        "title": "Risk Assessment Methodology",
        "description": "A formal risk assessment methodology shall be applied to all OT assets, evaluating threats, vulnerabilities, and business impact.",
        "mapping_to_iec": "IEC 62443-3-3 SR 5.4",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Implement a formal OT risk assessment methodology aligned with ISA/IEC 62443-3-2. Conduct annual risk assessments for all BMS systems. Document threat scenarios, likelihood, and business impact. Maintain a risk register with remediation timelines."
    },
    {
        "id": "VLM-04",
        "framework": "DESC",
        "category": "Vulnerability Management",
        "title": "Remediation Tracking",
        "description": "Vulnerability remediation activities shall be tracked with assigned owners, target dates, and verification of fix effectiveness.",
        "mapping_to_iec": "IEC 62443-3-3 SR 3.3",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Implement a remediation tracking system for OT vulnerabilities. Assign severity-based SLAs for remediation (Critical: 7 days, High: 30 days, Medium: 90 days). Verify remediation effectiveness through follow-up scanning. Report remediation status to management monthly."
    },

    # ─── IR: Incident Response (IR-01 through IR-04) ────────────
    {
        "id": "IR-01",
        "framework": "DESC",
        "category": "Incident Response",
        "title": "Incident Response Planning",
        "description": "An OT-specific incident response plan shall be documented, reviewed, and tested, covering cyber security incidents affecting BMS operations.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.10",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Develop and maintain an OT incident response plan specific to BMS systems. Include BACnet-specific scenarios (controller compromise, communication loss, data manipulation). Define roles, communication channels, and escalation procedures. Test the plan through tabletop exercises quarterly."
    },
    {
        "id": "IR-02",
        "framework": "DESC",
        "category": "Incident Response",
        "title": "Incident Detection and Analysis",
        "description": "Incident detection capabilities shall be deployed to identify OT security incidents with forensic analysis procedures for BACnet environments.",
        "mapping_to_iec": "IEC 62443-3-3 SR 3.2",
        "observability": "network",
        "evidence_rules": {
            "incident_detection_capable": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Deploy BACnet-aware intrusion detection sensors (Passive BACnet IDS). Implement rules to detect BACnet-specific attacks (Who-Is/Router-Request floods, WriteProperty to critical objects, device impersonation). Maintain forensic capture capabilities for BACnet traffic replay and analysis."
    },
    {
        "id": "IR-03",
        "framework": "DESC",
        "category": "Incident Response",
        "title": "Incident Reporting and Escalation",
        "description": "Security incidents shall be reported through defined channels with escalation procedures based on severity and potential impact to building operations.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.11",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Establish incident reporting procedures for BMS security events with defined severity levels. Define escalation paths based on operational impact (building evacuation risk, life safety systems affected, data center cooling disruption). Report to DESC for Tier 1 OT incidents within 1 hour."
    },
    {
        "id": "IR-04",
        "framework": "DESC",
        "category": "Incident Response",
        "title": "Lessons Learned and Improvement",
        "description": "Post-incident reviews shall be conducted to identify lessons learned and implement improvements to prevent recurrence.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.11",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Conduct post-incident reviews within 30 days of any OT security incident. Document root cause analysis, lessons learned, and corrective actions. Track improvement items in a remediation plan. Update incident response procedures based on lessons learned."
    },

    # ─── BCM: Business Continuity (BCM-01 through BCM-04) ──────
    {
        "id": "BCM-01",
        "framework": "DESC",
        "category": "Business Continuity",
        "title": "Backup and Recovery Procedures",
        "description": "Backup and recovery procedures shall be documented and tested for all OT systems including BACnet controller configurations and BMS databases.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.4",
        "observability": "config",
        "evidence_rules": {
            "backup_policy_detected": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Implement automated backup procedures for BACnet controller configurations, BMS server databases, and network device configurations. Store backups off-site with encryption. Test restoration procedures quarterly. Verify backup integrity through automated checks."
    },
    {
        "id": "BCM-02",
        "framework": "DESC",
        "category": "Business Continuity",
        "title": "Business Impact Analysis",
        "description": "A business impact analysis shall be conducted for OT systems and BMS functions to identify critical building services and recovery priorities.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.8",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Conduct a BIA for all BMS functions. Identify maximum tolerable downtime for each building system (HVAC, lighting, fire safety, access control). Define recovery time objectives (RTO) and recovery point objectives (RPO) for each system. Update BIA annually."
    },
    {
        "id": "BCM-03",
        "framework": "DESC",
        "category": "Business Continuity",
        "title": "Disaster Recovery Testing",
        "description": "Disaster recovery procedures for OT systems shall be tested periodically to verify effectiveness and identify improvement areas.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.4",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Conduct disaster recovery testing for BMS systems at least annually. Test BACnet controller failover, BMS server restoration, and network recovery. Document test results and remediation actions. Include OT-specific scenarios like BACnet network partition or controller firmware corruption."
    },
    {
        "id": "BCM-04",
        "framework": "DESC",
        "category": "Business Continuity",
        "title": "Redundancy and Failover",
        "description": "Critical OT systems and network paths shall have redundancy and automatic failover mechanisms to ensure continued building operations during failures.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.2",
        "observability": "network",
        "evidence_rules": {
            "redundant_paths_detected": {"weight": 3, "operator": "eq", "threshold": True},
            "bacnet_redundant_controllers": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Implement redundant BACnet controllers for critical building systems (life safety, data center cooling). Deploy redundant BMS servers with automatic failover. Use redundant network paths with STP or MRP for OT networks. Test failover procedures quarterly."
    },

    # ─── PHS: Physical Security (PHS-01 through PHS-03) ─────────
    {
        "id": "PHS-01",
        "framework": "DESC",
        "category": "Physical Security",
        "title": "Physical Access Control",
        "description": "Physical access to OT equipment rooms, data centers, and BACnet controller locations shall be controlled with electronic access, monitoring, and logging.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.8",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Implement electronic access control to all rooms housing BMS equipment. Use multi-factor physical access (badge + PIN) for sensitive OT areas. Maintain access logs with 12-month retention. Install CCTV monitoring in OT equipment rooms. Conduct quarterly physical access audits."
    },
    {
        "id": "PHS-02",
        "framework": "DESC",
        "category": "Physical Security",
        "title": "Environmental Controls Monitoring",
        "description": "Environmental conditions in OT equipment areas shall be monitored including temperature, humidity, and water detection.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.8",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Deploy environmental monitoring sensors in OT equipment rooms. Monitor temperature (18-27°C), humidity (20-80%), and water detection. Configure alerts for environmental threshold violations. Integrate environmental monitoring with BMS alarm system."
    },
    {
        "id": "PHS-03",
        "framework": "DESC",
        "category": "Physical Security",
        "title": "Asset Tracking and Inventory",
        "description": "Physical OT assets shall be tracked with location information, serial numbers, and assigned custodians.",
        "mapping_to_iec": "IEC 62443-3-3 SR 7.8",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Maintain a physical asset inventory with location tracking for all BMS hardware. Use asset tags with barcode/RFID for portable equipment. Conduct physical inventory audits semi-annually. Track asset movement and changes in custody."
    },

    # ─── SCS: Supply Chain Security (SCS-01 through SCS-03) ────
    {
        "id": "SCS-01",
        "framework": "DESC",
        "category": "Supply Chain Security",
        "title": "Vendor Risk Management",
        "description": "Vendor risk assessments shall be conducted for all OT product and service providers covering security practices, incident history, and compliance.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.11",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Conduct security assessments for all BMS vendors and integrators. Evaluate vendor security practices, product vulnerability history, and patch responsiveness. Require vendors to comply with IEC 62443-4-1 (Secure Product Development). Maintain a vendor risk register with assessment scores."
    },
    {
        "id": "SCS-02",
        "framework": "DESC",
        "category": "Supply Chain Security",
        "title": "Software Bill of Materials",
        "description": "A software bill of materials (SBOM) shall be maintained for all OT software components including third-party libraries, firmware, and operating systems.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.11",
        "observability": "config",
        "evidence_rules": {
            "vendor_uniformity_found": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Request and maintain SBOMs from all BMS equipment vendors for firmware and software components. Use open-source vulnerability scanners to cross-reference SBOM entries against known vulnerabilities. Maintain an inventory of all software components with version numbers. Review SBOMs during procurement."
    },
    {
        "id": "SCS-03",
        "framework": "DESC",
        "category": "Supply Chain Security",
        "title": "Secure Procurement",
        "description": "Procurement processes for OT equipment and services shall include security requirements covering encryption, secure configuration, and vendor support commitments.",
        "mapping_to_iec": "IEC 62443-3-3 SR 2.11",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Include security requirements in all BMS equipment procurement RFPs. Require FIPS 140-2 validated encryption for BACnet/SC devices. Specify minimum patch support duration (5+ years) for BACnet controller purchases. Require vendors to provide vulnerability disclosure policies."
    },
]


# ═══════════════════════════════════════════════════════════════════
# IEC 62443-3-3 FRAMEWORK - Security Requirements for IACS
# ═══════════════════════════════════════════════════════════════════

IEC62443_FRAMEWORK: list[dict] = [

    # ═════════════════════════════════════════════════════════════
    # SR 1.x - Identification and Authentication (I&A)
    # ═════════════════════════════════════════════════════════════
    {
        "id": "SR 1.1",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Human user identification and authentication",
        "description": "The IACS shall provide the capability to identify and authenticate all human users (including network access, interactive applications, and system-level access) before they are granted any access to the system.",
        "mapping_to_desc": "IAM-01, IAM-03",
        "observability": "network",
        "evidence_rules": {
            "unique_users_found": {"weight": 3, "operator": "gte", "threshold": 2},
            "default_credentials_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "FAIL",
        "remediation": "Implement unique user identification for all BMS workstation and server access. Eliminate shared and generic accounts. Change all default credentials on BACnet controllers and management interfaces."
    },
    {
        "id": "SR 1.2",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Software process and device identification",
        "description": "The IACS shall provide the capability to identify and authenticate software processes and devices, including BACnet controllers and field devices, before any communication is established.",
        "mapping_to_desc": "SCP-02",
        "observability": "network",
        "evidence_rules": {
            "bacnet_devices_found": {"weight": 3, "operator": "gte", "threshold": 1},
            "device_authentication_verified": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Enable device authentication on BACnet/SC connections. Implement certificate-based device identity verification for all BACnet controllers and gateways."
    },
    {
        "id": "SR 1.3",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Account management",
        "description": "The IACS shall provide the capability to manage user accounts including creation, modification, review, and removal, with appropriate authorization for account management actions.",
        "mapping_to_desc": "IAM-01, IAM-05",
        "observability": "config",
        "evidence_rules": {
            "auth_mechanisms_count": {"weight": 3, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Implement centralized account management for all BMS systems. Define account lifecycle procedures (creation, modification, disablement, deletion). Review active accounts quarterly."
    },
    {
        "id": "SR 1.4",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Identifier management",
        "description": "The IACS shall provide the capability to manage unique identifiers for users, processes, and devices throughout their lifecycle including generation, assignment, and revocation.",
        "mapping_to_desc": "IAM-01",
        "observability": "config",
        "evidence_rules": {
            "unique_users_found": {"weight": 3, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Assign unique identifiers to all users, processes, and BACnet devices. Implement identifier revocation procedures when users leave or devices are decommissioned."
    },
    {
        "id": "SR 1.5",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Authenticator management",
        "description": "The IACS shall provide the capability to manage authentication credentials including initial assignment, secure distribution, change on first use, and revocation.",
        "mapping_to_desc": "IAM-03",
        "observability": "network",
        "evidence_rules": {
            "default_credentials_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "FAIL",
        "remediation": "Implement authenticator management procedures. Enforce password change on first login. Disable default accounts on all BACnet controllers and BMS servers."
    },
    {
        "id": "SR 1.6",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Wireless access management",
        "description": "The IACS shall provide the capability to identify and authenticate all users and devices accessing the system through wireless interfaces.",
        "mapping_to_desc": "IAM-04, NWS-03",
        "observability": "network",
        "evidence_rules": {
            "wireless_ssids_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Implement WPA2-Enterprise or WPA3 for all wireless BMS connections. Use certificate-based authentication for wireless device access. Deploy wireless intrusion detection."
    },
    {
        "id": "SR 1.7",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Strength of password-based authentication",
        "description": "The IACS shall enforce configurable password strength rules including minimum length, complexity, and lifecycle expiration for all password-based authentication.",
        "mapping_to_desc": "IAM-05",
        "observability": "config",
        "evidence_rules": {
            "password_policy_detected": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Enforce password policies: minimum 12 characters, uppercase, lowercase, numeric, and special character requirements. Set password expiration to 90 days. Prevent password reuse (last 5 passwords)."
    },
    {
        "id": "SR 1.8",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Public key infrastructure certificates",
        "description": "The IACS shall provide the capability to issue, manage, and validate public key certificates for device and user authentication.",
        "mapping_to_desc": "SCP-01",
        "observability": "config",
        "evidence_rules": {
            "certificate_management_detected": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Deploy a PKI infrastructure for BACnet/SC certificate management. Issue device certificates to each BACnet controller. Implement certificate revocation and renewal procedures."
    },
    {
        "id": "SR 1.9",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Strength of public key authentication",
        "description": "The IACS shall use strong cryptographic algorithms for public key authentication including minimum key lengths and approved algorithms.",
        "mapping_to_desc": "SCP-01",
        "observability": "config",
        "evidence_rules": {
            "encryption_strength_verified": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Use RSA 2048-bit or ECC P-256 minimum key lengths for BACnet/SC certificates. Prohibit SHA-1 and MD5 signature algorithms. Use TLS 1.3 with AEAD cipher suites."
    },
    {
        "id": "SR 1.10",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Authenticator feedback",
        "description": "The IACS shall obscure authentication feedback during the authentication process to prevent information disclosure.",
        "mapping_to_desc": "IAM-05",
        "observability": "config",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Verify that BMS management interfaces mask password entry (e.g., asterisks). Ensure no verbose authentication error messages disclose valid usernames."
    },
    {
        "id": "SR 1.11",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Unsuccessful login attempts",
        "description": "The IACS shall limit the number of unsuccessful login attempts and enforce account lockout or progressive delay after exceeded limits.",
        "mapping_to_desc": "IAM-06",
        "observability": "config",
        "evidence_rules": {
            "session_timeouts_enabled": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Configure account lockout after 5 failed login attempts on BMS servers and BACnet management consoles. Implement progressive delay (30s, 60s, 120s). Set lockout duration to 30 minutes or until administrator reset."
    },
    {
        "id": "SR 1.12",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "System use notification",
        "description": "The IACS shall provide system use notification messages before user identification to inform users about authorized use, monitoring, and legal implications.",
        "mapping_to_desc": "",
        "observability": "config",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Display system use notification banners on BMS workstation login screens. Include warning about authorized use only, monitoring, and legal consequences of unauthorized access."
    },
    {
        "id": "SR 1.13",
        "framework": "IEC 62443",
        "category": "Identification and Authentication",
        "title": "Access via untrusted networks",
        "description": "The IACS shall enforce stronger authentication mechanisms (e.g., multi-factor authentication) for any access initiated from untrusted networks.",
        "mapping_to_desc": "IAM-04",
        "observability": "network",
        "evidence_rules": {
            "remote_access_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "vpn_gateway_present": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Implement MFA for all remote access to the BMS network. Use VPN gateways with strong authentication. Enforce time-limited access approvals for remote connections."
    },

    # ═════════════════════════════════════════════════════════════
    # SR 2.x - Use Control
    # ═════════════════════════════════════════════════════════════
    {
        "id": "SR 2.1",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Authorization enforcement",
        "description": "The IACS shall enforce authorizations for all users, processes, and devices based on the principle of least privilege.",
        "mapping_to_desc": "IAM-02",
        "observability": "config",
        "evidence_rules": {
            "user_role_counts": {"weight": 3, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Implement RBAC for BACnet management systems. Define roles (operator, engineer, administrator) with granular permissions. Restrict BACnet WriteProperty access to authorized roles only."
    },
    {
        "id": "SR 2.2",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Wireless use control",
        "description": "The IACS shall enforce authorization controls for all wireless communication to the system, including device authentication and encryption.",
        "mapping_to_desc": "NWS-03",
        "observability": "network",
        "evidence_rules": {
            "wireless_ssids_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Implement 802.1X port-based authentication for wireless BMS device access. Use separate VLANs for wireless OT devices with ACLs restricting access to authorized systems only."
    },
    {
        "id": "SR 2.3",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Use control for portable and mobile devices",
        "description": "The IACS shall enforce use control for portable and mobile devices that connect to the system, including configuration management and malware protection.",
        "mapping_to_desc": "PHS-03",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Implement device management policies for laptops and tablets connecting to BMS networks. Enforce endpoint security controls including disk encryption, antivirus, and patch management."
    },
    {
        "id": "SR 2.4",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Mobile code",
        "description": "The IACS shall enforce authorization controls for mobile code (scripts, macros, applets) execution on control system components.",
        "mapping_to_desc": "",
        "observability": "config",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Disable macro execution in BMS software applications. Restrict script execution on BMS servers. Implement application whitelisting on BMS workstations."
    },
    {
        "id": "SR 2.5",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Session lock",
        "description": "The IACS shall provide the capability to lock user sessions after a configurable period of inactivity.",
        "mapping_to_desc": "IAM-06",
        "observability": "config",
        "evidence_rules": {
            "session_timeouts_enabled": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Configure automatic session lock on BMS workstations after 15 minutes of inactivity. Require password or biometric re-authentication to unlock sessions."
    },
    {
        "id": "SR 2.6",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Remote session termination",
        "description": "The IACS shall provide the capability to terminate remote sessions either automatically after a period of inactivity or upon administrator command.",
        "mapping_to_desc": "IAM-04, IAM-06",
        "observability": "config",
        "evidence_rules": {
            "session_timeouts_enabled": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Configure automatic termination of remote BMS sessions after 30 minutes of inactivity. Enable administrator-initiated session termination. Log remote session termination events."
    },
    {
        "id": "SR 2.7",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Concurrent session control",
        "description": "The IACS shall provide the capability to limit the number of concurrent sessions for each user account.",
        "mapping_to_desc": "IAM-06",
        "observability": "config",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Limit concurrent sessions to 1-2 per user on BMS management systems. Enforce session limits through application configuration or directory service policies."
    },
    {
        "id": "SR 2.8",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Auditable events",
        "description": "The IACS shall provide the capability to generate audit records for security-relevant events including authentication, authorization changes, and configuration modifications.",
        "mapping_to_desc": "LOG-01",
        "observability": "network",
        "evidence_rules": {
            "event_logging_detected": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Enable audit logging for all security-relevant events on BMS systems. Log authentication successes and failures, BACnet WriteProperty operations, and configuration changes."
    },
    {
        "id": "SR 2.9",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Audit storage and protection",
        "description": "The IACS shall protect audit records from unauthorized access, modification, and deletion, with sufficient storage capacity.",
        "mapping_to_desc": "LOG-02",
        "observability": "config",
        "evidence_rules": {
            "log_retention_policy": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Store audit logs in immutable storage with access controls. Implement log rotation with minimum 12-month retention. Use log integrity verification mechanisms (WORM storage or cryptographic signing)."
    },
    {
        "id": "SR 2.10",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Response to audit processing failures",
        "description": "The IACS shall provide the capability to alert appropriate personnel when audit processing failures occur (e.g., storage full, logging system failure).",
        "mapping_to_desc": "LOG-03, IR-01",
        "observability": "network",
        "evidence_rules": {
            "continuous_monitoring_active": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Configure alerts for audit log failures (storage capacity, logging service health, log forwarding failures). Define escalation procedures for audit system failures."
    },
    {
        "id": "SR 2.11",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Timestamp generation",
        "description": "The IACS shall provide the capability to generate accurate timestamps for audit records using a trusted time source.",
        "mapping_to_desc": "SCP-05",
        "observability": "network",
        "evidence_rules": {
            "time_sync_detected": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Configure all BMS systems and BACnet devices to synchronize time from a trusted NTP source. Enable NTP authentication. Verify timestamp accuracy across all auditing systems."
    },
    {
        "id": "SR 2.12",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Non-repudiation",
        "description": "The IACS shall provide the capability to protect audit records against repudiation of actions performed by users and processes.",
        "mapping_to_desc": "LOG-02, VLM-02",
        "observability": "config",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Implement signed audit records using digital signatures for critical BMS configuration changes. Maintain chain of custody for forensic evidence from BACnet systems."
    },
    {
        "id": "SR 2.13",
        "framework": "IEC 62443",
        "category": "Use Control",
        "title": "Use of physical diagnostic and test interfaces",
        "description": "The IACS shall enforce authorization controls for the use of physical diagnostic and test interfaces on control system components.",
        "mapping_to_desc": "PHS-01, NWS-05",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Restrict physical access to diagnostic ports on BACnet controllers and network equipment. Disable unused serial/console ports. Implement physical access controls to OT equipment rooms."
    },

    # ═════════════════════════════════════════════════════════════
    # SR 3.x - System Integrity
    # ═════════════════════════════════════════════════════════════
    {
        "id": "SR 3.1",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Communication integrity",
        "description": "The IACS shall provide the capability to protect the integrity of information in transit across communication channels.",
        "mapping_to_desc": "SCP-02",
        "observability": "network",
        "evidence_rules": {
            "bacnet_plaintext_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "bacnet_protocol_anomalies": {"weight": 2, "operator": "eq", "threshold": False}
        },
        "default_status": "FAIL",
        "remediation": "Implement BACnet/SC with TLS 1.3 for integrity-protected BACnet communications. Use message integrity checks for BACnet/IP deployments where possible."
    },
    {
        "id": "SR 3.2",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Malware protection",
        "description": "The IACS shall provide malware detection and prevention capabilities on control system components where technically feasible.",
        "mapping_to_desc": "LOG-04, IR-02",
        "observability": "network",
        "evidence_rules": {
            "anomaly_detection_active": {"weight": 3, "operator": "eq", "threshold": True},
            "incident_detection_capable": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Deploy endpoint protection on BMS workstations and servers. Use application whitelisting for BACnet management tools. Implement network-based anomaly detection for BACnet traffic patterns."
    },
    {
        "id": "SR 3.3",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Security functionality verification",
        "description": "The IACS shall provide the capability to verify that security functions (authentication, authorization, audit, encryption) are operating correctly.",
        "mapping_to_desc": "AST-03, VLM-04",
        "observability": "config",
        "evidence_rules": {
            "firmware_versions_found": {"weight": 3, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Implement automated health checks for security functions on BMS systems. Verify authentication, authorization, audit logging, and encryption mechanisms are operational. Generate alerts for security function failures."
    },
    {
        "id": "SR 3.4",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Software and information integrity",
        "description": "The IACS shall provide the capability to detect unauthorized changes to software and configuration information on control system components.",
        "mapping_to_desc": "AST-05",
        "observability": "network",
        "evidence_rules": {
            "bacnet_vendor_uniformity": {"weight": 3, "operator": "gte", "threshold": 90}
        },
        "default_status": "FAIL",
        "remediation": "Implement file integrity monitoring on BMS servers and workstations. Use configuration baselines to detect changes to BACnet device settings. Alert on unauthorized configuration changes."
    },

    {
        "id": "SR 3.5",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Input validation",
        "description": "The IACS shall validate inputs to prevent malformed, unauthorized, or unsafe data from affecting control system operation.",
        "mapping_to_desc": "SCP-02, LOG-03",
        "observability": "network",
        "evidence_rules": {
            "bacnet_protocol_anomalies": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Validate BACnet object writes and command sources at supervisors/gateways. Restrict WriteProperty to authorized systems and alert on malformed BACnet traffic or unsafe setpoint values."
    },
    {
        "id": "SR 3.6",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Deterministic output",
        "description": "The IACS shall provide deterministic outputs when processing inputs or transitioning states, where required for safe control operation.",
        "mapping_to_desc": "BCM-03, SCS-04",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Document safe-state behavior for BMS controllers and supervisors. Test controller behavior for invalid values, communication loss, restart, and failover conditions."
    },
    {
        "id": "SR 3.7",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Error handling",
        "description": "The IACS shall identify and handle error conditions in a manner that does not disclose sensitive information or put the process into an unsafe state.",
        "mapping_to_desc": "LOG-02, IR-02, BCM-03",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Verify BMS error handling during controller faults, network outages, invalid commands, and supervisor failures. Ensure logs are useful without exposing credentials or sensitive configuration."
    },
    {
        "id": "SR 3.8",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Session integrity",
        "description": "The IACS shall protect the integrity of communication sessions, including protection against session hijacking, replay, and unauthorized session reuse.",
        "mapping_to_desc": "SCP-01, SCP-02, IAM-06",
        "observability": "network",
        "evidence_rules": {
            "bacnet_plaintext_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "encryption_mechanisms_count": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Prefer BACnet/SC with TLS session protection. For legacy BACnet/IP, isolate traffic in OT VLANs/VPNs and restrict sessions to approved engineering workstations and BMS servers."
    },
    {
        "id": "SR 3.9",
        "framework": "IEC 62443",
        "category": "System Integrity",
        "title": "Protection of audit information",
        "description": "The IACS shall protect audit records and audit tools from unauthorized access, modification, and deletion.",
        "mapping_to_desc": "LOG-01, LOG-04",
        "observability": "config",
        "evidence_rules": {
            "central_logging_configured": {"weight": 3, "operator": "eq", "threshold": True},
            "log_retention_days": {"weight": 2, "operator": "gte", "threshold": 90}
        },
        "default_status": "FAIL",
        "remediation": "Forward BMS and gateway logs to a protected log server/SIEM. Restrict log deletion privileges, retain logs for an approved period, and alert on log tampering or collection failure."
    },


    # ═════════════════════════════════════════════════════════════
    # SR 4.x - Data Confidentiality
    # ═════════════════════════════════════════════════════════════
    {
        "id": "SR 4.1",
        "framework": "IEC 62443",
        "category": "Data Confidentiality",
        "title": "Information confidentiality",
        "description": "The IACS shall provide the capability to protect the confidentiality of information in transit and at rest, including BACnet communication payloads.",
        "mapping_to_desc": "SCP-01, NWS-04",
        "observability": "network",
        "evidence_rules": {
            "bacnet_plaintext_detected": {"weight": 3, "operator": "eq", "threshold": False},
            "encryption_mechanisms_count": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Encrypt all BACnet traffic using BACnet/SC (TLS 1.3) or VPN tunnels. Protect BACnet configuration files and databases with encryption at rest."
    },
    {
        "id": "SR 4.2",
        "framework": "IEC 62443",
        "category": "Data Confidentiality",
        "title": "Information persistence",
        "description": "The IACS shall provide the capability to securely erase or overwrite information from persistent storage before decommissioning or repurposing control system components.",
        "mapping_to_desc": "AST-04",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Define secure disposal procedures for decommissioned BACnet controllers and BMS servers. Use cryptographic wiping or physical destruction for storage media."
    },
    {
        "id": "SR 4.3",
        "framework": "IEC 62443",
        "category": "Data Confidentiality",
        "title": "Use of cryptography",
        "description": "The IACS shall provide the capability to use cryptographic mechanisms according to approved standards for confidentiality and integrity protection.",
        "mapping_to_desc": "SCP-01, LOG-01, LOG-02",
        "observability": "network",
        "evidence_rules": {
            "encryption_mechanisms_count": {"weight": 3, "operator": "gte", "threshold": 1},
            "bacnet_plaintext_detected": {"weight": 2, "operator": "eq", "threshold": False}
        },
        "default_status": "FAIL",
        "remediation": "Implement FIPS 140-2 validated cryptography for all BMS communications. Use AES-256 for data encryption and SHA-256 for integrity checking. Transition to BACnet/SC with TLS 1.3."
    },

    # ═════════════════════════════════════════════════════════════
    # SR 5.x - Restricted Data Flow
    # ═════════════════════════════════════════════════════════════
    {
        "id": "SR 5.1",
        "framework": "IEC 62443",
        "category": "Restricted Data Flow",
        "title": "Network segmentation",
        "description": "The IACS shall provide the capability to segment control system networks into zones based on criticality, with firewalls enforcing restricted data flows between zones.",
        "mapping_to_desc": "NWS-01",
        "observability": "network",
        "evidence_rules": {
            "bacnet_it_ot_cross_traffic": {"weight": 3, "operator": "eq", "threshold": False},
            "bacnet_broadcast_domains": {"weight": 2, "operator": "lte", "threshold": 2},
            "zones_detected": {"weight": 1, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Segment the BACnet BMS network onto dedicated VLANs. Implement firewalls between OT zones with whitelist rules. Prevent BACnet traffic from crossing into IT network segments."
    },
    {
        "id": "SR 5.2",
        "framework": "IEC 62443",
        "category": "Restricted Data Flow",
        "title": "Zone boundary protection",
        "description": "The IACS shall enforce restricted data flows through zone boundary protection mechanisms (firewalls, routers with ACLs, one-way gateways).",
        "mapping_to_desc": "NWS-02",
        "observability": "network",
        "evidence_rules": {
            "acls_detected": {"weight": 3, "operator": "eq", "threshold": True},
            "bacnet_port_restricted": {"weight": 2, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Deploy firewalls at all OT zone boundaries. Configure ACLs permitting only required BACnet services. Implement default-deny policies for cross-zone traffic."
    },
    {
        "id": "SR 5.3",
        "framework": "IEC 62443",
        "category": "Restricted Data Flow",
        "title": "General purpose person-to-person communication restrictions",
        "description": "The IACS shall restrict general purpose person-to-person communication services (email, web browsing, instant messaging) across zone boundaries.",
        "mapping_to_desc": "NWS-08, SCP-03",
        "observability": "network",
        "evidence_rules": {
            "unexpected_ports_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Block general-purpose internet services (HTTP/HTTPS to external, SMTP, IMAP) from OT zones. Restrict OT workstation internet access to authorized update sites only."
    },
    {
        "id": "SR 5.4",
        "framework": "IEC 62443",
        "category": "Restricted Data Flow",
        "title": "Application partitioning",
        "description": "The IACS shall provide the capability to partition control system applications and data into different zones or security levels based on criticality.",
        "mapping_to_desc": "VLM-03, NWS-01",
        "observability": "network",
        "evidence_rules": {
            "zones_detected": {"weight": 3, "operator": "gte", "threshold": 2}
        },
        "default_status": "FAIL",
        "remediation": "Implement zone-based partitioning for BMS applications (HVAC zone, life safety zone, access control zone). Separate critical building systems into different security levels with controlled data flows."
    },

    # ═════════════════════════════════════════════════════════════
    # SR 6.x - Timely Response to Events
    # ═════════════════════════════════════════════════════════════
    {
        "id": "SR 6.1",
        "framework": "IEC 62443",
        "category": "Timely Response to Events",
        "title": "Audit log accessibility",
        "description": "The IACS shall provide the capability to make audit logs available to authorized personnel in a timely manner for incident investigation.",
        "mapping_to_desc": "LOG-03, NWS-06",
        "observability": "network",
        "evidence_rules": {
            "continuous_monitoring_active": {"weight": 3, "operator": "eq", "threshold": True},
            "bacnet_cov_subscriptions": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Implement centralized log aggregation with real-time search capabilities for BMS audit logs. Ensure BACnet event data is accessible within 5 minutes of generation."
    },
    {
        "id": "SR 6.2",
        "framework": "IEC 62443",
        "category": "Timely Response to Events",
        "title": "Continuous monitoring",
        "description": "The IACS shall provide the capability to continuously monitor the security state of the system including device health, network traffic, and security events.",
        "mapping_to_desc": "LOG-03",
        "observability": "network",
        "evidence_rules": {
            "continuous_monitoring_active": {"weight": 3, "operator": "eq", "threshold": True},
            "bacnet_cov_subscriptions": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Deploy continuous monitoring of BACnet device health, COV notifications, and network traffic. Configure real-time alerts for device failures, security events, and anomalous behavior."
    },

    # ═════════════════════════════════════════════════════════════
    # SR 7.x - Resource Availability
    # ═════════════════════════════════════════════════════════════
    {
        "id": "SR 7.1",
        "framework": "IEC 62443",
        "category": "Resource Availability",
        "title": "Denial of service protection",
        "description": "The IACS shall provide the capability to protect against denial of service attacks by limiting the impact on control system functions.",
        "mapping_to_desc": "",
        "observability": "network",
        "evidence_rules": {
            "traffic_monitoring_active": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Implement rate limiting on BACnet broadcast messages (Who-Is, I-Am, Router-Request). Configure firewalls to prevent BACnet traffic floods. Deploy anomaly detection for DoS patterns."
    },
    {
        "id": "SR 7.2",
        "framework": "IEC 62443",
        "category": "Resource Availability",
        "title": "Resource management",
        "description": "The IACS shall provide the capability to manage control system resources to ensure availability under normal and abnormal conditions.",
        "mapping_to_desc": "BCM-04",
        "observability": "network",
        "evidence_rules": {
            "redundant_paths_detected": {"weight": 3, "operator": "eq", "threshold": True},
            "bacnet_redundant_controllers": {"weight": 2, "operator": "gte", "threshold": 1}
        },
        "default_status": "FAIL",
        "remediation": "Implement resource management policies for critical BACnet controllers. Monitor CPU, memory, and network utilization. Deploy redundant systems for life safety and critical building functions."
    },
    {
        "id": "SR 7.3",
        "framework": "IEC 62443",
        "category": "Resource Availability",
        "title": "Control system backup",
        "description": "The IACS shall provide the capability to create and restore backups of control system configurations, application software, and data.",
        "mapping_to_desc": "SCP-05",
        "observability": "config",
        "evidence_rules": {
            "backup_policy_detected": {"weight": 3, "operator": "eq", "threshold": True}
        },
        "default_status": "FAIL",
        "remediation": "Implement automated backup procedures for BACnet controller configurations and BMS databases. Test backup restoration quarterly. Store backups in secure, off-site locations."
    },
    {
        "id": "SR 7.4",
        "framework": "IEC 62443",
        "category": "Resource Availability",
        "title": "Control system recovery and reconstitution",
        "description": "The IACS shall provide the capability to recover and reconstitute control system functionality after disruption using documented procedures.",
        "mapping_to_desc": "BCM-01, BCM-03",
        "observability": "policy",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Document recovery procedures for BACnet controllers, BMS servers, and network infrastructure. Conduct recovery drills quarterly. Verify reconstitution of security controls after recovery."
    },
    {
        "id": "SR 7.5",
        "framework": "IEC 62443",
        "category": "Resource Availability",
        "title": "Emergency power",
        "description": "The IACS shall provide the capability to maintain control system operations during power disruptions through uninterruptible power supplies and emergency generators.",
        "mapping_to_desc": "",
        "observability": "manual",
        "evidence_rules": {},
        "default_status": "NOT_OBSERVABLE",
        "remediation": "Deploy UPS for all BACnet controllers, BMS servers, and network equipment. Ensure UPS runtime of at least 30 minutes for orderly shutdown. Test emergency power systems quarterly."
    },
    {
        "id": "SR 7.6",
        "framework": "IEC 62443",
        "category": "Resource Availability",
        "title": "Network and security configuration settings",
        "description": "The IACS shall provide the capability to manage network and security configuration settings for control system components centrally.",
        "mapping_to_desc": "AST-05, NWS-07, SCP-04",
        "observability": "config",
        "evidence_rules": {
            "bacnet_device_details": {"weight": 3, "operator": "pct", "threshold": 70},
            "secure_config_verified_pct": {"weight": 2, "operator": "pct", "threshold": 80}
        },
        "default_status": "FAIL",
        "remediation": "Implement centralized configuration management for all BMS devices. Use configuration baselines with drift detection. Enforce secure configuration settings through automation."
    },
    {
        "id": "SR 7.7",
        "framework": "IEC 62443",
        "category": "Resource Availability",
        "title": "Least functionality",
        "description": "The IACS shall provide the capability to disable unnecessary ports, protocols, and services on control system components.",
        "mapping_to_desc": "SCP-03",
        "observability": "network",
        "evidence_rules": {
            "unexpected_ports_detected": {"weight": 3, "operator": "eq", "threshold": False}
        },
        "default_status": "PARTIAL",
        "remediation": "Disable all unnecessary ports and services on BACnet controllers and BMS servers. Remove unused protocols (HTTP, Telnet, SNMP v1/v2c). Maintain a least-functionality baseline."
    },
    {
        "id": "SR 7.8",
        "framework": "IEC 62443",
        "category": "Resource Availability",
        "title": "System inventory",
        "description": "The IACS shall provide the capability to maintain an inventory of control system components, their hardware/software versions, and their network connections.",
        "mapping_to_desc": "AST-01, AST-02, AST-04, BCM-02, PHS-01, PHS-02, PHS-03",
        "observability": "network",
        "evidence_rules": {
            "bacnet_devices_found": {"weight": 3, "operator": "gte", "threshold": 1},
            "bacnet_device_details": {"weight": 2, "operator": "pct", "threshold": 80}
        },
        "default_status": "FAIL",
        "remediation": "Maintain a comprehensive inventory of all BMS assets. Track device IDs, firmware versions, IP addresses, physical locations, and criticality classifications. Update inventory automatically through passive BACnet monitoring."
    },
]


# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════


def get_control_by_id(control_id: str) -> dict | None:
    """Look up a control by its ID across both frameworks.

    Args:
        control_id: Control identifier (e.g., "AST-01", "SR 1.1")

    Returns:
        The control dict if found, None otherwise.
    """
    for ctrl in DESC_FRAMEWORK:
        if ctrl["id"] == control_id:
            return dict(ctrl)
    for ctrl in IEC62443_FRAMEWORK:
        if ctrl["id"] == control_id:
            return dict(ctrl)
    return None

# ═══════════════════════════════════════════════════════════════════
# CORE EVALUATION ENGINE
# ═══════════════════════════════════════════════════════════════════


def _evaluate_evidence_rules(rules: dict, evidence: dict) -> str:
    """Evaluate evidence rules against available evidence data.

    Rules are evaluated by computing a weighted score. If total weight
    of passing rules >= 60% of max weight, the control passes.
    Between 30-60% is partial, below 30% is fail.

    Args:
        rules: evidence_rules dict from the control definition
        evidence: dict of evidence key -> value (from scan data)

    Returns:
        "PASS", "PARTIAL", or "FAIL"
    """
    if not rules:
        return "NOT_OBSERVABLE"

    total_weight = 0
    pass_weight = 0

    for rule_key, rule_config in rules.items():
        w = rule_config.get("weight", 1)
        total_weight += w
        op = rule_config.get("operator", "gte")
        threshold = rule_config.get("threshold")
        actual = evidence.get(rule_key)

        if actual is None:
            continue

        passed = False
        if op == "gte":
            passed = actual >= threshold
        elif op == "lte":
            passed = actual <= threshold
        elif op == "eq":
            passed = actual == threshold
        elif op == "pct":
            passed = actual >= threshold
        elif op == "gt":
            passed = actual > threshold
        elif op == "lt":
            passed = actual < threshold

        if passed:
            pass_weight += w

    if total_weight == 0:
        return "NOT_OBSERVABLE"

    ratio = (pass_weight / total_weight) * 100.0
    if ratio >= 60:
        return "PASS"
    elif ratio >= 30:
        return "PARTIAL"
    else:
        return "FAIL"


def _build_evidence_from_assets(assets: list[dict], summary: dict) -> dict:
    """Extract evidence metrics from scan data for control evaluation.

    Builds a comprehensive evidence dictionary from the asset list
    and summary statistics that can be consumed by evidence_rules.

    Args:
        assets: List of discovered BACnet/OT device dicts
        summary: Dict with scan summary statistics

    Returns:
        Evidence dict with keys matching evidence_rules patterns
    """
    total = summary.get("total_assets", len(assets))

    # Count unique devices
    unique_ips = set()
    unique_ids = set()
    device_types_found = set()
    vendors_found = set()
    firmware_versions = set()
    has_default_creds = False
    has_plaintext = True  # Default: BACnet/IP is plaintext
    has_bacnet_secure = False
    has_wireless = False
    has_cov = False
    has_time_sync = False
    has_backup_policy = False
    has_monitoring = False
    has_anomaly_detection = False
    has_event_logging = False
    has_incident_detection = False
    has_acls = False
    has_port_restriction = False
    has_unexpected_ports = False
    has_cross_traffic = True  # Default: assume unsegmented
    has_redundant_paths = False
    has_vpn = False
    has_remote_access = False
    has_session_timeouts = False
    has_password_policy = False
    has_log_retention = False
    has_device_auth = False
    has_cert_mgmt = False
    has_encryption_strength = False
    has_network_hardening = False
    has_bacnet_baseline = False
    vendor_uniform = 0
    user_roles = 0
    unique_users = 0
    auth_mechs = 0
    encryption_count = 0
    bbmd_exposure = False
    zone_count = 1
    broadcast_domains = 1
    redundant_controllers = 0
    vuln_scans = False
    bacnet_protocol_anomalies = False
    outdated_firmware = True
    vulnerable_protocols = False
    bacnet_vendor_uniformity = 0
    secure_config_pct = 0

    for asset in assets:
        ip = asset.get("ip", "")
        if ip:
            unique_ips.add(ip)
        dev_id = asset.get("device_id", "") or asset.get("id", "")
        if dev_id:
            unique_ids.add(dev_id)
        dtype = asset.get("type", "") or asset.get("device_type", "")
        if dtype:
            device_types_found.add(dtype)
        vendor = asset.get("vendor", "") or asset.get("vendor_name", "")
        if vendor:
            vendors_found.add(vendor)
        fw = asset.get("firmware", "") or asset.get("fw_version", "")
        if fw:
            firmware_versions.add(fw)

        # Check for default credentials
        if asset.get("default_credentials", False) or asset.get("default_password", False):
            has_default_creds = True

        # Check for BACnet/SC support
        if asset.get("bacnet_sc", False) or asset.get("secure_connect", False):
            has_bacnet_secure = True
            has_plaintext = False

        # Wireless
        if asset.get("wireless", False) or asset.get("ssid", ""):
            has_wireless = True

        # COV
        if asset.get("cov_subscribed", False) or asset.get("cov_enabled", False):
            has_cov = True

        # Time sync
        if asset.get("time_sync", False) or asset.get("ntp_configured", False):
            has_time_sync = True

        # Monitoring
        if asset.get("monitored", False):
            has_monitoring = True

        # Vulnerability info
        vulns = asset.get("vulnerabilities", []) or asset.get("cvss", [])
        if vulns:
            vuln_scans = True

    # Summary-derived evidence
    # Network segmentation
    zone_count = summary.get("zones_detected", summary.get("zones", 1))
    broadcast_domains = summary.get("broadcast_domains", summary.get("subnets", 1))
    has_cross_traffic = summary.get("it_ot_cross_traffic", summary.get("cross_zone_traffic", True))
    if not isinstance(has_cross_traffic, bool):
        has_cross_traffic = True

    # BBMD exposure
    bbmd_exposure = summary.get("bbmd_exposure", summary.get("bbmd_exposed", False))

    # BACnet security
    has_plaintext = summary.get("bacnet_plaintext", summary.get("plaintext", True))
    if not isinstance(has_plaintext, bool):
        has_plaintext = True
    has_bacnet_secure = summary.get("bacnet_sc", summary.get("secure_connect", has_bacnet_secure))

    # Remote access
    has_remote_access = summary.get("remote_access_detected", summary.get("remote_access", False))
    has_vpn = summary.get("vpn_gateway", summary.get("vpn_detected", False))

    # Monitoring
    has_monitoring = summary.get("monitoring_active", summary.get("monitored", has_monitoring))
    has_anomaly_detection = summary.get("anomaly_detection", summary.get("anomaly_detection_active", False))
    has_event_logging = summary.get("event_logging", summary.get("logging_enabled", False))
    has_incident_detection = summary.get("incident_detection", summary.get("ids_detected", False))
    has_cov = summary.get("cov_subscriptions", summary.get("cov_active", has_cov))

    # Network controls
    has_acls = summary.get("acls_detected", summary.get("firewall_rules", False))
    has_port_restriction = summary.get("bacnet_port_restricted", summary.get("port_restriction", False))
    has_unexpected_ports = summary.get("unexpected_ports", False)
    has_redundant_paths = summary.get("redundant_paths", summary.get("redundancy", False))
    redundant_controllers = summary.get("bacnet_redundant_controllers", 0)

    # Config
    has_session_timeouts = summary.get("session_timeouts", False)
    has_password_policy = summary.get("password_policy", False)
    has_log_retention = summary.get("log_retention", False)
    has_device_auth = summary.get("device_authentication", False)
    has_cert_mgmt = summary.get("certificate_management", False)
    has_encryption_strength = summary.get("encryption_strength", False)
    has_network_hardening = summary.get("network_hardening", False)
    has_bacnet_baseline = summary.get("traffic_baseline", False)
    has_backup_policy = summary.get("backup_policy", False)

    # Stats
    vendor_uniform = len(vendors_found)
    unique_users = summary.get("unique_users", summary.get("user_count", 0))
    user_roles = summary.get("user_roles", summary.get("role_count", 1))
    auth_mechs = summary.get("auth_mechanisms", 1)
    encryption_count = summary.get("encryption_mechanisms", 0)
    bacnet_protocol_anomalies = summary.get("protocol_anomalies", False)
    outdated_firmware = summary.get("outdated_firmware", summary.get("outdated_devices", False))
    vulnerable_protocols = summary.get("vulnerable_protocols", False)
    bacnet_vendor_uniformity = summary.get("vendor_uniformity_pct", vendor_uniform * 25 if vendor_uniform > 0 else 0)
    secure_config_pct = summary.get("secure_config_pct", summary.get("secure_config", 50))

    # Build evidence dict
    evidence = {
        "bacnet_devices_found": len(unique_ips) if unique_ips else total,
        "bacnet_device_details": len(unique_ids),
        "bacnet_device_types_identified": len(device_types_found),
        "firmware_versions_found": len(firmware_versions),
        "bacnet_vendor_uniformity": bacnet_vendor_uniformity,
        "vendor_uniformity_found": len(vendors_found) > 0,
        "unique_users_found": unique_users,
        "default_credentials_detected": has_default_creds,
        "user_role_counts": user_roles,
        "auth_mechanisms_count": auth_mechs,
        "session_timeouts_enabled": has_session_timeouts,
        "remote_access_detected": has_remote_access,
        "vpn_gateway_present": has_vpn,
        "bacnet_it_ot_cross_traffic": has_cross_traffic,
        "bacnet_broadcast_domains": broadcast_domains,
        "zones_detected": zone_count,
        "acls_detected": has_acls,
        "bacnet_port_restricted": has_port_restriction,
        "bacnet_port_47808_detected": True,
        "bacnet_plaintext_detected": has_plaintext,
        "encrypted_protocols_detected": encryption_count,
        "encryption_mechanisms_count": encryption_count,
        "bacnet_secure_connect_detected": has_bacnet_secure,
        "bacnet_protocol_anomalies": bacnet_protocol_anomalies,
        "unexpected_ports_detected": has_unexpected_ports,
        "time_sync_detected": has_time_sync,
        "ntp_authentication_verified": has_time_sync,
        "event_logging_detected": has_event_logging,
        "log_retention_policy": has_log_retention,
        "continuous_monitoring_active": has_monitoring,
        "bacnet_cov_subscriptions": 1 if has_cov else 0,
        "anomaly_detection_active": has_anomaly_detection,
        "bacnet_traffic_baseline": has_bacnet_baseline,
        "vulnerability_scans_available": vuln_scans,
        "known_vulnerable_protocols": vulnerable_protocols,
        "outdated_firmware_devices": outdated_firmware,
        "incident_detection_capable": has_incident_detection,
        "backup_policy_detected": has_backup_policy,
        "redundant_paths_detected": has_redundant_paths,
        "bacnet_redundant_controllers": redundant_controllers,
        "traffic_monitoring_active": has_monitoring,
        "bbmd_exposure_detected": bbmd_exposure,
        "network_device_hardening_verified": has_network_hardening,
        "secure_config_verified_pct": secure_config_pct,
        "remote_access_vpn": has_vpn,
        "wireless_ssids_detected": has_wireless,
        "password_policy_detected": has_password_policy,
        "certificate_management_detected": has_cert_mgmt,
        "encryption_strength_verified": has_encryption_strength,
        "device_authentication_verified": has_device_auth,
    }

    return evidence


def _evaluate_controls(framework: list[dict], evidence: dict) -> tuple[list[dict], dict]:
    """Evaluate all controls in a framework against evidence.

    For each control:
    - If NOT_OBSERVABLE (default or from evidence evaluation), skip scoring
    - Otherwise, compute PASS (100), PARTIAL (50), or FAIL (0)

    Args:
        framework: List of control dicts
        evidence: Evidence dict from _build_evidence_from_assets

    Returns:
        Tuple of (controls_with_status, category_scores)
    """
    evaluated = []
    category_results = {}

    for ctrl in framework:
        control = dict(ctrl)
        rules = control.get("evidence_rules", {})
        observability = control.get("observability", "manual")

        # Determine status
        # If observability is manual/policy and no evidence rules, default to NOT_OBSERVABLE
        if observability in ("manual", "policy") and not rules:
            status = "NOT_OBSERVABLE"
            gap = "Manual assessment required - cannot be determined from network monitoring"
        elif control.get("default_status") == "NOT_OBSERVABLE" and not rules:
            status = "NOT_OBSERVABLE"
            gap = "Manual assessment required - cannot be determined from network monitoring"
        else:
            status = _evaluate_evidence_rules(rules, evidence)
            gap = _generate_gap_description(control, status, evidence)

        control["status"] = status
        control["gap"] = gap
        evaluated.append(control)

        # Track by category
        cat = control.get("category", "Uncategorized")
        if cat not in category_results:
            category_results[cat] = {"total": 0, "passed": 0, "partial": 0, "failed": 0, "not_observable": 0}

        category_results[cat]["total"] += 1
        if status == "PASS":
            category_results[cat]["passed"] += 1
        elif status == "PARTIAL":
            category_results[cat]["partial"] += 1
        elif status == "FAIL":
            category_results[cat]["failed"] += 1
        else:
            category_results[cat]["not_observable"] += 1

    # Compute category scores (percentage)
    category_scores = {}
    for cat, counts in category_results.items():
        scorable = counts["total"] - counts["not_observable"]
        if scorable == 0:
            score = 0.0
        else:
            scored = (counts["passed"] * 100) + (counts["partial"] * 50)
            score = round((scored / (scorable * 100)) * 100, 1)
        category_scores[cat] = {
            "passed": counts["passed"],
            "partial": counts["partial"],
            "failed": counts["failed"],
            "not_observable": counts["not_observable"],
            "total": counts["total"],
            "score": score,
        }

    return evaluated, category_scores


def _generate_gap_description(control: dict, status: str, evidence: dict) -> str:
    """Generate a human-readable gap description for a control result.

    Args:
        control: The control dict
        status: "PASS", "FAIL", "PARTIAL", or "NOT_OBSERVABLE"
        evidence: Evidence dict from scan data

    Returns:
        String describing the gap or compliance status
    """
    ctrl_id = control["id"]
    title = control["title"]

    if status == "PASS":
        return f"Control {ctrl_id} ({title}) is compliant based on observed network evidence."

    if status == "NOT_OBSERVABLE":
        return f"Control {ctrl_id} ({title}) requires manual assessment - cannot be evaluated from network monitoring alone."

    rules = control.get("evidence_rules", {})
    failures = []

    for rule_key, rule_config in rules.items():
        threshold = rule_config.get("threshold", 0)
        actual = evidence.get(rule_key, "N/A")
        op = rule_config.get("operator", "gte")

        if status == "PARTIAL":
            # Some rules passed, some didn't
            pass

        failures.append(f"{rule_key}={actual} (threshold: {op} {threshold})")

    if status == "FAIL":
        gap_detail = "; ".join(failures[:3]) if failures else "No evidence available"
        return (
            f"Control {ctrl_id} ({title}) failed compliance check. "
            f"Evidence: {gap_detail}. "
            f"Remediation: {control.get('remediation', 'Review and implement controls.')}"
        )

    if status == "PARTIAL":
        gap_detail = "; ".join(failures[:3]) if failures else "Partial evidence only"
        return (
            f"Control {ctrl_id} ({title}) partially meets requirements. "
            f"Evidence: {gap_detail}. "
            f"Address remaining gaps per: {control.get('remediation', 'Review and implement controls.')}"
        )

    return f"Control {ctrl_id} ({title}) status undetermined."


def _compute_framework_score(category_scores: dict) -> float:
    """Compute overall framework score from category scores.

    Categories with all controls as NOT_OBSERVABLE are excluded.

    Args:
        category_scores: Dict of category -> score info

    Returns:
        Float 0-100 representing overall framework adherence
    """
    total_weighted = 0.0
    total_weight = 0

    for cat, info in category_scores.items():
        scorable = info["total"] - info["not_observable"]
        if scorable == 0:
            continue
        weight = scorable  # Weight by number of scorable controls
        total_weighted += info["score"] * weight
        total_weight += weight

    if total_weight == 0:
        return 0.0

    return round(total_weighted / total_weight, 1)


def _compute_rating(score: float) -> str:
    """Convert a numerical score to a compliance rating.

    Args:
        score: Float 0-100

    Returns:
        "Compliant", "Partial", or "At Risk"
    """
    if score >= 85:
        return "Compliant"
    elif score >= 65:
        return "Partial"
    else:
        return "At Risk"


def _find_critical_findings(desc_evaluated: list[dict], iec_evaluated: list[dict]) -> list[str]:
    """Identify the top 5 most important compliance gaps.

    Prioritizes FAIL status controls with network observability
    over manual/policy controls.

    Args:
        desc_evaluated: Evaluated DESC controls
        iec_evaluated: Evaluated IEC controls

    Returns:
        List of top 5 gap descriptions
    """
    all_failures = []

    for ctrl in desc_evaluated + iec_evaluated:
        if ctrl.get("status") == "FAIL":
            obs = ctrl.get("observability", "policy")
            priority = 0 if obs == "network" else (1 if obs == "config" else 2)
            desc = f"({ctrl['framework']}) {ctrl['id']}: {ctrl['title']}"
            all_failures.append((priority, desc))

    # Sort: network first, then config, then manual/policy
    all_failures.sort(key=lambda x: x[0])
    return [desc for _, desc in all_failures[:5]]


def _find_strengths(desc_evaluated: list[dict], iec_evaluated: list[dict]) -> list[str]:
    """Identify the top 5 compliance strengths.

    Prioritizes PASS status controls with network observability.

    Args:
        desc_evaluated: Evaluated DESC controls
        iec_evaluated: Evaluated IEC controls

    Returns:
        List of top 5 strength descriptions
    """
    all_passes = []

    for ctrl in desc_evaluated + iec_evaluated:
        if ctrl.get("status") == "PASS":
            obs = ctrl.get("observability", "policy")
            priority = 0 if obs == "network" else (1 if obs == "config" else 2)
            desc = f"({ctrl['framework']}) {ctrl['id']}: {ctrl['title']}"
            all_passes.append((priority, desc))

    if not all_passes:
        return ["No compliant controls detected from network monitoring. Manual assessment may reveal additional compliance."]

    all_passes.sort(key=lambda x: x[0])
    return [desc for _, desc in all_passes[:5]]


def evaluate_compliance(assets: list[dict], summary: dict) -> dict:
    """Evaluate OT cybersecurity compliance against DESC and IEC 62443-3-3.

    This is the core evaluation engine. It processes scan data (asset list
    + summary statistics) against all controls in both frameworks and produces
    a comprehensive compliance report.

    Args:
        assets: List of discovered BACnet/OT device dictionaries.
                Each device should have fields like:
                - ip, device_id, type, vendor, firmware, default_credentials
                - bacnet_sc, wireless, cov_subscribed, time_sync
                - vulnerabilities, etc.
        summary: Dict with scan summary statistics including:
                - total_assets, zones_detected, broadcast_domains
                - it_ot_cross_traffic, bbmd_exposure, monitoring_active
                - bacnet_plaintext, acls_detected, and more.

    Returns:
        dict: Complete compliance assessment with:
            - score: Overall 0-100 score
            - rating: "Compliant" | "Partial" | "At Risk"
            - generated_at: ISO timestamp
            - frameworks: dict with DESC and IEC results
            - critical_findings: Top 5 gaps
            - strengths: Top 5 compliant areas
    """
    # Build evidence from scan data
    evidence = _build_evidence_from_assets(assets, summary)

    # Evaluate both frameworks
    desc_evaluated, desc_cat_scores = _evaluate_controls(DESC_FRAMEWORK, evidence)
    iec_evaluated, iec_cat_scores = _evaluate_controls(IEC62443_FRAMEWORK, evidence)

    # Compute framework scores
    desc_score = _compute_framework_score(desc_cat_scores)
    iec_score = _compute_framework_score(iec_cat_scores)

    # Compute overall score (weighted average of both frameworks)
    total_controls = sum(
        info["total"] - info["not_observable"]
        for info in desc_cat_scores.values()
    ) + sum(
        info["total"] - info["not_observable"]
        for info in iec_cat_scores.values()
    )

    if total_controls > 0:
        desc_weight = sum(
            info["total"] - info["not_observable"]
            for info in desc_cat_scores.values()
        ) / total_controls
        iec_weight = sum(
            info["total"] - info["not_observable"]
            for info in iec_cat_scores.values()
        ) / total_controls
        overall_score = round((desc_score * desc_weight + iec_score * iec_weight), 1)
    else:
        overall_score = 0.0

    # Generate findings
    critical_findings = _find_critical_findings(desc_evaluated, iec_evaluated)
    strengths = _find_strengths(desc_evaluated, iec_evaluated)

    return {
        "score": overall_score,
        "rating": _compute_rating(overall_score),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "frameworks": {
            "DESC": {
                "controls": desc_evaluated,
                "category_scores": desc_cat_scores,
                "score": desc_score,
            },
            "IEC 62443": {
                "controls": iec_evaluated,
                "category_scores": iec_cat_scores,
                "score": iec_score,
            },
        },
        "critical_findings": critical_findings,
        "strengths": strengths,
    }

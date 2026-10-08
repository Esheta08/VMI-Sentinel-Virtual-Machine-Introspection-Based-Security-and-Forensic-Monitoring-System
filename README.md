# VMI-Sentinel
### Virtual Machine Introspection Based Security Monitoring System

## 1. Project Description

VMI-Sentinel is a security monitoring system based on **Virtual Machine Introspection (VMI)**. The project focuses on monitoring virtual machines from outside the guest operating system using the hypervisor and VMI technologies.

The system collects information and events from a running virtual machine without depending entirely on software installed inside the guest. The collected data is processed to identify suspicious activities and potential security threats, which are then stored and presented through a monitoring dashboard.

## 2. Problem Statement

Traditional security monitoring solutions generally depend on agents or security software running inside the guest operating system. If the guest OS is compromised, attackers may be able to manipulate or disable these monitoring mechanisms.

VMI provides an alternative approach by allowing monitoring to be performed externally from the hypervisor layer. This project aims to use VMI to collect reliable information about the guest system and use it for security monitoring and threat detection.

## 3. Objectives

- Monitor virtual machines from outside the guest OS.
- Collect guest system information and security-related events.
- Process and analyze the collected events.
- Detect suspicious activities and potential threats.
- Store monitoring data and security alerts in a database.
- Provide a dashboard for real-time or near-real-time visualization.
- Build a modular platform that can be extended with additional security detection techniques.

## 4. Team Members

Tejas Joshi - VMI and Virtualization

Esheta - Event Processing and Threat Detection

Parv Saini - Dashboard and Database

## 5. Technologies and Tools

- **KVM** – Hardware-assisted virtualization
- **KVMI / KVM-VMI** – Virtual Machine Introspection support
- **QEMU** – Virtual machine emulator
- **LibVMI** – Library for accessing guest OS information through VMI
- **libvirt** – Virtual machine management
- **Virt-Manager** – Virtual machine management interface
- **Python** – Backend and event-processing components
- **PostgreSQL** – Database for storing events and alerts
- **React** – Monitoring dashboard
- **Ubuntu Linux** – Development and virtualization environment
- **Git** – Version control

## 6. System Modules

### 6.1 VMI and Virtualization
Responsible for setting up the virtualization environment and enabling VMI-based access to the guest virtual machine. This module uses KVM, KVMI, QEMU and LibVMI to obtain information from the guest externally.

### 6.2 Event Processing and Threat Detection
Collects and processes events obtained through VMI. The module analyzes system activity and identifies patterns that may indicate suspicious behavior or security threats.

### 6.3 Database
Stores collected events, system information, detected threats and security alerts. PostgreSQL is planned to be used as the primary database.

### 6.4 Dashboard
Provides a web-based interface for viewing VM activity, events, detected threats and alerts. The dashboard will help users understand the security state of monitored virtual machines.

## 7. Project Setup

1. Set up an Ubuntu Linux host with KVM and libvirt.
2. Create and configure the guest virtual machine.
3. Clone and configure the KVM-VMI repository.
4. Build and configure the KVMI-enabled kernel.
5. Build the modified QEMU with introspection support.
6. Configure the guest VM for VMI.
7. Build and install LibVMI.
8. Implement event collection and processing.
9. Configure the PostgreSQL database.
10. Develop and connect the monitoring dashboard.

## 8. Current Project Status

**Project Status: In Development**

### Completed
- Ubuntu development environment setup
- KVM and virtualization environment verification
- QEMU and libvirt setup
- Guest virtual machine creation
- KVM-VMI repository setup
- Selection of the KVMI-V7 branch
- Initial project architecture and module planning

### In Progress
- KVM-VMI submodule setup
- KVMI-enabled kernel configuration
- Modified QEMU setup
- LibVMI integration
- Initial VMI-based guest monitoring

### Planned
- Event collection pipeline
- Threat detection mechanisms
- PostgreSQL database integration
- Web-based monitoring dashboard
- Real-time security alerts
- Testing and performance evaluation

## 9. Expected Outcome

The final system will provide a centralized platform capable of monitoring virtual machines using VMI, processing guest activity, detecting suspicious behavior and presenting security information through a dashboard.

The project aims to demonstrate how hypervisor-level monitoring can be used as an additional layer of security for virtualized environments.

## 10. Future Scope

- Advanced memory and process monitoring
- Real-time threat detection
- Automated security alerts
- Detection of rootkits and malicious processes
- Support for multiple virtual machines
- Improved visualization and reporting
- Integration with additional security and threat intelligence systems
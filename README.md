VMI-Sentinel

Virtual Machine Introspection Based Security and Forensic Monitoring System

1. About the Project

VMI-Sentinel is a security monitoring system that uses Virtual Machine Introspection (VMI) to monitor the activities of a Guest Virtual Machine from outside its operating system.

Traditional monitoring systems usually install an agent inside the Guest OS to collect information. However, if the Guest OS is compromised, an attacker may also interfere with that monitoring agent.

VMI-Sentinel takes a different approach. It uses the hypervisor to observe the Guest VM externally, without depending on an in-guest monitoring agent.

The collected process-related events are processed and stored in a PostgreSQL database. A Machine Learning model analyses the activity to identify unusual behaviour, and the results are displayed through a Streamlit dashboard.

2. Objectives

To monitor Guest VM activities from outside the operating system.

To collect process-related information using Virtual Machine Introspection.

To process and store collected events in a structured format.

To identify unusual VM behaviour using Machine Learning.

To maintain event history for security monitoring and forensic investigation.

To provide a dashboard for viewing events, anomaly scores and alerts.


Working Flow

Guest VM: The virtual machine runs its operating system and processes.

QEMU/KVM: Provides the virtualization environment and manages the Guest VM.

KVMI: Allows configured monitoring events to be handled through the hypervisor.

LibVMI Collector: The C-based collector reads the required process information from the Guest VM's memory.

Python Adapter: Receives the collector output, validates it and converts it into a standard event format.

PostgreSQL: Stores the processed events, VM information and alerts.

Feature Extraction: Converts process events into numerical features over fixed time windows.

Isolation Forest: Analyses the features and assigns anomaly scores to identify unusual activity.

Streamlit Dashboard: Displays VM information, event timelines, anomaly scores and alerts.

4. Key Features

External VM Monitoring: Monitors guest processes without installing a monitoring agent inside the Guest OS.

Process Event Collection: Collects information related to process creation, execution and termination.

Event Processing: Converts raw collector output into a consistent structure using the Python adapter.

Database Management: Stores VM details, events and alerts in PostgreSQL.

Anomaly Detection: Uses Isolation Forest to identify behaviour that differs from normal VM activity.

Alert Generation: Records activities identified as anomalous by the detection model.

Event History: Maintains historical records that can be used for further investigation.

Dashboard: Provides a visual interface to monitor events and alerts.

5. Technologies Used

Technology

Purpose

QEMU

Runs and manages virtual machines

KVM

Provides hardware-assisted virtualization

KVMI

Handles configured VM monitoring events

LibVMI

Reads information from Guest VM memory

C

Implements the process monitoring collector

Python

Processes and validates collected events

PostgreSQL

Stores VM details, events and alerts

Scikit-learn

Provides Machine Learning functionality

Isolation Forest

Detects unusual VM behaviour

Streamlit

Displays monitoring information

Git and GitHub

Version control and project management

6. Machine Learning Approach

VMI-Sentinel uses the Isolation Forest algorithm for anomaly detection.

The model is trained using normal VM activity. It learns the usual pattern of process-related behaviour and identifies observations that differ from this baseline.

The model uses five process-related features:

Number of processes created.

Number of processes executed.

Number of processes terminated.

Number of short-lived processes.

Number of distinct programs.

These features are calculated over 30-second time windows.

The trained model assigns anomaly scores to new observations. Activities identified as anomalous are recorded as alerts for further investigation.

Why Isolation Forest?

It does not require labelled attack data for training.

It can learn from normal activity.

It works with a small number of numerical features.

It is suitable for identifying unusual combinations of behaviour.

7. Database

PostgreSQL is used as the central storage system.

It maintains:

Virtual machine information.

Collected process events.

Anomaly alerts.

Historical monitoring records.

The stored information can be queried later to examine previous VM activities and investigate suspicious events.

8. Dashboard

The project uses Streamlit to provide a visual interface for monitoring the Guest VM.

The dashboard displays:

Monitored VM information.

Process event history.

Event timelines.

Anomaly scores.

Generated alerts.

Historical records for investigation.

9. Project Limitations

VMI-Sentinel is an academic prototype and currently focuses on process-related monitoring and basic anomaly detection.

Some limitations include:

Monitoring is focused mainly on selected process events rather than all VM activities.

The ML model is trained on a limited set of collected workloads.

Low-rate or stealthy activities can be difficult to detect.

The monitoring setup depends on compatible kernel configurations and VMI profiles.

Further work is required to improve detection accuracy and reduce monitoring overhead.

10. Future Scope

Monitor additional system activities such as file and network operations.

Improve detection of slow and stealthy attacks.

Explore additional anomaly detection techniques.

Improve monitoring performance using more targeted event handling.

Extend support to multiple virtual machines.

Improve the integrity and protection of stored forensic evidence.

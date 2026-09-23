# Splunk SIEM Security Monitoring & BOTSv3 Investigation Lab

## Project Overview

This project demonstrates hands-on experience using **Splunk Enterprise as a SIEM** for Windows security monitoring, firewall analysis, endpoint investigation, cloud authentication analysis, event correlation, and dashboard creation.

The lab was divided into two major phases:

1. **Windows Security & Firewall Monitoring**
   - Analyzed Windows Security events
   - Investigated network source and destination addresses
   - Reviewed process creation activity
   - Created firewall event classifications
   - Built a Splunk firewall analysis dashboard

2. **BOTSv3 Security Investigation**
   - Explored multiple security data sources
   - Investigated suspicious endpoint activity
   - Analyzed Windows Event Logs
   - Investigated email and Microsoft 365 activity
   - Identified suspicious authentication activity from Hong Kong
   - Pivoted on an IP address across Azure AD, SharePoint, OneDrive, and Exchange
   - Correlated activity between multiple user accounts
   - Reconstructed an event timeline
   - Built a final SOC investigation dashboard

---

## Technologies Used

- Splunk Enterprise
- Splunk Search Processing Language (SPL)
- Windows Security Event Logs
- Windows Event Viewer
- Windows Filtering Platform
- Microsoft Azure Active Directory logs
- Microsoft 365 audit logs
- SharePoint
- OneDrive
- Exchange
- Symantec Endpoint Protection telemetry
- BOTSv3 Dataset

---

# Part 1 — Windows Network Analysis

I began by analyzing Windows network events in Splunk and using SPL to understand communication between source and destination systems.

```spl
index=main Destination_Address="*.*"
| stats count by Destination_Address, Source_Address

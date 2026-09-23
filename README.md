# Splunk SIEM Security Monitoring & BOTSv3 Investigation Lab

## Project Overview

This project focused on using **Splunk Enterprise as a SIEM** for Windows security monitoring, firewall analysis, endpoint investigation, identity analysis, Microsoft 365 activity, event correlation, timeline reconstruction, and dashboard creation.

The lab had two major phases:

1. **Windows Security and Firewall Monitoring**
   - Analyzed Windows network activity
   - Investigated Windows process creation events
   - Correlated processes with user accounts
   - Analyzed allowed and blocked firewall traffic
   - Built a firewall analysis dashboard

2. **BOTSv3 Security Investigation**
   - Loaded and explored the Boss of the SOC v3 dataset
   - Investigated suspicious endpoint activity
   - Analyzed Windows Security events
   - Investigated suspicious email artifacts
   - Analyzed Azure AD authentication activity
   - Pivoted on a suspicious IP address
   - Correlated SharePoint, OneDrive, Exchange, and Azure AD activity
   - Correlated multiple user accounts
   - Reconstructed a timeline
   - Created saved reports and a final SOC investigation dashboard

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
- Boss of the SOC v3 (BOTSv3)

---

# Part 1 — Network Source and Destination Analysis

I began by using Splunk to analyze Windows network events.

I used SPL to group traffic by its source and destination addresses:

```spl
index=main Destination_Address="*.*"
| stats count by Destination_Address, Source_Address
```

This made it easier to understand which systems were communicating and how frequently different source and destination combinations appeared.

![Network Source and Destination Analysis](Splunk%20screenshots/network-source-destination-analysis.png)

### What I Learned

This step helped me become more comfortable using `stats` to summarize large numbers of events instead of reviewing logs individually.

It also reinforced the difference between:

- `Source_Address` — where traffic originated
- `Destination_Address` — where traffic was going

---

# Part 2 — Windows Process Creation Analysis

I investigated Windows process creation events using **Event ID 4688**.

```spl
index=main EventCode=4688
```

Event ID 4688 is generated when Windows creates a new process and can help analysts investigate command execution and suspicious applications.

![Windows Event 4688 Process Creation](Splunk%20screenshots/windows-event-4688-process-creation.png)

I also correlated processes with user accounts:

```spl
index=main Account_Name="*"
| stats count by Creator_Process_Name, Account_Name
```

![Process and Account Correlation](Splunk%20screenshots/process-account-correlation.png)

### What I Learned

Instead of looking only at a process name, I learned to ask:

- Which user account was associated with the process?
- How frequently did the process appear?
- Did the process appear under multiple accounts?
- Was the process path expected?

This is useful when investigating suspicious endpoint behavior.

---

# Part 3 — Windows Firewall Analysis

I searched Windows event data for blocked network activity.

```spl
index=main *blocked*
```

This allowed me to review activity that Windows Filtering Platform had prevented.

![Blocked Firewall Traffic](Splunk%20screenshots/blocked-firewall-traffic.png)

I also worked with Windows Filtering Platform events such as:

- **5156** — Windows Filtering Platform permitted a connection
- **5158** — Windows Filtering Platform permitted an application to bind to a local port

I created classifications for allowed and blocked firewall activity and then used the data to build a Splunk dashboard.

---

# Part 4 — Firewall Analysis Dashboard

I created a dashboard to make firewall activity easier to review.

The dashboard included information such as:

- Source IP
- Source port
- Destination IP
- Destination port
- Event classification
- Computer name
- Event count
- Allowed vs. blocked traffic

![Firewall Analysis Dashboard](Splunk%20screenshots/firewall-analysis-dashboard.png)

### What I Learned

This demonstrated the difference between simply searching logs and presenting the results in a way an analyst can quickly review.

Dashboards can help turn raw event data into a more usable monitoring view.

---

# Part 5 — Loading and Verifying BOTSv3

The second phase of the project used the **Boss of the SOC v3 (BOTSv3)** dataset.

After loading the dataset into Splunk, I verified that the events were available:

```spl
index=botsv3 earliest=0
```

![BOTSv3 Data Verification](Splunk%20screenshots/botsv3-data-verification.png)

Because BOTSv3 contains historical events, I learned that the **Splunk time range is extremely important**.

Many searches needed to use:

**All time**

Otherwise, the correct SPL could still return no results.

---

# Part 6 — Discovering Available Data Sources

Before starting the investigation, I explored the different sourcetypes contained in BOTSv3.

```spl
index=botsv3 earliest=0
| top limit=20 sourcetype
```

![BOTSv3 Sourcetype Discovery](Splunk%20screenshots/botsv3-sourcetype-discovery.png)

The dataset contained multiple types of security telemetry, including:

- Windows Security events
- Azure AD authentication events
- Microsoft 365 events
- Endpoint security data
- Email-related data
- Cloud activity
- Network activity

### What I Learned

One important lesson was to first understand **what logs are available** before deciding how to investigate.

A SOC analyst cannot search data that is not being collected.

---

# Part 7 — Suspicious Dropbox Process Investigation

During the endpoint portion of the investigation, I searched for Dropbox-related processes.

One process stood out because `DropboxUpdate.exe` was executing from a temporary directory:

```text
C:\Users\BRUCEG~1\AppData\Local\Temp\GUM4F89.tmp\DropboxUpdate.exe
```

![Suspicious Dropbox Process](Splunk%20screenshots/suspicious-dropbox-process.png)

The location was important because legitimate programs are normally expected to run from known application directories rather than unusual temporary folders.

This did not automatically prove the file was malicious, but it made the process worth investigating further.

---

# Part 8 — Correlating Dropbox Windows Events

I narrowed the investigation to the temporary `DropboxUpdate.exe` process.

```spl
index=botsv3 sourcetype="WinEventLog:Security" earliest=0 Process_Name="*DropboxUpdate.exe"
| where like(Process_Name, "%Temp%")
| table _time ComputerName Account_Name Process_Name EventCode
```

This search allowed me to correlate multiple Windows events involving the same process.

![Dropbox Event Correlation](Splunk%20screenshots/dropbox-event-correlation.png)

The activity included events such as:

- **4663** — an attempt was made to access an object
- **4689** — a process exited

This helped build a timeline around the process rather than viewing each event separately.

---

# Part 9 — Windows Event 4663 Analysis

I opened the Event ID 4663 activity in more detail.

![Dropbox Event 4663 Details](Splunk%20screenshots/dropbox-event-4663-details.png)

The event showed the temporary `DropboxUpdate.exe` process interacting with a file on the system.

Important investigation fields included:

- Computer name
- Account name
- Process name
- Object name
- Access type
- Event ID
- Timestamp

### What I Learned

This showed me how Windows logs can be combined to understand what a process was doing instead of only knowing that it existed.

---

# Part 10 — Searching for Bruce and Birthday Artifacts

I expanded the investigation using keyword searches.

```spl
index=botsv3 *bruce* OR *birthday*
```

This allowed me to search across multiple data sources for information connected with Bruce and birthday-related activity.

The search surfaced additional artifacts, including email-related evidence.

---

# Part 11 — Suspicious Email Investigation

One of the artifacts was an email associated with the investigation.

![Suspicious Birthday Email](Splunk%20screenshots/suspicious-birthday-email.png)

The email contained information such as:

```text
From: HyunKi Kim <hyunki1984@naver.com>
Sent: Thursday, July 26, 2018
```

and became another pivot point in the investigation.

### What I Learned

This demonstrated how a broad keyword search can identify artifacts that would be difficult to find if I only searched a single sourcetype.

A SOC investigation often moves between:

**endpoint activity → email → identity → cloud activity**

rather than staying inside one log source.

---

# Part 12 — Hong Kong Authentication Investigation

I investigated Azure AD authentication events originating from Hong Kong.

```spl
index=botsv3 sourcetype="ms:aad:signin" location.country="HK"
```

I set the time range to:

```text
All time
```

The search returned **27 events**.

![Hong Kong Sign-In Investigation](Splunk%20screenshots/hong-kong-signin-investigation.png)

One important IP address identified during the investigation was:

```text
104.207.83.63
```

The events included successful sign-in activity involving accounts such as:

```text
fyodor@froth.ly
```

### What I Learned

The location itself was not enough to prove malicious activity.

Instead, the location became interesting because it could be correlated with:

- User accounts
- Authentication results
- IP addresses
- Microsoft applications
- Other activity in the dataset

---

# Part 13 — Account and MFA Analysis

I examined additional authentication fields to understand which accounts and Microsoft applications were involved.

Important fields included:

- `userPrincipalName`
- `location.country`
- `appDisplayName`
- `mfaRequired`

![Hong Kong Account and MFA Analysis](Splunk%20screenshots/hong-kong-account-mfa-analysis.png)

The results included activity involving:

```text
bgist@froth.ly
fyodor@froth.ly
```

and Microsoft services such as:

- Azure Portal
- Microsoft Office 365
- Exchange Online
- SharePoint Online

This helped expand the investigation from one login event into broader account activity.

---

# Part 14 — Pivoting on the IP Address

After identifying the IP:

```text
104.207.83.63
```

I searched the entire BOTSv3 dataset for it.

```spl
index=botsv3 *"104.207.83.63"*
```

This is an example of **IOC pivoting**.

The investigation workflow became:

```text
Identify an interesting IP
        ↓
Search the IP across all logs
        ↓
Identify associated users
        ↓
Identify associated services
        ↓
Investigate related activity
```

### What I Learned

One artifact can become the starting point for multiple searches.

Instead of stopping after identifying the IP, I used it to discover additional user and cloud activity.

---

# Part 15 — SharePoint and OneDrive File Activity

I narrowed the IP search to events containing filenames.

```spl
index=botsv3 *"104.207.83.63"* SourceFileName="*"
```

This returned Microsoft 365 file-related events.

One important event contained:

```text
ClientIP: 104.207.83.63
EventSource: SharePoint
Operation: FilePreviewed
SourceFileName: morebeer.jpg
SourceRelativeUrl: Documents/Birthday Pictures
UserId: bgist@froth.ly
Workload: OneDrive
```

![SharePoint Birthday Photo Activity](Splunk%20screenshots/sharepoint-birthday-photo-activity.png)

This correlated the IP with:

- `bgist@froth.ly`
- SharePoint
- OneDrive
- Birthday-related file activity

### What I Learned

This was a good example of using one indicator across completely different data sources.

The same IP that appeared in authentication activity also appeared in Microsoft 365 file activity.

---

# Part 16 — BGIST and FYODOR Correlation

I summarized activity associated with the IP by user and workload.

```spl
index=botsv3 *"104.207.83.63"*
| stats count by ClientIP, UserId, Workload
```

![BGIST FYODOR IP Correlation](Splunk%20screenshots/bgist-fyodor-ip-correlation.png)

The results connected the IP with both:

```text
bgist@froth.ly
fyodor@froth.ly
```

across workloads including:

- AzureActiveDirectory
- OneDrive
- SharePoint
- Exchange

### Why This Was Important

Instead of viewing each event individually, the `stats` command showed that:

**one IP → multiple users → multiple Microsoft services**

This made the larger pattern easier to see.

---

# Part 17 — Timeline Reconstruction

The previous correlation search showed what accounts and services were involved, but it did not clearly show the order of activity.

I added `_time`:

```spl
index=botsv3 *"104.207.83.63"*
| stats count by _time, ClientIP, UserId, Workload
```

![BGIST FYODOR Timeline](Splunk%20screenshots/bgist-fyodor-timeline.png)

Adding `_time` allowed me to reconstruct the sequence of events.

This helped answer questions such as:

- Which account appeared first?
- Which service was accessed first?
- When did OneDrive activity occur?
- When did SharePoint activity occur?
- When did FYODOR activity appear?
- How did the activity progress over time?

### What I Learned

A list of events tells me **what happened**.

Adding time helps answer:

**In what order did it happen?**

That is critical during incident investigation.

---

# Part 18 — Reports

Throughout the investigation, I saved important searches as Splunk reports.

Reports included investigations involving:

- Birthday photo activity
- Hong Kong authentication activity
- BGIST and FYODOR correlation
- Timeline analysis

Saving reports allowed important investigation searches to be reused without rebuilding the SPL every time.

---

# Part 19 — Bruce Analysis Dashboard

I created a Splunk Classic Dashboard named:

# Bruce Analysis

The dashboard combined important investigation findings into a centralized SOC-style view.

The dashboard included a timeline containing:

```text
_time
ClientIP
UserId
Workload
count
```

It also included supporting Azure AD authentication evidence.

![Bruce Analysis Dashboard](Splunk%20screenshots/bruce-analysis-dashboard.png)

### What I Learned

Dashboards are useful because they allow an analyst to move from individual searches into a centralized view of the investigation.

This dashboard brought together:

- Timeline information
- IP activity
- User accounts
- Microsoft workloads
- Authentication evidence

---

# Key Findings

| Finding | Evidence |
|---|---|
| Windows network traffic analyzed | Source and destination address data |
| Windows process creation investigated | Event ID 4688 |
| Firewall activity analyzed | Windows Filtering Platform events |
| Suspicious process path identified | Temporary `DropboxUpdate.exe` |
| Object access investigated | Event ID 4663 |
| Birthday-related email artifact discovered | Email telemetry |
| Authentication activity identified from Hong Kong | Azure AD sign-in events |
| Important investigation IP identified | `104.207.83.63` |
| BGIST activity correlated | `bgist@froth.ly` |
| FYODOR activity correlated | `fyodor@froth.ly` |
| Microsoft cloud workloads correlated | Azure AD, SharePoint, OneDrive, Exchange |
| Birthday photo activity identified | `morebeer.jpg` |
| Timeline reconstructed | `_time` correlation |
| Investigation reports created | Splunk reports |
| Final investigation dashboard created | Bruce Analysis |

---

# SPL Queries Used

## Network Analysis

```spl
index=main Destination_Address="*.*"
| stats count by Destination_Address, Source_Address
```

## Process Creation

```spl
index=main EventCode=4688
```

## Process and Account Correlation

```spl
index=main Account_Name="*"
| stats count by Creator_Process_Name, Account_Name
```

## PowerShell Search

```spl
index=main powershell
```

## Blocked Firewall Activity

```spl
index=main *blocked*
```

## BOTSv3 Verification

```spl
index=botsv3 earliest=0
```

## Sourcetype Discovery

```spl
index=botsv3 earliest=0
| stats count by sourcetype
```

## Suspicious Dropbox Process

```spl
index=botsv3 sourcetype="WinEventLog:Security" earliest=0 Process_Name="*DropboxUpdate.exe"
| where like(Process_Name, "%Temp%")
| table _time ComputerName Account_Name Process_Name EventCode
```

## Bruce / Birthday Search

```spl
index=botsv3 *bruce* OR *birthday*
```

## Hong Kong Authentication

```spl
index=botsv3 sourcetype="ms:aad:signin" location.country="HK"
```

## IP Pivot

```spl
index=botsv3 *"104.207.83.63"*
```

## File Activity

```spl
index=botsv3 *"104.207.83.63"* SourceFileName="*"
```

## User and Workload Correlation

```spl
index=botsv3 *"104.207.83.63"*
| stats count by ClientIP, UserId, Workload
```

## Timeline Reconstruction

```spl
index=botsv3 *"104.207.83.63"*
| stats count by _time, ClientIP, UserId, Workload
```

---

# Skills Demonstrated

- Splunk Enterprise
- Search Processing Language (SPL)
- SIEM monitoring
- Windows Event Log analysis
- Windows Event IDs
- Windows Filtering Platform analysis
- Network traffic analysis
- Process creation analysis
- Endpoint investigation
- File activity analysis
- IOC pivoting
- Azure AD authentication analysis
- Microsoft 365 security analysis
- SharePoint analysis
- OneDrive analysis
- Exchange analysis
- Email investigation
- Cross-source event correlation
- User activity analysis
- Timeline reconstruction
- Report creation
- Dashboard creation
- SOC investigation workflow

---

# Investigation Workflow

```text
Collect Security Logs
        ↓
Understand Available Data Sources
        ↓
Search and Filter Events
        ↓
Identify Suspicious Activity
        ↓
Investigate Processes / Users / Files
        ↓
Identify Investigation Artifacts
        ↓
Pivot on IPs and Accounts
        ↓
Correlate Multiple Data Sources
        ↓
Reconstruct Timeline
        ↓
Save Reports
        ↓
Build SOC Dashboard
```

---

# What I Learned

This project helped me understand how Splunk can be used throughout an investigation instead of only as a log search tool.

Some of my biggest takeaways were:

- The **time range** can completely change Splunk search results.
- Broad searches are useful for discovering leads, but fields and sourcetypes help narrow the investigation.
- A process name alone is not enough; its **path, account, host, and related Event IDs** also matter.
- One IOC such as an IP address can be used to pivot across multiple log sources.
- `stats` is useful for turning hundreds of individual events into recognizable patterns.
- Adding `_time` helps turn correlation into a timeline.
- Identity, endpoint, email, and cloud events become much more useful when they are analyzed together.
- Saved reports and dashboards make investigation findings easier to revisit and communicate.

---

# Conclusion

This lab provided hands-on experience using Splunk for both security monitoring and SOC-style incident investigation.

I began with Windows event and network analysis, investigated process creation and firewall activity, and created a firewall dashboard.

I then loaded the BOTSv3 dataset and performed a broader investigation involving endpoint activity, Windows Security events, email artifacts, Azure AD authentication, Microsoft 365, SharePoint, OneDrive, and Exchange.

The investigation required me to move from individual artifacts to broader correlation by using processes, usernames, filenames, IP addresses, workloads, and timestamps as pivots.

By the end of the project, I had created multiple SPL searches, saved reports, reconstructed a timeline, and built a final Splunk dashboard containing the investigation evidence.

The project strengthened my practical experience with **SIEM analysis, SPL, log investigation, IOC pivoting, cross-source correlation, timeline reconstruction, and SOC workflows**.

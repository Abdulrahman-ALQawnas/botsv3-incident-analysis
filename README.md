# botsv3-incident-analysis
Explore a complete Security Operations Center (SOC) investigation of the Frothly case study using the BOTSv3 dataset in Splunk. This repository contains refined SPL queries, evidence screenshots, and in-depth documentation, highlighting best practices in version-controlled SOC reporting and continuous incident analysis.

# Project Outline
## ●	Introduction
- Security Operations Center (SOC) overview
- BOTSv3 dataset overview
- Project objectives, scope, and assumptions
##  ●	SOC Roles & Incident Handling Reflection
- SOC analyst responsibilities reflected in this project
- Incident response lifecycle applied to findings
## ●	Installation & Data Preparation
- Splunk installation environment
- BOTSv3 dataset ingestion process
- Screenshot and evidence management
## ●	Incident Investigation (Core Analysis)
- Investigation goal and SOC methodology
- 200-series incident analysis using SPL
- Identity abuse, cloud misconfiguration, endpoint compromise
- SOC alignment: detection, investigation, root-cause analysis
- Documentation and GitHub commit strategy
## ●	Conclusion & References

# Introduction 
# Overview of Security Operations Center (SOC)
A Security Operations Center (SOC) is a centralized function responsible for monitoring, detecting, analyzing, and responding to cybersecurity threats across an organization’s infrastructure. A SOC continuously collects logs from endpoints, servers, cloud platforms, and security tools to maintain visibility and ensure rapid response to incidents.
Modern SOC teams rely on SIEM platforms to correlate events across multiple data sources. These platforms allow analysts to identify abnormal behavior, investigate incidents, and reconstruct attack timelines. Effective SOC operations depend not only on tools, but also on structured investigation methodology and clear documentation.
________________________________________
# Overview of the BOTSv3 Dataset
BOTSv3 (Boss of the SOC – Version 3) is a realistic enterprise dataset created by Splunk for SOC training and incident response simulations. It represents a fictional organization called Frothly and includes logs from Windows endpoints, AWS infrastructure, web servers, email systems, and endpoint security tools.
The dataset contains both legitimate activity and multiple attack scenarios, including credential leakage, cloud misconfiguration, malware infections, and unauthorized access attempts. This makes BOTSv3 ideal for practicing real-world SOC investigations.
________________________________________
# Project Objectives, Scope, and Assumptions
The objective of this project is to perform a complete SOC-style investigation using Splunk and the BOTSv3 dataset. The project demonstrates the ability to analyze logs, identify security incidents, and document findings in a professional and client-ready format.
The scope includes Splunk installation, dataset ingestion, SPL-based analysis, and investigation of cloud security incidents, identity misuse, and endpoint compromise. Live response and remediation actions are outside the scope.
It is assumed that all logs in the dataset are accurate and complete. The investigation is performed from a post-incident perspective, similar to how SOC analysts reconstruct events after alerts are triggered.
________________________________________
# SOC Roles & Incident Handling Reflection 
# SOC Roles Reflected in This Project
This project closely mirrors the responsibilities of a Tier-2 SOC Analyst. Rather than simply responding to alerts, the analysis involves correlating logs across cloud, endpoint, and security platforms to understand the full scope of incidents.
Throughout the project, identity activity, cloud configuration changes, endpoint performance anomalies, and malware alerts were analyzed together. This multi-source correlation reflects real SOC investigation workflows.
________________________________________
# Incident Response Lifecycle Applied
The investigation follows the standard incident response lifecycle.
Preparation involved setting up Splunk and ensuring correct data ingestion.
Detection occurred when abnormal activities such as unauthorized AWS API calls and high CPU utilization were identified.
Analysis was performed using SPL to confirm incidents, identify affected assets, and build timelines.
Containment and eradication were observed indirectly through logs showing blocked malware activity.
Lessons learned were derived by identifying security gaps such as exposed credentials and lack of MFA enforcement.
________________________________________
# Installation & Data Preparation 
# Splunk Installation Environment
Splunk Enterprise Free was installed on an Ubuntu virtual machine to simulate a realistic SOC environment. The system was updated before installation to ensure stability. Splunk was then installed and initialized, and the web interface was accessed through the browser using port 8000.
Administrative credentials were configured and Splunk was enabled to start automatically on boot.
## Step 1: Install Splunk Free on Ubuntu VM
## 1. Update the system
Before installing, make sure your system packages are updated:
sudo apt update && sudo apt upgrade -y

### Explanation:
This ensures all dependencies are up-to-date and prevents installation errors.
________________________________________

## 2. Download Splunk Free
Go to the official Splunk download page: https://www.splunk.com/en_us/download/splunk-enterprise.html
●	Select Linux → 64-bit .deb package.
![Select Linux → 64-bit .deb package]( screenshots/screenshots/splunk/splunk1.png)
●	Copy the download link, then run:
wget -O splunk-10.0.2-e2d18b4767e9-linux-amd64.deb "https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.deb"
### Explanation:
This downloads the Splunk installation package to your VM.
![downloads the Splunk installation package](screenshots/screenshots/splunk/splunk2.png)
________________________________________

## 3. Install Splunk
### Explanation:
This installs Splunk on your Ubuntu system using the Debian package manager.
 ![installs Splunk]( screenshots/screenshots/splunk/splunk3.png)
________________________________________

## 4. Start Splunk for the first time
sudo /opt/splunk/bin/splunk start --accept-license

●	You will be prompted to create an admin username and password.
●	Make note of these credentials as you will need them to log in.
![Start Splunk for the first time]( screenshots/screenshots/splunk/splunk4.png)
![splunk interface]( screenshots/screenshots/splunk/splunk5.png)
________________________________________

## 5. Enable Splunk to start on boot (optional)
sudo /opt/splunk/bin/splunk enable boot-start
![Enable Splunk to start on boot]( screenshots/screenshots/splunk/splunk6.png)
________________________________________

## 6. Access Splunk Web Interface
Open your web browser and go to:
http://<YOUR_VM_IP>:8000

●	Login using the admin username and password you set earlier.
![Access Splunk Web Interface]( screenshots/screenshots/splunk/splunk7.png)
![gui interface]( screenshots/screenshots/splunk/splunk8.png)
________________________________________


# BOTSv3 Dataset Ingestion
The BOTSv3 dataset was downloaded from the official repository and extracted locally. Only the correct pre-indexed dataset folder was copied into Splunk’s application directory. Splunk was then restarted to load all indexes and sourcetypes.
Successful ingestion was verified by running searches against the botsv3 index and confirming the presence of events from multiple data sources.
## Step 1: Direct ZIP Download via Browser
## 1.	Open this link in your browser:
https://github.com/splunk/botsv3
Click Code → Download ZIP 
![Direct ZIP Download via Browser](screenshots/screenshots/botsv3-ingestion/dataset1.png)
## 2.	Save the ZIP file somewhere on your VM, e.g.:
Mkdir botsv3_project

## 4.	Open a terminal and unzip the file:
       cd ~/botsv3_project
![Save the ZIP file]( screenshots/screenshots/botsv3-ingestion/dataset2.png)
![extract]( screenshots/screenshots/botsv3-ingestion/dataset3.png)
________________________________________
 
## Step 2: Delete any wrong folder in Splunk apps (if exists)
Go to Splunk apps folder:
cd /opt/splunk/etc/apps
Ls
●	If you see a wrong folder (like a previous botsv3), delete it:

      sudo rm -r botsv3
●	Verify deletion:

       ls
![Go to Splunk apps folder]( screenshots/screenshots/botsv3-ingestion/dataset4.png)
________________________________________

## Step 3: Copy the correct pre-indexed dataset into Splunk
Copy botsv3_data_set folder into Splunk apps:
sudo cp -r /home/ubuntu/Downloads/botsv3/botsv3_data_set /opt/splunk/etc/apps/
![Copy botsv3_data_set folder into Splunk apps](screenshots/screenshots/botsv3ingestion/dataset5.png)
●	You should see botsv3_data_set among other apps.
●	Inside it, you should see folders like default/, local/, metadata/.
![ls]( screenshots/screenshots/botsv3-ingestion/dataset6.png)
________________________________________

## Step 4: Restart Splunk
To make Splunk recognize the new dataset:
sudo /opt/splunk/bin/splunk restart

●	Wait a minute.

●	Open Splunk Web: http://localhost:8000
![retsart splunk]( screenshots/screenshots/botsv3-ingestion/dataset7.png)
![go to manage apps]( screenshots/screenshots/botsv3-ingestion/dataset8.png)
________________________________________


# Incident Investigation (Core Analysis) 
# Investigation Goal
The goal of this phase is to answer the BOTSv3 200-series questions using SPL while applying a structured SOC investigation methodology. Each question is treated as a security investigation rather than a simple query.
________________________________________

# Standard Investigation Methodology
## For every question, the following process was applied consistently:
- The investigation objective was defined.
- The correct sourcetype was identified.
- An SPL query was written and refined.
- Results were validated through field and event analysis.
- Screenshots were captured as evidence.
- Findings were recorded along with SOC relevance.
- This disciplined approach reflects professional SOC investigation standards.
________________________________________

# Q200: List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment
## Investigation Explanation
To identify IAM users accessing AWS services, AWS CloudTrail logs were analyzed. CloudTrail records both successful and failed API activity, making it the authoritative source for identity-based access investigations. By filtering for IAM user activity, all identities interacting with Frothly’s AWS environment can be enumerated.
The field userIdentity.type=IAMUser ensures that only IAM users are included, excluding roles and services.
## SPL Query
index=botsv3 sourcetype=aws:cloudtrail userIdentity.type=IAMUser
| stats values(userName)

## Answer
### bstoll, btun, splunk_access, web_admin
## Evidence
![IAM users accessing AWS services](screenshots/screenshots/aws/q200.png)
### IAM users accessing AWS services
________________________________________

# Q201: What field would you use to alert that AWS API activity has occurred without MFA?
## Investigation Explanation
AWS API activity is recorded in CloudTrail events with the event type AwsApiCall. To determine whether MFA was used during authentication, the session context fields were examined. The field userIdentity.sessionContext.attributes.mfaAuthenticated explicitly indicates whether MFA was enforced.
This field is critical for SOC alerting because API activity without MFA significantly increases risk.
## SPL Query
index=botsv3 sourcetype=aws:cloudtrail eventType=AwsApiCall

## Answer
### userIdentity.sessionContext.attributes.mfaAuthenticated
## Evidence
![MFA authentication field highlighted]( screenshots/screenshots/aws/q201_1.png)
![MFA authentication field highlighted]( screenshots/screenshots/aws/q201_2.png)
 ### MFA authentication field highlighted
________________________________________


# Q202: What is the processor number used on the web servers?
## Investigation Explanation
To identify hardware details of the web servers, system telemetry logs were analyzed. The hardware sourcetype contains processor and system-level information. Reviewing the CPU-related fields reveals the processor model used by the web servers.
## SPL Query
index=botsv3 sourcetype=hardware

## Answer
### E5-2676
## Evidence
![CPU type field showing Intel Xeon E5-2676]( screenshots/screenshots/aws/q202.png)
### CPU type field showing Intel Xeon E5-2676
________________________________________

# Q204: Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access?
## Investigation Explanation
Public access to an S3 bucket is typically enabled through changes to the bucket’s Access Control List (ACL). According to AWS documentation, this action is performed using the PutBucketAcl API call. By searching for ACL modification events, the exact API call responsible for exposing the bucket can be identified.
## SPL Query
index=botsv3 sourcetype=aws:cloudtrail (putbucketacl OR "put-bucket-acl")

## Answer
### ab45689d-69cd-41e7-8705-5350402cf7ac
## Evidence
![Event ID confirming public S3 access]( screenshots/screenshots/aws/q204_1.png)
![Event ID confirming public S3 access]( screenshots/screenshots/aws/q204_2.png)
![Event ID confirming public S3 access]( screenshots/screenshots/aws/q204_3.png) 
### Event ID confirming public S3 access
________________________________________

# Q205: What is Bud's username?
## Investigation Explanation
Using the same CloudTrail events that modified the S3 bucket ACL, the userName field was examined to identify the responsible IAM user. The username clearly maps to Bud.
## SPL Query
index=botsv3 sourcetype=aws:cloudtrail (putbucketacl OR "put-bucket-acl")
| table userName

## Answer
### bstoll
## Evidence

![userName field showing bstoll]( screenshots/screenshots/aws/q205.png)
### userName field showing bstoll
________________________________________

# Q206: What is the name of the S3 bucket that was made publicly accessible?
## Investigation Explanation
Within the same ACL modification event, the bucket name is recorded in the request parameters. This identifies which resource was exposed.
## SPL Query
index=botsv3 sourcetype=aws:cloudtrail (putbucketacl OR "put-bucket-acl")

## Answer
### frothlywebcode
________________________________________


# Q207: What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible?
## Investigation Explanation
To identify files uploaded during the exposure window, S3 access logs were analyzed. A successful file upload corresponds to a PUT operation with an HTTP status code of 200. The uploaded object name appears in the request URI.
## SPL Query
index=botsv3 sourcetype=aws:s3:accesslogs bucket_name=frothlywebcode operation="REST.PUT.OBJECT" http_status=200
| table request_uri

## Answer
### OPEN_BUCKET_PLEASE_FIX.txt
## Evidence
![Uploaded file name in S3 access logs]( screenshots/screenshots/aws/q207.png) 
### Uploaded file name in S3 access logs
________________________________________

# Q208: What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?
## Investigation Explanation
Endpoint operating system information was reviewed using Windows host monitoring logs. Most systems were running Windows 10 Pro, but one endpoint was running Windows 10 Enterprise. Additional event logs were used to resolve the full domain name of this system.
## SPL Query
index=botsv3 sourcetype=winhostmon source=operatingsystem
| table OS, host
| dedup host

index=botsv3 sourcetype=wineventlog BSTOLL-L

### Answer
BSTOLL-L.froth.ly
## Evidence
![OS comparison and FQDN identification]( screenshots/screenshots/aws/q208.png)
![OS comparison and FQDN identification]( screenshots/screenshots/aws/q208_1.png)
### OS comparison and FQDN identification
________________________________________

# Q209: What is the second process to reach 100% CPU utilization during coin mining activity?
## Investigation Explanation
High CPU utilization is a common indicator of cryptocurrency mining. Performance monitoring logs were analyzed to identify processes reaching 100% CPU usage. Sorting events chronologically reveals the order in which processes consumed maximum CPU.
## SPL Query
index=botsv3 sourcetype="Perfmon:Process" process_cpu_used_percent=100
| table _time process_name host
| sort _time

## Answer
### chrome#5
## Evidence
![CPU utilization timeline]( screenshots/screenshots/aws/q209.png)
### CPU utilization timeline
________________________________________


# Q210: What is the short hostname of the only Frothly endpoint to actually mine Monero cryptocurrency?
## Investigation Explanation
The endpoint responsible for sustained high CPU utilization and mining activity was identified from previous performance analysis.
## Answer
BSTOLL-L
________________________________________

# Q211: What is the first seen signature ID of the coin miner threat according to Symantec Endpoint Protection?
## Investigation Explanation
Symantec Endpoint Protection logs were analyzed and sorted chronologically to identify the earliest detected signature ID associated with the coin miner.
## SPL Query
index=botsv3 sourcetype="symantec:ep:security:file"
| table _time CIDS_Signature_ID
| sort _time

## Answer
### 30358
Evidence
![Earliest signature ID]( screenshots/screenshots/aws/q211.png)
### Earliest signature ID
________________________________________

# Q212: What is the name of the attack?
## Investigation Explanation
Using the identified signature ID, the corresponding event description was reviewed to determine the malware name.
## SPL Query
index=botsv3 sourcetype="symantec:ep:security:file"
| table Event_Description
| dedup Event_Description

## Answer
### JSCoinminer Download 8
## Evidence
![Attack name field]( screenshots/screenshots/aws/q212.png)
### Attack name field
________________________________________

# Q213: According to Symantec, what is the severity of this coin miner threat?
## Investigation Explanation
Severity information was obtained directly from the Symantec Endpoint Protection event data, ensuring accuracy relative to the time of the incident.
## Answer
### Medium
## Evidence
![Severity field]( screenshots/screenshots/aws/q213_1.png)
![Severity field]( screenshots/screenshots/aws/q213_2.png)
### Severity field
________________________________________

# Q214: What is the short hostname of the endpoint that successfully defeated the threat?
## Investigation Explanation
One endpoint showed evidence of blocking the attack. Reviewing host-level SEP logs identifies the system that successfully mitigated the threat.
## SPL Query
index=botsv3 sourcetype="symantec:ep:security:file"
| table Event_Description Host_Name
| dedup Event_Description

## Answer
### BTUN-L
## Evidence
![Blocked attack confirmation]( screenshots/screenshots/aws/q214.png)
### Blocked attack confirmation
________________________________________

# Q215: What IAM access key generated the most distinct errors when accessing IAM resources?
## Investigation Explanation
Failed IAM API calls were analyzed and grouped by access key. The access key producing the highest number of distinct error messages indicates misuse or compromise.
## SPL Query
index=botsv3 sourcetype=aws:cloudtrail eventSource="iam.amazonaws.com" errorCode!=success
| stats dc(errorMessage) by userIdentity.accessKeyID user

## Answer
### AKIAJOGCDXJ5NW5PXUPA
## Evidence
![Distinct error count by access key](screenshots/screenshots/aws/q215.png) 
### Distinct error count by access key
________________________________________


# Q216: What is the AWS support case ID opened after the account compromise?
## Investigation Explanation
AWS notified Bud via email regarding the compromise. Email traffic was searched to locate the AWS support case reference.
## SPL Query
index=botsv3 sourcetype="stream:smtp" bstoll@froth.ly *aws* *case*

## Answer
### 5244329601
## Evidence
![AWS support email](screenshots/screenshots/aws/q216.png) 
### AWS support email
________________________________________

# Q217: What is the leaked secret access key?
## Investigation Explanation
The AWS notification referenced an external repository containing exposed credentials. Reviewing the repository revealed the leaked secret key.
## Answer
### Bx8/gTsYC98T0oWiFhpmdROqhELPtXJSR9vFPNGk
## Evidence
![Leaked secret key](screenshots/screenshots/aws/q217.png) 
### Leaked secret key
________________________________________

# Q218: What resource did the adversary attempt to create a key for?
## Investigation Explanation
CloudTrail logs were searched for failed key creation attempts using the leaked access key.
## SPL Query
index=botsv3 sourcetype=aws:cloudtrail userIdentity.accessKeyId=AKIAJOGCDXJ5NW5PXUPA eventName=CreateAccessKey

## Answer
### nullweb_admin
## Evidence
![Unauthorized CreateAccessKey attempt](screenshots/screenshots/aws/q218.png)
### Unauthorized CreateAccessKey attempt
________________________________________

# Q219: What is the full user agent of the application used in the unauthorized account description attempt?
## Investigation Explanation
The leaked key was used to attempt to describe AWS account attributes. The user agent field identifies the tool used by the adversary.
## SPL Query
index=botsv3 sourcetype=aws:cloudtrail userIdentity.accessKeyId=AKIAJOGCDXJ5NW5PXUPA eventName=DescribeAccountAttributes

## Answer
### ElasticWolf/5.1.6
## Evidence
![User agent field](screenshots/screenshots/aws/q219.png) 
### User agent field

________________________________________

# Conclusion & References 
# Key Findings and Lessons Learned
This project demonstrates how a combination of exposed credentials, cloud misconfigurations, and weak authentication controls can rapidly escalate into serious security incidents if left undetected. Through the BOTSv3 dataset, multiple real-world attack patterns were observed, including IAM credential misuse, public S3 bucket exposure, unauthorized API activity, and endpoint compromise via cryptocurrency mining malware.
One of the most critical lessons learned is the risk posed by leaked cloud credentials. The investigation showed how a single exposed AWS access key, once committed to an external code repository, enabled an adversary to perform unauthorized reconnaissance and access attempts across AWS services. This reinforces the importance of strong secrets management, continuous credential monitoring, and automated key rotation.
The project also highlights how cloud misconfigurations, such as publicly accessible S3 buckets, can lead to unintended data exposure. Even accidental configuration changes can introduce attack surfaces that adversaries actively scan for. Proper cloud security posture management, least-privilege access controls, and continuous auditing are essential to mitigate these risks.
From an endpoint security perspective, the detection of cryptocurrency mining activity emphasized the value of performance and behavior-based monitoring. High CPU utilization served as a key indicator of compromise, allowing correlation between system performance logs and endpoint protection alerts to confirm malicious activity.
From a SOC operational standpoint, this project reinforces several core principles:
- The importance of centralized logging to maintain visibility across cloud, endpoint, and security tools
- The effectiveness of log correlation across multiple data sources rather than relying on a single alert
- The value of a structured, repeatable investigation methodology when handling incidents
- The necessity of clear documentation and evidence preservation for auditability and client reporting
Overall, this project reflects real-world SOC workflows where analysts must reconstruct events post-incident, validate findings through logs, and clearly communicate technical results in a professional format. The approach used throughout this investigation aligns with industry best practices for detection, investigation, and root-cause analysis
________________________________________

# References (IEEE Style)
-  Splunk Inc., “Boss of the SOC v3 Dataset,” 2023.
-  Amazon Web Services, “AWS CloudTrail Documentation.”
-  IST, “Computer Security Incident Handling Guide (SP 800-61).”
-  roadcom, “Symantec Endpoint Protection Threat Intelligence.”
________________________________________

# Final Statement
This repository represents a complete SOC-style investigation using industry-standard tools and methodologies. It demonstrates practical incident analysis skills, structured thinking, and professional documentation suitable for enterprise SOC environments and client-facing security engagements.






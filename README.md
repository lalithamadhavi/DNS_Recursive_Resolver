# DNS_Recursive_Resolver
The Domain Name System (DNS), which acts as the Internet's phone book, is a crucial
component of the internet. So that machines can load the resources without the user having to
memorize the IP address of their desired sites, DNS converts domain names to IP addresses. But
most DNS traffic consists of UDP-based queries and unencrypted answers.
DNS was invented about 30 years ago. So, security and privacy concerns are not initially taken
into consideration. As DNS responses and queries are not encrypted, they can be used to block
traffic, track user internet behavior, and spoof IPs in phishing scams and DNS cache poisoning
attacks. The implementation of security and privacy features is occurring as the internet
advances to its present level.
Here, I have implemented a DNS recursive resolver in Linux with an assortment of security and
privacy enhancements against DNS cache poisoning attacks, censorship using Unbound 1.9.4
and a python script which mimics a recursive resolver using dnspython library.

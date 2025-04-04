+++
authors = ["Matt Johnson"]
title = 'ADFS WAP: Resolve TCP reset errors connected to wildcard certificate usage'
date = '2025-02-12'
description = "ADFS is a confusing technology that frequently causes frustration. This post documents an instance of that and hopefully helps someone else along the way."
draft = false
tags = ["microsoft","adfs"]
summary = "ADFS is a confusing technology that frequently causes frustration. This post documents an instance of that and hopefully helps someone else along the way."
+++
Hello to the fourteen people who will inevitably stumble upon this article,

Long time no write! I wanted to make a short post about a problem I came across in a customer environment recently related to ADFS Web Application Proxy (WAP), TLS Server Name Indication (SNI), and lazy documentation from Microsoft.

The long and short of the problem was that a customer had recently added a new ADFS server as well as Web Application Proxy (WAP) server to their ADFS farm and were having issues where internal authentication attempts against the ADFS server went through just fine, but external authentication attempts (e.g. via WAP) could not connect to the server, receiving only TCP resets in reply to the TLS Hello packets.

The whole issue can basically be summarized by this high quality meme that I created, though if it's not clear enough feel free to skip to the solution section and ignore the ramblings.

{{< figure src="patrick_meme_adfs.png">}}

# What didn't work

We ended up spinning our wheels on the issue for quite a while, as there were lots of rabbit holes to fall into. First off, the trust between the ADFS server and its WAP was broken. Fixed that, didn't help. Next, we found that the ADFS service account didn't have appropriate permissions to the private key of the service communications certificate. Fixed that, didn't help. I had a feeling that the ADFS Farm being in a "mixed" state with both 2012R2 and 2022 servers could be causing issues, so we decommissioned the 2012R2 servers as they were no longer necessary. This allowed us to raise the farm's level to 4. No dice though, problem was still there.

Those were the main things, but many other attempts were tried, all of which were unsuccessful. TLS configurations were checked, /etc/hosts was updated to rule out any DNS issues, etc. But unfortunately nothing helped.

# The solution

If it wasn't clear from the meme, the solution was to explicitly tell the Web Application Proxy server to use the wildcard certificate for all connections, even if the certificate doesn't match the domain name explicitly. 

To get ahead of any know-it-alls, his is technically documented by Microsoft in [AD FS 2016 Requirements](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-requirements). "Certificate contains the federation service name, such as fs.contoso.com in the Subject or Subject Alternative Name (SAN)." It is further documented in the "Perform a detailed WAP check" section of the [AD FS Troubleshooting - Users can't log in using AD FS from an external network](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-extranet#perform-a-detailed-wap-check), if somewhat lazily.

The main issue I ran into is that the specific behavior exhibited by the WAP and how it is solved specifically are documented nowhere, so I wanted to solve that problem myself and document the solution.

AD FS 2016 (and 2019, 2022, 2025) have very specific requirements regarding TLS SNIs. The expectation is that if your ADFS service runs under `fs.contoso.com`, it expects that you'll provide a certificate with the exact SNI of `fs.contoso.com`. A wildcard certificate, despite being perhaps the most common way of implementing ADFS, will not work without a little bit of massaging. The WAP will see `*.contoso.com` and instead of recognizing that `fs.contoso.com` is included in that, it will simply say "nope, that's not me" and won't use the certificate. To get around this, you have to explicitly add an IP/Port binding to the certificate such that any connection to the service (as designated by the App ID), whether it be via an internal hostname, the service name, or via IP address, will be recognized as valid and use the wildcard certificate.

To do so, execute the following Powershell as an administrator on the Web Application Proxy Server:

Get the current IP/Port bindings: 

`netsh http show sslcert`

If you determine that there is no standard binding for 0.0.0.0:443, set one via the following command: 

`netsh http add sslcert ipport=0.0.0.0:443 appid='{5d89a20c-beab-4389-9447-324788eb944a}' certhash=<thumbprint of your wildcard certificate>`

That's literally it. Just a public service announcement so that at least one person on this earth will be spared the effort of having to figure this out the hard way. Hope it helps!
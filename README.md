# Cross_Site_Scripting_Defense

## What is a Cross_Site Scripting Attack?: 🗣️  

A Cross-Site Scripting (XSS) attack happens when a hacker tricks a website into showing harmful code—usually JavaScript—to other users. This works if 
the website doesn’t properly check or clean up user input, like comments or search boxes. When someone visits the affected page, the malicious code runs
in their browser as if it came from the trusted site. This could allow malicious actors to steal sensitive data, hijack user sessions or run additional malicious scripts. 

---  

##  🛠️ What This Does: 

This program started out as a vulnerable web-service that could fall prey to a cross-site scripting attack, and had some security features applied to it, so it is no longer vulnerable
to this type of attack, as well as some others. 

➤ **Input Whitelisting**:** This service only allows input of a certain nature, specifically preventing JavaScript from being injected into it. 

➤ **HTTP Strict-Transport Security Policy**:** This means that connections can only be made to the service using HTT**S**, which means that all of the application data is encrypted when being sent
between devices. Which means that someone cannot simply take a packet sniffer and intercept, and then read the contents of the transmissions

➤ **Content Security Policy (Set To Self)**:** This means that this service will only load scripts comming from it's own domain, providing an extra layer of security against cross-site scripting attacks. 



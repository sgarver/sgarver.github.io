---
layout: post
author: _tephen
updated: "2024-09-16"
---
Legacy versions of Ivanti Connect Secure are affected by several CVE's.

I created a simple NSE script to detect an unpatched Ivanti Connect Secure installations.

The logic is Based on the check function used in this Metasploit Framework module:  
exploit/linux/http/ivanti_connect_secure_rce_cve_2024_21893

Related CVEs:

- [CVE-2024-29847](https://www.cve.org/CVERecord?id=CVE-2024-29847) 10 Critical
- [CVE-2023-39336](https://www.cve.org/CVERecord?id=CVE-2023-39336) 9.6 Critical
- [CVE-2024-21887](https://www.cve.org/CVERecord?id=CVE-2024-21887) 9.1 Critical
- [CVE-2024-21893](https://www.cve.org/CVERecord?id=CVE-2024-21893) 8.2 High
- [CVE-2023-46805](https://www.cve.org/CVERecord?id=CVE-2023-46805) 8.2 High

Background:

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [cve.org](https://www.cve.org)
- [Invanti Security Advisory](https://forums.ivanti.com/s/article/Security-Advisory-EPM-September-2024-for-EPM-2024-and-EPM-2022)
- [Bleeping Compouter (Blog Post)](https://www.bleepingcomputer.com/news/security/ivanti-fixes-maximum-severity-rce-bug-in-endpoint-management-software/)

```lua
-- ivanti-unpatched.nse
local http = require("http")
local nmap = require("nmap")

portrule = function(host, port)
  local auth_port = { number = 443, protocol = "tcp" }
  local identd = nmap.get_port_state(host, auth_port)

  return identd ~= nil and identd.state == "open" and port.protocol == "tcp" and port.state == "open"
end

function is_ivanti_unpatched(host, port)
  local response = http.get(host.ip, port.number, "/status")

  return string.find(response.body, "Pulse Secure")
end

action = function(host, port)
  if is_ivanti_unpatched(host, port) then
    return "Unpatched"
  else
    return "Unknown"
  end
end
```

```sh
$ nmap -sV -p443 --script ivanti-unpatched.nse 127.0.0.1

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-15 11:12 PDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000057s latency).

PORT    STATE SERVICE VERSION
443/tcp open  http    SimpleHTTPServer 0.6 (Python 3.12.3)
|_http-server-header: SimpleHTTP/0.6 Python/3.12.3
|_ivanti-unpatched: Patched

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.16 seconds
```



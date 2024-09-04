---
layout: post
author: _tephen
---
A Custom Selenium Version Checker for Nmap.

In the ever-evolving world of cybersecurity, vigilance is key. We've crafted a powerful custom script for the Nmap Scripting Engine (NSE) that acts as a detective, pinpointing running instances of Selenium Server. Why does this matter? Because these instances can be a hotbed for malicious activity, including the notorious SeleniumGreed crypto-miner.

SeleniumGreed, a cunning exploit, leverages insecure Selenium Servers to hijack resources for cryptocurrency mining. This script is your first line of defense, helping you spot potential threats before they can wreak havoc.

For a deep dive into SeleniumGreed and strategies to protect your systems, be sure to check out the comprehensive guide on the [official Selenium blog](https://www.selenium.dev/blog/2024/protecting-unsecured-selenium-grid/). Your security deserves nothing less.

```lua
local http = require("http")
local json = require("json")
local nmap = require("nmap")
local oops = require("oops")
local shortport = require("shortport")
local stdnse = require("stdnse")
local table = require("table")

portrule = function(host, port)
  local auth_port = { number = 4444, protocol = "tcp" }
  local identd = nmap.get_port_state(host, auth_port)

  return identd ~= nil and identd.state == "open" and port.protocol == "tcp" and port.state == "open"
end

function get_selenium_version(host, port)
  local response = http.get(host.ip, port.number, "/status")
  local status, body = json.parse(response.body)

  for key, val in pairs(body.value.nodes) do
    return val.version
  end

  return status
end

action = function(host, port)
  local version = get_selenium_version(host, port)

  if version then
    return version
  end

  return nil
end
```

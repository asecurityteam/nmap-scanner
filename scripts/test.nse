local stdnse = require "stdnse"
local table = require "table"
local shortport = require "shortport"

description = [[
Shows AFP server information. This information includes the server's
hostname, IPv4 and IPv6 addresses, and hardware type (for example
<code>Macmini</code> or <code>MacBookPro</code>).
]]

author = "Test"
license = "TEST LICENSE"
categories = {"default", "discovery", "safe"}
portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = stdnse.output_table()
    local subresult = stdnse.output_table()
    subresult["id"] = "IDENTIFIER"
    subresult["description"] = "A VULNERABILITY"
    subresult["product"] = "A JIRA MAYBE?"
    subresult["productVersion"] = "0.1.0"
    subresult["link"] = "https://localhost"
    result[1] = subresult
    result[2] = subresult
    return result
end

ByteBender is a powerful Burp Suite extension that allows you to bend, twist, and reshape your HTTP traffic with precision. It provides advanced string replacement capabilities, supporting multiple search and replace rules, and works seamlessly with various content types including JSON and XML.
Features

Multiple Search and Replace Rules: Define and manage multiple rules for complex request modifications.
Flexible Targeting: Apply rules to specific parts of the request (headers, URL parameters, body).
Content Type Support: Special handling for JSON and XML content, allowing deep modifications in structured data.
Tool Scope: Choose which Burp tools to apply the rules (Proxy, Scanner, Repeater).
Regular Expression Support: Use regex patterns for more powerful search and replace operations.
Real-time Rule Management: Add, edit, or delete rules on the fly without restarting Burp Suite.
Request Logging: Keep track of modified requests for easy review and debugging.

Tool GUI
![image](https://github.com/user-attachments/assets/50c96ad1-e722-47cf-a6cc-32e00ba0ef15)

**Installation**

Ensure you have Burp Suite installed (ByteBender is compatible with both the Community and Professional editions).
Download the ByteBender.py file from this repository.
In Burp Suite, go to the "Extender" tab.
Click on "Add" in the "Extensions" tab.
Set "Extension Type" to Python.
Select the ByteBender.py file you downloaded.
Click "Next" and the extension should load without errors.

**Usage**

After installation, you'll find a new tab named "ByteBender" in Burp Suite.
In the ByteBender tab:

Enter a match string and replace string in the provided fields.
Select the search type (Normal or Regex).
Choose which Burp tools to apply the rule to (Proxy, Scanner, Repeater).
Select where to apply the rule (Headers, URL Parameters, Body).
Click "Add Rule" to create a new rule.


Manage your rules using the "Edit Rule" and "Delete Rule" buttons.
Enable the extension using the "Enable Extension" button when you're ready to apply your rules.
Send requests through Burp Suite as normal, and ByteBender will modify them according to your rules.
Review modified requests in the log table at the bottom of the ByteBender tab.

**Advanced Usage**
JSON and XML Handling
ByteBender automatically detects JSON and XML content types and applies special processing:

For JSON: Modifies both keys and values in the JSON structure.
For XML: Modifies element tags, attribute names and values, and text content.

This allows for deep modifications in complex API requests and responses.

**Regular Expressions**
When using the "Regex" search type, you can leverage powerful regex patterns. For example:

^Bearer\s+(.*)$ could match and replace entire Authorization headers.
"id"\s*:\s*"(\d+)" could target specific JSON fields.

**Troubleshooting**

If rules are not applying, check if the extension is enabled and if the correct modules and locations are selected.
For JSON/XML modifications, ensure the content type is correctly set in the request headers.
Check the Burp Suite Extender output for any error messages if the extension is not functioning as expected.

**License**
ByteBender is released under the MIT License. See the LICENSE file for details.

**Disclaimer**
This tool is intended for use in authorized security testing only. Users are responsible for complying with applicable laws and regulations.

Create by Aditya Singh

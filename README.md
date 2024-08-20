# ByteBender: Advanced HTTP Request Manipulation Extension for Burp Suite

## Introduction

ByteBender is a powerful extension for Burp Suite that provides advanced HTTP request manipulation capabilities. It offers a comprehensive set of features designed to enhance your web application testing and security assessment workflows.

![image](https://github.com/user-attachments/assets/eca9d23e-6b53-4f34-99de-806a91452a47)

## Key Features

- **Flexible Rule Creation**: Develop complex search and replace rules using string matching or regular expressions.
- **Targeted Modification**: Apply rules to headers, URL parameters, and body content (including JSON and XML).
- **Conditional Execution**: Implement conditions for precise control over rule application.
- **Tool-Specific Application**: Choose specific Burp Suite tools (Proxy, Scanner, Repeater, Intruder) for rule execution.
- **Scope Control**: Option to limit rule application to in-scope requests as defined in Burp Suite.
- **Dynamic Rule Management**: Add, edit, delete, and reorder rules in real-time without restarting the extension.
- **Request Logging**: Track modified requests with before and after comparisons.
- **Built-in Regex Tester**: Efficiently test and refine regular expressions within the extension.
- **Import/Export Functionality**: Easily save, load, and share rule sets.
- **Performance Metrics**: Monitor rule application frequency and effectiveness.

## Installation

1. Ensure Jython is installed in Burp Suite.
2. Download the `ByteBender.py` file from this repository.
3. In Burp Suite, navigate to the "Extender" tab and select "Add".
4. Choose Python as the extension type and select the `ByteBender.py` file.
5. Click "Next" to complete the installation.

## User Interface Overview

ByteBender's interface is divided into two main sections:

### Left Panel
- Rule creation inputs (Match String, Replace String, Search Type, Condition)
- Tool and component selection checkboxes
- Rule list display
- Control buttons (Add Rule, Enable/Disable Extension, In-Scope Only, Import/Export Rules, Show Statistics)

### Right Panel
- Log table of modified requests
- Request and response viewers:
  - Original Request
  - Modified Request
  - Response
- Regex testing tool

## Rule Creation and Management

1. **Creating Rules**:
   - Enter the match string, replace string, and optional condition.
   - Select the search type (Normal or Regex).
   - Click "Add Rule".

2. **Editing Rules**:
   - Select a rule from the list.
   - Click "Edit Rule" to populate the input fields.
   - Modify as needed and click "Add Rule" to update.

3. **Deleting Rules**:
   - Select a rule from the list.
   - Click "Delete Rule".

4. **Reordering Rules**:
   - Use "Move Up" or "Move Down" buttons to adjust rule priority.

## Rule Application Logic

Rules are applied based on:
- Selected Burp Suite tools
- Chosen request components
- Search type (string matching or regex)
- Specified conditions (if any)

## Scope Functionality

The "In-Scope Only" option restricts rule application to URLs within the Burp Suite's defined scope.

## Logging and History

- The log table displays requests modified by ByteBender.
- Selecting a log entry shows the original request, modified request, and response in respective tabs.

## Regular Expression Tester

The built-in tool allows users to:
1. Input test text
2. Specify a regex pattern
3. View matching results in real-time

This feature aids in developing and refining regular expressions for use in rules.

## Data Management

- **Export Rules**: Save current rule sets to JSON format.
- **Import Rules**: Load previously saved rule sets for easy sharing and backup.

## Performance Considerations

ByteBender is engineered for optimal performance:
- Efficient rule application algorithms
- Multi-threaded processing for concurrent requests
- Optimized regular expression handling

## Advantages over Similar Tools

1. **Versatility**: Combines string replacement and regular expressions with conditional logic.
2. **Seamless Integration**: Fully integrates with Burp Suite's existing functionality and scope controls.
3. **Intuitive Interface**: User-friendly design for managing complex rules.
4. **Granular Control**: Apply rules to specific tools, request components, and data structures.
5. **Integrated Regex Testing**: Eliminates the need for external regex testing tools.
6. **Dynamic Updates**: Modify rules without restarting the extension or Burp Suite.
7. **Optimized Performance**: Designed for efficiency in complex manipulation scenarios.

---


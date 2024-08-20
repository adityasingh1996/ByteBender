#Author: Aditya Singh
from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController
from javax.swing import (JPanel, JTextField, JButton, JCheckBox, JLabel, JComboBox, BoxLayout, JScrollPane, BorderFactory, JTable, ListSelectionModel, JSplitPane, JTabbedPane, JTextArea, JList, DefaultListModel, JFileChooser, JOptionPane)
from javax.swing.table import AbstractTableModel
from java.awt import GridBagLayout, GridBagConstraints, Color, Dimension, BorderLayout
from java.awt import Insets, Font
from java.util import ArrayList
import re
from java.net import URLEncoder, URLDecoder
import json
import xml.etree.ElementTree as ET
import threading
from java.util.concurrent import Executors, TimeUnit

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController):
    
    
    
    def toggleInScope(self, event):
        self._inScopeOnly = self._inScopeCheckBox.isSelected()
        print("In-Scope Only mode: " + ("Enabled" if self._inScopeOnly else "Disabled"))
        
    def __init__(self):
        self._inScopeOnly = False   
        
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ByteBender")
    
        self._rules = []
        self._isEnabled = False
        self._inProxy = False
        self._inScanner = False
        self._inRepeater = False
        self._inIntruder = False
        self._inHeaders = False
        self._inUrlParams = False
        self._inBodyParams = False
        self._logEntries = ArrayList()
        self._currentlyDisplayedItem = None
        self._scope = []
        self._ruleStats = {}
        self._undoStack = []
    
        self._executor = Executors.newFixedThreadPool(10)  
    
        self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        leftPanel = JPanel(BorderLayout())
        leftPanel.setPreferredSize(Dimension(600, 800))  
    
        controlPanel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.insets = Insets(5, 5, 5, 5)
    
        
        inputPanel = JPanel(GridBagLayout())
        inputC = GridBagConstraints()
        inputC.fill = GridBagConstraints.HORIZONTAL
        inputC.insets = Insets(2, 2, 2, 2)
    
        inputC.gridx = 0
        inputC.gridy = 0
        inputPanel.add(JLabel("Match String:"), inputC)
    
        inputC.gridx = 1
        self._matchField = JTextField(20)
        inputPanel.add(self._matchField, inputC)
    
        inputC.gridx = 0
        inputC.gridy = 1
        inputPanel.add(JLabel("Replace String:"), inputC)
    
        inputC.gridx = 1
        self._replaceField = JTextField(20)
        inputPanel.add(self._replaceField, inputC)
    
        inputC.gridx = 0
        inputC.gridy = 2
        inputPanel.add(JLabel("Search Type:"), inputC)
    
        inputC.gridx = 1
        self._searchTypeCombo = JComboBox(["Normal", "Regex"])
        inputPanel.add(self._searchTypeCombo, inputC)
    
        inputC.gridx = 0
        inputC.gridy = 3
        inputPanel.add(JLabel("Condition:"), inputC)
    
        inputC.gridx = 1
        self._conditionField = JTextField(20)
        inputPanel.add(self._conditionField, inputC)
    
        c.gridx = 0
        c.gridy = 0
        c.gridwidth = 2
        controlPanel.add(inputPanel, c)
    
        
        checkboxPanel = JPanel()
        checkboxPanel.setLayout(BoxLayout(checkboxPanel, BoxLayout.Y_AXIS))
    
        toolPanel = JPanel()
        toolPanel.setLayout(BoxLayout(toolPanel, BoxLayout.X_AXIS))
        self._proxyBox = JCheckBox("Proxy", actionPerformed=self.settingsChanged)
        self._scannerBox = JCheckBox("Scanner", actionPerformed=self.settingsChanged)
        self._repeaterBox = JCheckBox("Repeater", actionPerformed=self.settingsChanged)
        self._intruderBox = JCheckBox("Intruder", actionPerformed=self.settingsChanged)
        toolPanel.add(self._proxyBox)
        toolPanel.add(self._scannerBox)
        toolPanel.add(self._repeaterBox)
        toolPanel.add(self._intruderBox)
        checkboxPanel.add(toolPanel)
    
        locationPanel = JPanel()
        locationPanel.setLayout(BoxLayout(locationPanel, BoxLayout.X_AXIS))
        self._headersBox = JCheckBox("Headers", actionPerformed=self.settingsChanged)
        self._urlParamsBox = JCheckBox("URL Parameters", actionPerformed=self.settingsChanged)
        self._bodyParamsBox = JCheckBox("Body Parameters", actionPerformed=self.settingsChanged)
        locationPanel.add(self._headersBox)
        locationPanel.add(self._urlParamsBox)
        locationPanel.add(self._bodyParamsBox)
        checkboxPanel.add(locationPanel)
    
        c.gridx = 0
        c.gridy = 1
        c.gridwidth = 2
        controlPanel.add(checkboxPanel, c)
    
        
        buttonPanel = JPanel(GridBagLayout())
        buttonC = GridBagConstraints()
        buttonC.fill = GridBagConstraints.HORIZONTAL
        buttonC.insets = Insets(2, 2, 2, 2)
    
        buttonC.gridx = 0
        buttonC.gridy = 0
        addRuleButton = JButton("Add Rule", actionPerformed=self.addRule)
        buttonPanel.add(addRuleButton, buttonC)
    
        buttonC.gridx = 1
        self._enableButton = JButton("Enable Extension", actionPerformed=self.toggleExtension)
        self._enableButton.setBorder(BorderFactory.createLineBorder(Color.RED))
        buttonPanel.add(self._enableButton, buttonC)
    
        buttonC.gridx = 0
        buttonC.gridy = 1
        self._inScopeCheckBox = JCheckBox("In-Scope Only", actionPerformed=self.toggleInScope)
        buttonPanel.add(self._inScopeCheckBox, buttonC)
    
        buttonC.gridx = 1
        exportButton = JButton("Export Rules", actionPerformed=self.exportRules)
        buttonPanel.add(exportButton, buttonC)
    
        buttonC.gridx = 0
        buttonC.gridy = 2
        importButton = JButton("Import Rules", actionPerformed=self.importRules)
        buttonPanel.add(importButton, buttonC)
    
        buttonC.gridx = 1
        statsButton = JButton("Show Stats", actionPerformed=self.showStatistics)
        buttonPanel.add(statsButton, buttonC)
    
        c.gridx = 2
        c.gridy = 0
        c.gridheight = 2
        controlPanel.add(buttonPanel, c)
    
        leftPanel.add(controlPanel, BorderLayout.NORTH)
        
        self._ruleListModel = DefaultListModel()
        self._ruleList = JList(self._ruleListModel)
        ruleScrollPane = JScrollPane(self._ruleList)
        ruleScrollPane.setBorder(BorderFactory.createTitledBorder("Search and Replace Rules"))
        
        ruleButtonPanel = JPanel()
        editRuleButton = JButton("Edit Rule", actionPerformed=self.editRule)
        deleteRuleButton = JButton("Delete Rule", actionPerformed=self.deleteRule)
        moveUpButton = JButton("Move Up", actionPerformed=self.moveRuleUp)
        moveDownButton = JButton("Move Down", actionPerformed=self.moveRuleDown)
        ruleButtonPanel.add(editRuleButton)
        ruleButtonPanel.add(deleteRuleButton)
        ruleButtonPanel.add(moveUpButton)
        ruleButtonPanel.add(moveDownButton)
    
        rulePanel = JPanel(BorderLayout())
        rulePanel.add(ruleScrollPane, BorderLayout.CENTER)
        rulePanel.add(ruleButtonPanel, BorderLayout.SOUTH)
    
        leftPanel.add(rulePanel, BorderLayout.CENTER)
    
        self._splitpane.setLeftComponent(leftPanel)
    
        rightPanel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        rightPanel.setResizeWeight(0.5)
        
        self._logTableModel = LogTableModel(self)
        self._logTable = LogTable(self, self._logTableModel)
        rightPanel.setTopComponent(JScrollPane(self._logTable))
    
        tabs = JTabbedPane()
        
        self._originalRequestViewer = callbacks.createMessageEditor(self, False)
        self._modifiedRequestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        self._regexTesterPanel = self.createRegexTesterPanel()
        
        tabs.addTab("Original Request", self._originalRequestViewer.getComponent())
        tabs.addTab("Modified Request", self._modifiedRequestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        tabs.addTab("Regex Tester", self._regexTesterPanel)
        
        rightPanel.setBottomComponent(tabs)
        
        self._splitpane.setRightComponent(rightPanel)
    
        self._splitpane.setDividerLocation(1000)
    
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
    
        print("Extension loaded successfully")

    def getTabCaption(self):
        return "ByteBender"

    def getUiComponent(self):
        return self._splitpane

    def addRule(self, event):
        matchString = self._matchField.getText()
        replaceString = self._replaceField.getText()
        searchType = self._searchTypeCombo.getSelectedItem()
        condition = self._conditionField.getText()
        rule = (matchString, replaceString, searchType, condition)
        self._rules.append(rule)
        self._ruleListModel.addElement("{0} -> {1} ({2}) [{3}]".format(matchString, replaceString, searchType, condition))
        self._ruleStats[matchString] = 0
        self.clearInputFields()

    def editRule(self, event):
        selectedIndex = self._ruleList.getSelectedIndex()
        if selectedIndex != -1:
            rule = self._rules[selectedIndex]
            self._matchField.setText(rule[0])
            self._replaceField.setText(rule[1])
            self._searchTypeCombo.setSelectedItem(rule[2])
            self._conditionField.setText(rule[3])
            self._rules.pop(selectedIndex)
            self._ruleListModel.remove(selectedIndex)

    def deleteRule(self, event):
        selectedIndex = self._ruleList.getSelectedIndex()
        if selectedIndex != -1:
            rule = self._rules.pop(selectedIndex)
            self._ruleListModel.remove(selectedIndex)
            del self._ruleStats[rule[0]]

    def moveRuleUp(self, event):
        selectedIndex = self._ruleList.getSelectedIndex()
        if selectedIndex > 0:
            rule = self._rules.pop(selectedIndex)
            self._rules.insert(selectedIndex - 1, rule)
            self._ruleListModel.remove(selectedIndex)
            self._ruleListModel.add(selectedIndex - 1, "{0} -> {1} ({2}) [{3}]".format(rule[0], rule[1], rule[2], rule[3]))
            self._ruleList.setSelectedIndex(selectedIndex - 1)

    def moveRuleDown(self, event):
        selectedIndex = self._ruleList.getSelectedIndex()
        if selectedIndex < len(self._rules) - 1:
            rule = self._rules.pop(selectedIndex)
            self._rules.insert(selectedIndex + 1, rule)
            self._ruleListModel.remove(selectedIndex)
            self._ruleListModel.add(selectedIndex + 1, "{0} -> {1} ({2}) [{3}]".format(rule[0], rule[1], rule[2], rule[3]))
            self._ruleList.setSelectedIndex(selectedIndex + 1)

    def clearInputFields(self):
        self._matchField.setText("")
        self._replaceField.setText("")
        self._searchTypeCombo.setSelectedIndex(0)
        self._conditionField.setText("")

    def settingsChanged(self, event):
        if self._isEnabled:
            self._isEnabled = False
            self._enableButton.setText("Enable Extension")
            self._enableButton.setBorder(BorderFactory.createLineBorder(Color.RED))
        print("Settings changed")

    def toggleExtension(self, event):
        self._isEnabled = not self._isEnabled
        self._enableButton.setText("Disable Extension" if self._isEnabled else "Enable Extension")
        self._enableButton.setBorder(BorderFactory.createLineBorder(Color.GREEN if self._isEnabled else Color.RED))
        self._inProxy = self._proxyBox.isSelected()
        self._inScanner = self._scannerBox.isSelected()
        self._inRepeater = self._repeaterBox.isSelected()
        self._inIntruder = self._intruderBox.isSelected()
        self._inHeaders = self._headersBox.isSelected()
        self._inUrlParams = self._urlParamsBox.isSelected()
        self._inBodyParams = self._bodyParamsBox.isSelected()
        print("Extension toggled.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._isEnabled:
            return
    
        if messageIsRequest:
            if (toolFlag == self._callbacks.TOOL_PROXY and self._inProxy) or \
            (toolFlag == self._callbacks.TOOL_SCANNER and self._inScanner) or \
            (toolFlag == self._callbacks.TOOL_REPEATER and self._inRepeater) or \
            (toolFlag == self._callbacks.TOOL_INTRUDER and self._inIntruder):
                
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                url = requestInfo.getUrl()
                
                if self._inScopeOnly and not self._callbacks.isInScope(url):
                    return
                
                headers = list(requestInfo.getHeaders())
                body = messageInfo.getRequest()[requestInfo.getBodyOffset():]
                
                originalRequest = messageInfo.getRequest()
                
                modified = False
                
                for rule in self._rules:
                    matchString, replaceString, searchType, condition = rule
                    
                    if not self.checkCondition(condition, requestInfo):
                        continue
                    
                    if self._inHeaders:
                        newHeaders, headersModified = self.processHeaders(headers, searchType, matchString, replaceString)
                        headers = newHeaders
                        modified = modified or headersModified
                    
                    if self._inUrlParams:
                        newFirstHeader, urlModified = self.processUrlParams(headers[0], searchType, matchString, replaceString)
                        headers[0] = newFirstHeader
                        modified = modified or urlModified
                    
                    if self._inBodyParams:
                        contentType = self.getContentType(headers)
                        if contentType == "application/json":
                            newBody, bodyModified = self.processJsonBody(body, searchType, matchString, replaceString)
                        elif contentType == "application/xml":
                            newBody, bodyModified = self.processXmlBody(body, searchType, matchString, replaceString)
                        else:
                            newBody, bodyModified = self.processBodyParams(body, searchType, matchString, replaceString)
                        body = newBody
                        modified = modified or bodyModified
                    
                    if modified:
                        self._ruleStats[matchString] += 1
                
                if modified:
                    newMessage = self._helpers.buildHttpMessage(headers, body)
                    messageInfo.setRequest(newMessage)
                    self.logReplacement(messageInfo, originalRequest, newMessage)
                    self._undoStack.append((messageInfo, originalRequest))
        else:
            self.updateLogEntryWithResponse(messageInfo)

    def getContentType(self, headers):
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":")[1].strip().lower()
        return ""

    def processHeaders(self, headers, searchType, matchString, replaceString):
        modified = False
        for i in range(1, len(headers)):
            parts = headers[i].split(': ', 1)
            if len(parts) == 2:
                key, value = parts
                newKey = self.processString(key, searchType, matchString, replaceString)
                newValue = self.processString(value, searchType, matchString, replaceString)
                if newKey != key or newValue != value:
                    headers[i] = "{0}: {1}".format(newKey, newValue)
                    modified = True
        return headers, modified

    def processUrlParams(self, requestLine, searchType, matchString, replaceString):
        parts = requestLine.split(' ')
        if len(parts) < 2 or '?' not in parts[1]:
            return requestLine, False
        
        url = parts[1]
        path, params = url.split('?', 1)
        newParams, modified = self.processParams(params, searchType, matchString, replaceString)
        
        if modified:
            parts[1] = "{0}?{1}".format(path, newParams)
            return ' '.join(parts), True
        
        return requestLine, False

    def processBodyParams(self, body, searchType, matchString, replaceString):
        bodyStr = self._helpers.bytesToString(body)
        newBodyStr, modified = self.processParams(bodyStr, searchType, matchString, replaceString)
        return self._helpers.stringToBytes(newBodyStr), modified

    def processParams(self, params, searchType, matchString, replaceString):
        pairs = params.split('&')
        newPairs = []
        modified = False
        for pair in pairs:
            if '=' not in pair:
                newPairs.append(pair)
                continue
            key, value = pair.split('=', 1)
            
            newKey = self.processString(key, searchType, matchString, replaceString)
            decodedValue = URLDecoder.decode(value, "UTF-8")
            newValue = self.processString(decodedValue, searchType, matchString, replaceString)
            
            if newKey != key or newValue != decodedValue:
                modified = True
            
            encodedValue = URLEncoder.encode(newValue, "UTF-8")
            newPairs.append("{0}={1}".format(newKey, encodedValue))
        
        return '&'.join(newPairs), modified

    def processString(self, input_string, searchType, matchString, replaceString):
        if searchType == "Normal":
            return input_string.replace(matchString, replaceString)
        elif searchType == "Regex":
            return re.sub(matchString, replaceString, input_string)
        return input_string

    def processJsonBody(self, body, searchType, matchString, replaceString):
        try:
            bodyStr = self._helpers.bytesToString(body)
            jsonData = json.loads(bodyStr)
            modified = self.processJsonObject(jsonData, searchType, matchString, replaceString)
            if modified:
                return self._helpers.stringToBytes(json.dumps(jsonData)), True
        except json.JSONDecodeError:
            print("Failed to parse JSON body")
        return body, False

    def processJsonObject(self, obj, searchType, matchString, replaceString):
        modified = False
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                newKey = self.processString(key, searchType, matchString, replaceString)
                if newKey != key:
                    obj[newKey] = obj.pop(key)
                    modified = True
                if isinstance(obj[newKey], (dict, list)):
                    modified |= self.processJsonObject(obj[newKey], searchType, matchString, replaceString)
                elif isinstance(obj[newKey], str):
                    newValue = self.processString(obj[newKey], searchType, matchString, replaceString)
                    if newValue != obj[newKey]:
                        obj[newKey] = newValue
                        modified = True
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    modified |= self.processJsonObject(item, searchType, matchString, replaceString)
                elif isinstance(item, str):
                    newItem = self.processString(item, searchType, matchString, replaceString)
                    if newItem != item:
                        obj[i] = newItem
                        modified = True
        return modified

    def processXmlBody(self, body, searchType, matchString, replaceString):
        try:
            bodyStr = self._helpers.bytesToString(body)
            root = ET.fromstring(bodyStr)
            modified = self.processXmlElement(root, searchType, matchString, replaceString)
            if modified:
                return self._helpers.stringToBytes(ET.tostring(root, encoding='unicode')), True
        except ET.ParseError:
            print("Failed to parse XML body")
        return body, False

    def processXmlElement(self, element, searchType, matchString, replaceString):
        modified = False
        
        newTag = self.processString(element.tag, searchType, matchString, replaceString)
        if newTag != element.tag:
            element.tag = newTag
            modified = True
        
        for attrName, attrValue in list(element.attrib.items()):
            newAttrName = self.processString(attrName, searchType, matchString, replaceString)
            newAttrValue = self.processString(attrValue, searchType, matchString, replaceString)
            if newAttrName != attrName or newAttrValue != attrValue:
                del element.attrib[attrName]
                element.attrib[newAttrName] = newAttrValue
                modified = True
        
        if element.text and element.text.strip():
            newText = self.processString(element.text, searchType, matchString, replaceString)
            if newText != element.text:
                element.text = newText
                modified = True
        
        for child in element:
            modified |= self.processXmlElement(child, searchType, matchString, replaceString)
        
        return modified

    def logReplacement(self, messageInfo, originalRequest, modifiedRequest):
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        logEntry = LogEntry(url, originalRequest, modifiedRequest, None)
        self._logEntries.add(0, logEntry)
        if self._logEntries.size() > 30:  
            self._logEntries.remove(self._logEntries.size() - 1)
        self._logTableModel.fireTableDataChanged()

    def updateLogEntryWithResponse(self, messageInfo):
        response = messageInfo.getResponse()
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        for logEntry in self._logEntries:
            if logEntry._url == url and logEntry._response is None:
                logEntry._response = response
                self._logTableModel.fireTableDataChanged()
                break

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService() if self._currentlyDisplayedItem else None

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest() if self._currentlyDisplayedItem else None

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse() if self._currentlyDisplayedItem else None

    def exportRules(self, event):
        rules = json.dumps(self._rules)
        fileChooser = JFileChooser()
        if fileChooser.showSaveDialog(self._splitpane) == JFileChooser.APPROVE_OPTION:
            with open(fileChooser.getSelectedFile().getPath(), 'w') as f:
                f.write(rules)

    def importRules(self, event):
        fileChooser = JFileChooser()
        if fileChooser.showOpenDialog(self._splitpane) == JFileChooser.APPROVE_OPTION:
            with open(fileChooser.getSelectedFile().getPath(), 'r') as f:
                rules = json.loads(f.read())
                self._rules = rules
                self._ruleListModel.clear()
                for rule in rules:
                    self._ruleListModel.addElement("{0} -> {1} ({2}) [{3}]".format(rule[0], rule[1], rule[2], rule[3]))
                    self._ruleStats[rule[0]] = 0

    def isInScope(self, url):
        return len(self._scope) == 0 or any(scope in url.toString() for scope in self._scope)

    def checkCondition(self, condition, requestInfo):
        if not condition:
            return True
        try:
            headers = requestInfo.getHeaders()
            url = requestInfo.getUrl().toString()
            method = requestInfo.getMethod()
            return eval(condition)
        except:
            return False

    def undoLastModification(self, event):
        if self._undoStack:
            messageInfo, originalRequest = self._undoStack.pop()
            messageInfo.setRequest(originalRequest)
            JOptionPane.showMessageDialog(self._splitpane, "Last modification undone")

    def showStatistics(self, event):
        statsMessage = "Rule application statistics:\n\n"
        for rule, count in self._ruleStats.items():
            statsMessage += "{0}: {1} times\n".format(rule, count)
        JOptionPane.showMessageDialog(self._splitpane, statsMessage)

    def createRegexTesterPanel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        inputLabel = JLabel("Input Text:")
        self._regexInput = JTextArea(5, 30)
        inputScroll = JScrollPane(self._regexInput)

        patternLabel = JLabel("Regex Pattern:")
        self._regexPattern = JTextField(30)

        resultLabel = JLabel("Matches:")
        self._regexResult = JTextArea(5, 30)
        self._regexResult.setEditable(False)
        resultScroll = JScrollPane(self._regexResult)

        testButton = JButton("Test Regex", actionPerformed=self.testRegex)

        panel.add(inputLabel)
        panel.add(inputScroll)
        panel.add(patternLabel)
        panel.add(self._regexPattern)
        panel.add(testButton)
        panel.add(resultLabel)
        panel.add(resultScroll)

        return panel

    def testRegex(self, event):
        input_text = self._regexInput.getText()
        pattern = self._regexPattern.getText()
        try:
            matches = re.findall(pattern, input_text)
            self._regexResult.setText("Matches found: " + str(matches))
        except re.error as e:
            self._regexResult.setText("Invalid regex: " + str(e))

class LogEntry:
    def __init__(self, url, originalRequest, modifiedRequest, response):
        self._url = url
        self._originalRequest = originalRequest
        self._modifiedRequest = modifiedRequest
        self._response = response

class LogTableModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getRowCount(self):
        return self._extender._logEntries.size()

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._extender._logEntries.get(rowIndex)
        if columnIndex == 0:
            return logEntry._url.toString()
        return ""

class LogTable(JTable):
    def __init__(self, extender, logTableModel):
        self._extender = extender
        self.setModel(logTableModel)
        self.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.getSelectionModel().addListSelectionListener(self.logSelection)

    def logSelection(self, e):
        if e.getValueIsAdjusting():
            return
        row = self.getSelectedRow()
        if row != -1:
            logEntry = self._extender._logEntries.get(row)
            self._extender._originalRequestViewer.setMessage(logEntry._originalRequest, True)
            self._extender._modifiedRequestViewer.setMessage(logEntry._modifiedRequest, True)
            self._extender._responseViewer.setMessage(logEntry._response, False)
            self._extender._currentlyDisplayedItem = logEntry

    def changeSelection(self, row, col, toggle, extend):
        logEntry = self._extender._logEntries.get(row)
        self._extender._originalRequestViewer.setMessage(logEntry._originalRequest, True)
        self._extender._modifiedRequestViewer.setMessage(logEntry._modifiedRequest, True)
        self._extender._responseViewer.setMessage(logEntry._response, False)
        self._extender._currentlyDisplayedItem = logEntry
        JTable.changeSelection(self, row, col, toggle, extend)

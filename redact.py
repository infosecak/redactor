from burp import IBurpExtender, IHttpListener, IContextMenuFactory
from java.io import PrintWriter
from javax.swing import JMenuItem
import re

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        self._callbacks.setExtensionName("Redact Selected Text")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)
        
        self.redaction_map = {}  # Store redaction rules per message
        
        self._stdout.println("Redact Selected Text extension loaded.")
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        message_id = id(messageInfo)
        if message_id in self.redaction_map and messageIsRequest:
            request = messageInfo.getRequest()
            modified_request = self.redact_text(request, self.redaction_map[message_id])
            if modified_request != request:
                messageInfo.setRequest(modified_request)
                self._stdout.println("Redaction applied to request.")
            else:
                self._stdout.println("No changes detected in request.")
    
    def redact_text(self, message, patterns):
        try:
            message_str = self._helpers.bytesToString(message)
            original_str = message_str  # Save original for comparison
            for pattern in patterns:
                message_str = message_str.replace(pattern, "[redacted]")
            
            if message_str != original_str:
                self._stdout.println("Redacted text applied successfully.")
                return self._helpers.stringToBytes(message_str)
            else:
                self._stdout.println("No redactions matched.")
                return message
        except Exception as e:
            self._stderr.println("Error while redacting: " + str(e))
            return message
    
    def createMenuItems(self, invocation):
        menu_item = JMenuItem("Redact Selected Text", actionPerformed=lambda x: self.add_redaction(invocation))
        return [menu_item]
    
    def add_redaction(self, invocation):
        try:
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages:
                return
            
            selected_text = self.get_selected_text(invocation)
            if not selected_text:
                self._stderr.println("No text selected for redaction.")
                return
            
            for messageInfo in selected_messages:
                message_id = id(messageInfo)
                if message_id not in self.redaction_map:
                    self.redaction_map[message_id] = []
                if selected_text not in self.redaction_map[message_id]:
                    self.redaction_map[message_id].append(selected_text)
                    self._stdout.println("Redacted: " + selected_text)
                    messageInfo.setRequest(self.redact_text(messageInfo.getRequest(), [selected_text]))
                    self._stdout.println("Request modified successfully.")
        except Exception as e:
            self._stderr.println("Error adding redaction: " + str(e))
    
    def get_selected_text(self, invocation):
        try:
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages:
                return None
            
            messageInfo = selected_messages[0]  # Get first selected message
            selection_bounds = invocation.getSelectionBounds()
            if not selection_bounds or len(selection_bounds) != 2:
                return None
            
            start, end = selection_bounds
            
            if invocation.getInvocationContext() in [
                invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                invocation.CONTEXT_MESSAGE_VIEWER_REQUEST
            ]:
                message = self._helpers.bytesToString(messageInfo.getRequest())
            else:
                message = self._helpers.bytesToString(messageInfo.getResponse())
            
            selected_text = message[start:end]
            self._stdout.println("Selected text: " + selected_text)
            return selected_text if start < end else None
        except Exception as e:
            self._stderr.println("Error getting selected text: " + str(e))
        return None

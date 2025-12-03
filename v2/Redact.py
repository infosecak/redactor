# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IContextMenuFactory, IMessageEditorTabFactory, IMessageEditorTab
from java.io import PrintWriter
from javax.swing import JMenuItem

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Redactor")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)

        self.redaction_map = {}  

        self._stdout.println("Redactor Extension loaded successfully.")

    def createMenuItems(self, invocation):
        menu_item = JMenuItem("Add to Redaction",
                              actionPerformed=lambda x: self.add_redaction(invocation))
        return [menu_item]

    def add_redaction(self, invocation):
        try:
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages:
                return

            selected_text = self.get_selected_text(invocation)
            if not selected_text:
                self._stderr.println("No text selected.")
                return

            for messageInfo in selected_messages:
                message_id = id(messageInfo)
                if message_id not in self.redaction_map:
                    self.redaction_map[message_id] = []

                if selected_text not in self.redaction_map[message_id]:
                    self.redaction_map[message_id].append(selected_text)
                    self._stdout.println("Redaction added: " + selected_text)

            # NOTE: No modification of the original request anymore
        except Exception as e:
            self._stderr.println("Error adding redaction: " + str(e))

    def get_selected_text(self, invocation):
        try:
            msg = invocation.getSelectedMessages()[0]
            start, end = invocation.getSelectionBounds()
            if start < end:
                data = self._helpers.bytesToString(msg.getRequest())
                return data[start:end]
            return None
        except:
            return None

    # DO NOT TOUCH REAL REQUEST ANYMORE
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        return  # Disabled request modification

    def createNewInstance(self, controller, editable):
        return RedactorTab(self, controller, editable)


class RedactorTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._controller = controller
        self._helpers = extender._helpers
        self._editor = extender._callbacks.createTextEditor()
        self._editor.setEditable(False)

    def getTabCaption(self):
        return "Redacted Request"

    def getUiComponent(self):
        return self._editor.getComponent()

    def isEnabled(self, content, isRequest):
        return isRequest

    def setMessage(self, content, isRequest):
        if content is None:
            self._editor.setText(None)
            return

        msg_str = self._helpers.bytesToString(content)
        redacted = msg_str

        # Apply stored patterns for this message only
        message_id = id(self._controller.getHttpService())
        for patterns in self._extender.redaction_map.values():
            for p in patterns:
                redacted = redacted.replace(p, "[redacted]")

        self._editor.setText(self._helpers.stringToBytes(redacted))

    def getMessage(self):   
        return None

    def isModified(self):
        return False

    def getSelectedData(self):
        return self._editor.getSelectedText()

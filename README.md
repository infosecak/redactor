## Overview

The Redactor extension for Burp Suite allows users to redact specific portions of HTTP requests by replacing selected text with [redacted]. This is useful for hiding sensitive information before sending, logging requests and hiding sensitive information in the Proof-of-concepts.

![redactor](https://github.com/user-attachments/assets/56385820-0efc-4dd2-86ce-750abfcb84d6)

## Features

1. Users can highlight text in Burp Suite's Request Editor.
2. Right-click and select "Redact Selected Text" to replace it with [redacted].
3. Works in Repeater, Intruder, and Proxy tools.
4. Provides real-time UI updates to ensure redactions apply instantly.
5. Logs redaction actions to the Burp Extender Output tab.

## Installation

1.	Open Burp Suite and navigate to the Extender tab.
2.	Click on Add and select the Python language.
3.	Load the redact.py script.
4.	Ensure the extension is enabled in the Loaded Extensions section.

## Usage

1.	Open a Request in Repeater.
2.	Highlight the text you want to redact.
3.	Right-click and select "Redact Selected Text" from the context menu.
4.	The selected text will be replaced with [redacted] immediately.
5.	Check the Extender Output tab for debugging logs.

## Troubleshooting

No Redaction Applied?
Ensure you are selecting text inside a request.
Verify that the modification appears in Repeater after selection.
Check Extender Output for messages like "No redactions matched."

## Note

This extension is provided as-is without any warranties. Use it responsibly and feel free to modify or extend it as needed.



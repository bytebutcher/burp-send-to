# Burp-Send-To-Extension

Adds a customizable "Send to..."-context-menu to your BurpSuite.

## Configuration

After loading the extension the "Send to"-Tab contains all necessary options to configure the "Send to"-context-menu. 

New context-menu-entries can be added using the "Add"-button. Each entry consists of following fields:
* Name: the name of the context-menu-entry
* Command: the command to be executed. You can use following placeholders:
	* %S: will be replaced with the selected text
	* %F: will be replaced with the path to a temporary file which contains the selected text
* Run in terminal: defines whether a terminal-window should appear in which the configured command is executed
* Show preview: gives you the chance to preview and change the command before executing it

![Burp-Send-To-Extension Tab](images/burp-send-to-extension-tab.png)

## Context-Menu

The context-menu contains all entries which were added in the "Send to"-Tab.
In addition you can add new entries via the "Custom command..."-context-menu-entry.

![Burp-Send-To-Extension Context-Menu](images/burp-send-to-extension-context-menu.png)

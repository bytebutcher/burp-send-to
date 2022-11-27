# Burp-Send-To-Extension

Adds a customizable "Send to..."-context-menu to your BurpSuite.

![Burp-Send-To-Extension Tab](images/burp-send-to-extension-intro.png)

## Configuration

After loading the extension the "Send to"-Tab contains all necessary options to configure the "Send to"-context-menu. 

New context-menu-entries can be added using the "Add"-button. Each entry consists of following fields:
* **Name:** the name of the context-menu-entry.
* **Command:** the command to be executed. You can use following placeholders:
	* **%H:** will be replaced with the host
	* **%P:** will be replaced with the port
	* **%T:** will be replaced with the protocol
	* **%U:** will be replaced with the url
	* **%A:** will be replaced with the url path
	* **%Q:** will be replaced with the url query
	* **%C:** will be replaced with the cookies
	* **%L:** will be replaced with the HTTP-content-length
	* **%M:** will be replaced with the HTTP-method
	* **%O:** will be replaced with the HTTP-status-code
	* **%S:** will be replaced with the selected text
	* **%F:** will be replaced with the path to a temporary file containing the selected text
	* **%R:** will be replaced with the path to a temporary file containing the content of the focused request/response
	* **%E:** will be replaced with the path to a temporary file containing the header of the focused request/response
	* **%B:** will be replaced with the path to a temporary file containing the body of the focused request/response
* **Group:** the name of the sub-menu in which this entry will be shown. Can be left blank.
* **Run in terminal:** defines whether a terminal-window should appear in which the configured command is executed. By default "xterm" is used as terminal-emulator. You can change the terminal-emulator in the "Miscellaneous Options" to your liking.
* **Show preview:** gives you the chance to preview and change the command before executing it.
* **Output should replace selection:** will replace the selection with the output of the to be executed command.

![Burp-Send-To-Extension Add-/Edit-Dialog](images/burp-send-to-extension-add-edit-dialog.png)

In addition it is possible to customize how placeholders behave when multiple HTTP messages are selected by clicking the "Advanced"-button. 
By default each selected HTTP message forms a separate command. However, it is also possible to join all values of a specific placeholder using a custom separator, or to store all values of a specific placeholder within a file.

![Burp-Send-To-Extension Advanced-Dialog](images/burp-send-to-extension-advanced-dialog.png)

After creating new context-menu-entries using the "Add"-button they can be edited or deleted again using the "Edit"- and "Remove"-button. In addition the order in which they appear in the context-menu can be altered using the "Up"- and "Down"-button.

![Burp-Send-To-Extension Tab](images/burp-send-to-extension-tab.png)

## Terminal Options

The "Terminal Options" allow to configure the graphical terminal to use. In addition it is possible to specify how multiple commands should be run in terminal. Multiple commands can either be run sequential in a single terminal or in parallel in separate terminals. While it's possible to choose a default behaviour, the exact behaviour can also be selected via a dialog, everytime a send-to context menu entry is selected. However, if you prefer one behaviour all the time, this dialog can also be disabled.

## Context-Menu

The "Send to..." context-menu contains all entries which were added in the "Send to"-Tab.
In addition you can add new entries via the "Custom command..."-context-menu-entry.

#### Request Field

![Burp-Send-To-Extension Context-Menu](images/burp-send-to-extension-context-menu-repeater.png)

#### Proxy History

![Burp-Send-To-Extension Context-Menu](images/burp-send-to-extension-context-menu-target-sitemap.png)

## Save and load options

Usually the options of the "Send to"-Tab are saved automatically. However, if you switch computers you may save and load your current options. This can be done by clicking on the gear-symbol in the upper-left corner of the "Send to"-Tab and select the appropriate context-menu-entry.

![Burp-Send-To-Extension Options](images/burp-send-to-extension-options.png)

## Extending the Extension

Not satisfied yet? The [Wiki Page](https://github.com/bytebutcher/burp-send-to/wiki/Examples) lists some additional context-menu entries which might come in handy.

## Security Notes

Executing commands based on untrusted input always introduces the risk of command injection. This is especially true when using the **%S** placeholder. Thus it is recommended to always activate the **Show preview** option when using the **%S** placeholder and closely analyse commands in the preview window prior to execution.

![Burp-Send-To-Extension Options](images/burp-send-to-extension-forkbomb.png)

## Build

This project was built using IntelliJ and Gradle. When you make changes to the source (and especially the GUI) you should apply following settings within Intellij to make sure that everything builds successfully:
* File -> Settings -> Editor -> GUI Designer -> Generate GUI into: Java source
* File -> Settings -> Build, Execution, Deployment -> Compiler -> Build project automatically
* File -> Settings -> Build, Execution, Deployment -> Build Tools -> Gradle -> Build and run using: IntelliJ IDEA

When the GUI is not updated correctly you may rebuild the project manually:
* Build -> Rebuild Project

After that you can execute the "fatJar"-task within the "build.gradle"-file. This will produce a jar in the "build/libs/" directory called "burp-send-to-extension-{version}.jar".

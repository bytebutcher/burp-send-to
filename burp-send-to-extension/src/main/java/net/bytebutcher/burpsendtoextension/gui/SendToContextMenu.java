package net.bytebutcher.burpsendtoextension.gui;

import burp.*;
import com.google.common.collect.*;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.utils.OsUtils;
import net.bytebutcher.burpsendtoextension.utils.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.util.*;

public class SendToContextMenu implements IContextMenuFactory {

    private BurpExtender burpExtender;
    private SendToTableListener sendToTableListener;
    private final List<JMenuItem> sendToMenuBar;
    private final JMenu sendToMenu;
    private IContextMenuInvocation invocation;

    public SendToContextMenu(BurpExtender burpExtender, SendToTableListener sendToTableListener) {
        this.burpExtender = burpExtender;
        this.sendToTableListener = sendToTableListener;
        this.sendToTableListener.registerCommandsChangeLister(new CommandsChangeListener() {
            @Override
            public void commandsChanged(List<CommandObject> commandObjects) {
                refreshSendToMenuBar(commandObjects);
            }
        });
        this.sendToMenuBar = new ArrayList<JMenuItem>();
        this.sendToMenu = new JMenu("Send to...");
        this.sendToMenuBar.add(this.sendToMenu);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.invocation = invocation;
        return sendToMenuBar;
    }

    private IRequestInfo getRequestInfo(IHttpRequestResponse req) {
        return burpExtender.getCallbacks().getHelpers().analyzeRequest(req.getHttpService(), req.getRequest());
    }

    private String getSelectedText() {
        String selectedText = null;
        int[] selectionBounds = this.invocation.getSelectionBounds();
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        byte iContext = invocation.getInvocationContext();
        if (selectionBounds != null) {
            IHttpRequestResponse iHttpRequestResponse = invocation.getSelectedMessages()[0];
            if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                    || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                selectedText = new String(iHttpRequestResponse.getRequest()).substring(selectionBounds[0], selectionBounds[1]);
            } else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
                    || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
                selectedText = new String(iHttpRequestResponse.getResponse()).substring(selectionBounds[0], selectionBounds[1]);
            }
        } else if (selectedMessages != null) {
            selectedText = getRequestInfo(selectedMessages[0]).getUrl().toString();
        }
        return selectedText;
    }

    private void replaceSelectedText(String replaceText) {
        if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            int[] bounds = invocation.getSelectionBounds();
            byte[] message = invocation.getSelectedMessages()[0].getRequest();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            try {
                outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                outputStream.write(replaceText.getBytes());
                outputStream.write(Arrays.copyOfRange(message, bounds[1],message.length));
                outputStream.flush();
                invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
            } catch (IOException e) {
                burpExtender.getCallbacks().printError("Error during replacing selection with output: " + e.toString());
            }
        }
    }

    public void refreshSendToMenuBar(final List<CommandObject> commandObjects) {
        sendToMenu.removeAll();
        sendToMenu.add(new JMenuItem(new AbstractAction("Custom command...") {
            @Override
            public void actionPerformed(ActionEvent e) {
                SendToAddDialog addDialog = new SendToAddDialog(
                        burpExtender.getParent(),
                        "Add and run custom command...",
                        commandObjects
                );
                if (addDialog.run()) {
                    CommandObject commandObject = addDialog.getCommandObject();
                    sendToTableListener.onAddButtonClick(e, commandObject);
                    String result = runCommandObject(commandObject);
                    if (commandObject.shouldOutputReplaceSelection() && result != null) {
                        replaceSelectedText(result);
                    }
                }
            }
        }));
        if (commandObjects.size() > 0) {
            sendToMenu.addSeparator();
            HashMap<String, java.util.List<CommandObject>> groupedCommandObjects = Maps.newLinkedHashMap();
            boolean hasEmptyGroup = false;
            for (final CommandObject commandObject : commandObjects) {
                String group = commandObject.getGroup();
                if (group.isEmpty()) {
                    sendToMenu.add(newCommandMenuItem(commandObject));
                    hasEmptyGroup = true;
                    continue;
                }
                if (!groupedCommandObjects.containsKey(group)) {
                    groupedCommandObjects.put(group, Lists.newArrayList());
                }
                groupedCommandObjects.get(group).add(commandObject);
            }
            if (hasEmptyGroup && !groupedCommandObjects.isEmpty()) {
                sendToMenu.addSeparator();
            }
            for (String group : groupedCommandObjects.keySet()) {
                JMenu menuItem = new JMenu(group);
                for (CommandObject commandObject : groupedCommandObjects.get(group)) {
                    menuItem.add(newCommandMenuItem(commandObject));
                }
                sendToMenu.add(menuItem);
            }
        }
        sendToMenuBar.add(sendToMenu);
    }

    private JMenuItem newCommandMenuItem(CommandObject commandObject) {
        return new JMenuItem(new AbstractAction(commandObject.getName()) {
            @Override
            public void actionPerformed(ActionEvent e) {
                String result = runCommandObject(commandObject);
                if (commandObject.shouldOutputReplaceSelection() && result != null) {
                    replaceSelectedText(result);
                }
            }
        });
    }

    private Set<String> getCommandNames(List<CommandObject> commandObjects) {
        Set<String> names = new HashSet<String>();
        for (CommandObject commandObject : commandObjects) {
            names.add(commandObject.getName());
        }
        return names;
    }

    private String runCommandObject(CommandObject commandObject) {
        try {
            String[] commandToBeExecuted = getCommandToBeExecuted(commandObject);
            if (commandToBeExecuted == null) {
                return null;
            }

            logCommandToBeExecuted(commandToBeExecuted);
            Process process = new ProcessBuilder(commandToBeExecuted).start();
            return StringUtils.fromInputStream(process.getInputStream());
        } catch (Exception e) {
            DialogUtil.showErrorDialog(
                    burpExtender.getParent(),
                    "Error during command execution!",
                    "<html><p>There was an unknown error during command execution!</p>" +
                            "<p>For more information check out the \"Send to\" extension error log!</p></html>"
            );
            burpExtender.getCallbacks().printError("Error during command execution: " + e);
            return null;
        }
    }

    private String[] getCommandToBeExecuted(CommandObject commandObject) throws IOException {
        return formatCommand(commandObject);
    }

    private String[] formatCommand(CommandObject commandObject) throws IOException {
        String[] commandToBeExecuted;
        String command = formatCommandPattern(commandObject.getCommand());

        if (commandObject.shouldShowPreview()) {
            SendToPreviewDialog previewDialog = new SendToPreviewDialog(
                    burpExtender.getParent(),
                    "Execute command?",
                    commandObject.getId(),
                    command,
                    sendToTableListener
            );
            if (!previewDialog.run()) {
                return null;
            }
            command = previewDialog.getCommand();
        }

        if (commandObject.isRunInTerminal()) {
            commandToBeExecuted = formatCommandForRunningInTerminal(command);
        } else {
            commandToBeExecuted = formatCommandRunningOnOperatingSystem(command);
        }
        return commandToBeExecuted;
    }

    private String[] formatCommandRunningOnOperatingSystem(String command) {
        String[] commandToBeExecuted;
        if (OsUtils.isWindows()) {
            commandToBeExecuted = new String[]{"cmd", "/c", command};
        } else {
            commandToBeExecuted = new String[]{"/bin/bash", "-c", command};
        }
        return commandToBeExecuted;
    }

    private String formatCommandPattern(String command) throws IOException {
        if (command.contains("%F")) {
            File tmp = writeTextToTemporaryFile(command);
            command = command.replace("%F", tmp.getAbsolutePath());
        }
        if (command.contains("%S")) {
            command = command.replace("%S", "'" + StringUtils.shellEscape(this.getSelectedText()) + "'");
        }
        return command;
    }

    private File writeTextToTemporaryFile(String command) throws IOException {
        File tmp = File.createTempFile("burp_", ".snd");
        PrintWriter out = new PrintWriter(tmp.getPath());
        out.write(this.getSelectedText());
        out.flush();
        return tmp;
    }

    private String[] formatCommandForRunningInTerminal(String command) throws IOException {
        String[] commandToBeExecuted = this.burpExtender.getConfig().getRunInTerminalCommand().split(" ");
        for (int i = 0; i < commandToBeExecuted.length; i++) {
            String commandPart = commandToBeExecuted[i];
            if ("%C".equals(commandPart)) {
                commandToBeExecuted[i] = command;
            }
        }
        return commandToBeExecuted;
    }

    private void logCommandToBeExecuted(String[] commandToBeExecuted) {
        String commandToBeExecutedWithoutControlCharacters = String.join(" ", commandToBeExecuted).replaceAll("[\u0000-\u001f]", "");
        burpExtender.getCallbacks().printOutput("CommandObject: " + commandToBeExecutedWithoutControlCharacters);
    }
}

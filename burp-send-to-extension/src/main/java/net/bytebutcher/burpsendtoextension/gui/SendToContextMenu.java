package net.bytebutcher.burpsendtoextension.gui;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.utils.OsUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

public class SendToContextMenu implements IContextMenuFactory {

    private BurpExtender burpExtender;
    private SendToTableListener sendToTableListener;
    private final List<JMenuItem> sendToMenuBar;
    private final JMenu sendToMenu;
    private String selectedText;

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
        this.selectedText = getSelectedText(invocation);
        return sendToMenuBar;
    }

    private String getSelectedText(IContextMenuInvocation invocation) {
        String selectedText = null;
        int[] selection = invocation.getSelectionBounds();
        byte iContext = invocation.getInvocationContext();
        if (selection != null) {
            IHttpRequestResponse iHttpRequestResponse = invocation.getSelectedMessages()[0];
            if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                    || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                selectedText = new String(iHttpRequestResponse.getRequest()).substring(selection[0], selection[1]);
            } else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
                    || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
                selectedText = new String(iHttpRequestResponse.getResponse()).substring(selection[0], selection[1]);
            }
        }
        return selectedText;
    }

    public void refreshSendToMenuBar(final List<CommandObject> commandObjects) {
        sendToMenu.removeAll();
        sendToMenu.add(new JMenuItem(new AbstractAction("Custom command...") {
            @Override
            public void actionPerformed(ActionEvent e) {
                SendToAddDialog addDialog = new SendToAddDialog(
                        burpExtender.getParent(),
                        "Add and run custom command...",
                        getCommandNames(commandObjects)
                );
                if (addDialog.run()) {
                    sendToTableListener.onAddButtonClick(e, addDialog.getCommandObject());
                    runCommandObject(addDialog.getCommandObject());
                }
            }
        }));
        if (commandObjects.size() > 0) {
            sendToMenu.addSeparator();
            for (final CommandObject commandObject : commandObjects) {
                sendToMenu.add(new JMenuItem(new AbstractAction(commandObject.getName()) {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        runCommandObject(commandObject);
                    }
                }));
            }
        }
        sendToMenuBar.add(sendToMenu);
    }

    private Set<String> getCommandNames(List<CommandObject> commandObjects) {
        Set<String> names = new HashSet<String>();
        for (CommandObject commandObject : commandObjects) {
            names.add(commandObject.getName());
        }
        return names;
    }

    private void runCommandObject(CommandObject commandObject) {
        try {
            String[] commandToBeExecuted = getCommandToBeExecuted(commandObject);
            if (commandToBeExecuted == null) {
                return;
            }

            logCommandToBeExecuted(commandToBeExecuted);
            new ProcessBuilder(commandToBeExecuted).start();
        } catch (Exception e) {
            DialogUtil.showErrorDialog(
                    burpExtender.getParent(),
                    "Error during command execution!",
                    "<html><p>There was an unknown error during command execution!</p>" +
                            "<p>For more information check out the \"Send to\" extension error log!</p></html>"
            );
            burpExtender.getCallbacks().printError("Error during command execution: " + e);
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
            command = command.replace("%S", this.selectedText);
        }
        return command;
    }

    private File writeTextToTemporaryFile(String command) throws IOException {
        File tmp = File.createTempFile("burp_", ".snd");
        PrintWriter out = new PrintWriter(tmp.getPath());
        out.write(this.selectedText);
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

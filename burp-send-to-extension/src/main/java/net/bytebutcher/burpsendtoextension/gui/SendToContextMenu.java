package net.bytebutcher.burpsendtoextension.gui;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Placeholders;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholder;
import net.bytebutcher.burpsendtoextension.utils.OsUtils;
import net.bytebutcher.burpsendtoextension.utils.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class SendToContextMenu implements IContextMenuFactory {

    private BurpExtender burpExtender;
    private SendToTableListener sendToTableListener;
    private final List<JMenuItem> sendToMenuBar;
    private final JMenu sendToMenu;
    private IContextMenuInvocation invocation;
    private List<Map<String, IPlaceholder>> placeholders = Lists.newArrayList();
    private List<CommandObjectMenuItem> menuItems = Lists.newArrayList();

    private class CommandObjectMenuItem extends JMenuItem {

        private final CommandObject commandObject;

        public CommandObjectMenuItem(Action a, CommandObject commandObject) {
            super(a);
            this.commandObject = commandObject;
        }

        public void refreshStatus(List<Map<String, IPlaceholder>> placeholders) {
            List<Map<String, IPlaceholder>> validEntries = commandObject.getValid(placeholders);
            if (placeholders.size() > 1) {
                setText(commandObject.getName() + " (" + validEntries.size() + "/" + placeholders.size() + ")");
            } else {
                setText(commandObject.getName());
            }
            setEnabled(validEntries.size() > 0);
        }
    }

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
        this.placeholders = Placeholders.get(burpExtender.getCallbacks(), invocation);
        refreshMenuItemsStatus(placeholders);
        return sendToMenuBar;
    }

    /**
     * Enables menu items when associated command object is valid, otherwise disables them.
     */
    private void refreshMenuItemsStatus(List<Map<String, IPlaceholder>> placeholders) {
        for (CommandObjectMenuItem menuItem : menuItems) {
            menuItem.refreshStatus(placeholders);
        }
    }

    private void replaceSelectedText(String replaceText) {
        try {
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                int[] bounds = invocation.getSelectionBounds();
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                outputStream.write(replaceText.getBytes());
                outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
                outputStream.flush();
                invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
            }
        } catch (IOException e) {
            burpExtender.getCallbacks().printError("Error during replacing selection with output: " + e.toString());
        }
    }

    public void refreshSendToMenuBar(final List<CommandObject> commandObjects) {
        menuItems.clear();
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
                    addMenuItem(sendToMenu, commandObject);
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
                    addMenuItem(menuItem, commandObject);
                }
                sendToMenu.add(menuItem);
            }
        }
        sendToMenuBar.add(sendToMenu);
    }

    private void addMenuItem(JMenu menu, CommandObject commandObject) {
        CommandObjectMenuItem menuItem = new CommandObjectMenuItem(new AbstractAction(commandObject.getName()) {
            @Override
            public void actionPerformed(ActionEvent e) {
                String result = runCommandObject(commandObject);
                if (commandObject.shouldOutputReplaceSelection() && result != null) {
                    replaceSelectedText(result);
                }
            }
        }, commandObject);
        menuItems.add(menuItem);
        menu.add(menuItem);
    }

    private String runCommandObject(CommandObject commandObject) {
        try {
            String[] commandToBeExecuted = getCommandToBeExecuted(commandObject);
            if (commandToBeExecuted == null) {
                return null;
            }

            logCommandToBeExecuted(commandToBeExecuted);
            Process process = new ProcessBuilder(commandToBeExecuted).start();
            if (commandObject.shouldOutputReplaceSelection()) {
                return StringUtils.fromInputStream(process.getInputStream());
            }
            return null;
        } catch (Exception e) {
            DialogUtil.showErrorDialog(
                    burpExtender.getParent(),
                    "Error during command execution!",
                    "<html><p>There was an unknown error during command execution!</p>" +
                            "<p>For more information check out the \"Send to\" extension error log!</p></html>"
            );
            BurpExtender.printErr("Error during command execution: " + e);
            BurpExtender.printErr(stackTraceToString(e));
            return null;
        }
    }

    private String stackTraceToString(Exception e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }

    private String[] getCommandToBeExecuted(CommandObject commandObject) throws Exception {
        return formatCommand(commandObject);
    }

    private String[] formatCommand(CommandObject commandObject) throws Exception {
        String[] commandToBeExecuted;
        String command = commandObject.getFormattedCommand(placeholders);

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

        if (commandObject.shouldRunInTerminal()) {
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
        String dateTime = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss"));
        BurpExtender.printOut("[" + dateTime + "] " + commandToBeExecutedWithoutControlCharacters);
        BurpExtender.printOut("----------------------------------------------------------------------");
    }
}

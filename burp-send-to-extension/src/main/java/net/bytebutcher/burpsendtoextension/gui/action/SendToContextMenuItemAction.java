package net.bytebutcher.burpsendtoextension.gui.action;

import burp.BurpExtender;
import net.bytebutcher.burpsendtoextension.builder.CommandBuilder;
import net.bytebutcher.burpsendtoextension.executioner.CommandExecutioner;
import net.bytebutcher.burpsendtoextension.gui.SendToPreviewDialog;
import net.bytebutcher.burpsendtoextension.gui.SendToRunInTerminalBehaviourChoiceDialog;
import net.bytebutcher.burpsendtoextension.gui.SendToTableListener;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.models.ERunInTerminalBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholderParser;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;

public class SendToContextMenuItemAction extends AbstractAction {

    private final CommandObject commandObject;
    private final List<Map<String, IPlaceholderParser>> placeholders;
    private final SendToTableListener sendToTableListener;
    private final Context context;

    public SendToContextMenuItemAction(String title, CommandObject commandObject, List<Map<String, IPlaceholderParser>> placeholders, SendToTableListener sendToTableListener, Context context) {
        super(title);
        this.commandObject = commandObject;
        this.placeholders = placeholders;
        this.sendToTableListener = sendToTableListener;
        this.context = context;
    }
    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            String command = new CommandBuilder(commandObject, placeholders, context).build();
            if (commandObject.shouldShowPreview()) {
                command = showSendToPreviewDialog(commandObject.getId(), command);
            }
            if (command == null) {
                return;
            }
            if (commandObject.shouldRunInTerminal()) {
                runCommandInTerminal(command);
            } else {
                runCommandInBackground(command);
            }
        } catch (Exception e1) {
            DialogUtil.showErrorDialog(
                    BurpExtender.getParent(),
                    "Error during command execution!",
                    "<html><p>There was an unknown error during command execution!</p>" +
                            "<p>For more information check out the \"Send to\" extension error log!</p></html>"
            );
            BurpExtender.printErr("Error during command execution: " + e1);
            BurpExtender.printErr(stackTraceToString(e1));
        }
    }

    private void runCommandInBackground(String command) throws Exception {
        new CommandExecutioner(commandObject.shouldOutputReplaceSelection(), context).execute(command);
    }

    private void runCommandInTerminal(String command) throws Exception {
        ERunInTerminalBehaviour runInTerminalBehaviour = BurpExtender.getConfig().getRunInTerminalBehaviour();
        boolean containsMultipleCommands = command.contains("\n");
        if (containsMultipleCommands && BurpExtender.getConfig().shouldShowRunInTerminalBehaviourChoiceDialog()) {
            SendToRunInTerminalBehaviourChoiceDialog.EChoice choice = null;
            while (choice != SendToRunInTerminalBehaviourChoiceDialog.EChoice.RUN_IN_SEPARATE_TERMINALS && choice != SendToRunInTerminalBehaviourChoiceDialog.EChoice.RUN_IN_SINGLE_TERMINAL) {
                choice = new SendToRunInTerminalBehaviourChoiceDialog(BurpExtender.getParent(), runInTerminalBehaviour, command.split("\n").length).run();
                switch (choice) {
                    case RUN_IN_SINGLE_TERMINAL:
                        runInTerminalBehaviour = ERunInTerminalBehaviour.RUN_IN_SINGLE_TERMINAL;
                        break;
                    case RUN_IN_SEPARATE_TERMINALS:
                        runInTerminalBehaviour = ERunInTerminalBehaviour.RUN_IN_SEPARATE_TERMINALS;
                        break;
                    case REVIEW_COMMANDS:
                        command = showSendToPreviewDialog(command);
                        if (command == null) {
                            return;
                        }
                    case CANCEL:
                        return;
                }
            }
        }
        new CommandExecutioner(runInTerminalBehaviour, commandObject.shouldOutputReplaceSelection(), context).execute(command);
    }

    private String showSendToPreviewDialog(String command) {
        SendToPreviewDialog previewDialog = new SendToPreviewDialog(BurpExtender.getParent(), "Review commands", command);
        return previewDialog.run() ? previewDialog.getCommand() : null;
    }

    private String showSendToPreviewDialog(String id, String command) throws Exception {
        SendToPreviewDialog previewDialog = new SendToPreviewDialog(
                BurpExtender.getParent(),
                "Execute command?",
                command, id,
                sendToTableListener
        );
        if (!previewDialog.run()) {
            return null;
        }
        return previewDialog.getCommand();
    }

    private String stackTraceToString(Exception e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }
}
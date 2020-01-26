package net.bytebutcher.burpsendtoextension.gui.action;

import burp.BurpExtender;
import burp.IContextMenuInvocation;
import net.bytebutcher.burpsendtoextension.gui.SendToPreviewDialog;
import net.bytebutcher.burpsendtoextension.gui.SendToTableListener;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.gui.util.SelectionUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholder;
import net.bytebutcher.burpsendtoextension.utils.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

public class SendToContextMenuItemAction extends AbstractAction {

    private final CommandObject commandObject;
    private final List<Map<String, IPlaceholder>> placeholders;
    private final IContextMenuInvocation invocation;
    private final SendToTableListener sendToTableListener;
    private final Context context;

    public SendToContextMenuItemAction(String title, CommandObject commandObject, List<Map<String, IPlaceholder>> placeholders, IContextMenuInvocation invocation, SendToTableListener sendToTableListener, Context context) {
        super(title);
        this.commandObject = commandObject;
        this.placeholders = placeholders;
        this.invocation = invocation;
        this.sendToTableListener = sendToTableListener;
        this.context = context;
    }
    @Override
    public void actionPerformed(ActionEvent e) {
        String result = runCommandObject(commandObject);
        if (commandObject.shouldOutputReplaceSelection() && result != null) {
            SelectionUtil.replaceSelectedText(invocation, result);
        }
    }

    private String runCommandObject(CommandObject commandObject) {
        try {
            String command = commandObject.getCommand(placeholders, context);
            if (commandObject.shouldShowPreview()) {
                command = showSendToPreviewDialog(commandObject.getId(), command);
            }

            if (command == null) {
                return null;
            }

            ProcessBuilder commandProcessBuilder = commandObject.getProcessBuilder(command);
            logCommandToBeExecuted(commandProcessBuilder.command().toArray(new String[commandProcessBuilder.command().size()]));
            Process process = commandProcessBuilder.start();
            if (commandObject.shouldOutputReplaceSelection()) {
                return StringUtils.fromInputStream(process.getInputStream());
            }
            return null;
        } catch (Exception e) {
            DialogUtil.showErrorDialog(
                    BurpExtender.getParent(),
                    "Error during command execution!",
                    "<html><p>There was an unknown error during command execution!</p>" +
                            "<p>For more information check out the \"Send to\" extension error log!</p></html>"
            );
            BurpExtender.printErr("Error during command execution: " + e);
            BurpExtender.printErr(stackTraceToString(e));
            return null;
        }
    }

    private String showSendToPreviewDialog(String id, String command) throws Exception {
        SendToPreviewDialog previewDialog = new SendToPreviewDialog(
                BurpExtender.getParent(),
                "Execute command?",
                id,
                command,
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

    private void logCommandToBeExecuted(String[] commandToBeExecuted) {
        String commandToBeExecutedWithoutControlCharacters = String.join(" ", commandToBeExecuted).replaceAll("[\u0000-\u001f]", "");
        String dateTime = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss"));
        BurpExtender.printOut("[" + dateTime + "] " + commandToBeExecutedWithoutControlCharacters);
        BurpExtender.printOut("----------------------------------------------------------------------");
    }
}
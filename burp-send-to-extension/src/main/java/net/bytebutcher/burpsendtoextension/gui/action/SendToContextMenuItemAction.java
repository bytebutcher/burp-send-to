package net.bytebutcher.burpsendtoextension.gui.action;

import burp.BurpExtender;
import net.bytebutcher.burpsendtoextension.executioner.CommandExecutioner;
import net.bytebutcher.burpsendtoextension.gui.SendToPreviewDialog;
import net.bytebutcher.burpsendtoextension.gui.SendToTableListener;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholder;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;

public class SendToContextMenuItemAction extends AbstractAction {

    private final CommandObject commandObject;
    private final List<Map<String, IPlaceholder>> placeholders;
    private final SendToTableListener sendToTableListener;
    private final Context context;

    public SendToContextMenuItemAction(String title, CommandObject commandObject, List<Map<String, IPlaceholder>> placeholders, SendToTableListener sendToTableListener, Context context) {
        super(title);
        this.commandObject = commandObject;
        this.placeholders = placeholders;
        this.sendToTableListener = sendToTableListener;
        this.context = context;
    }
    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            String command = commandObject.getCommand(placeholders, context);
            if (commandObject.shouldShowPreview()) {
                command = showSendToPreviewDialog(commandObject.getId(), command);
            }
            new CommandExecutioner(command, commandObject.shouldRunInTerminal(), commandObject.shouldOutputReplaceSelection(), context).execute();
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
}
package net.bytebutcher.burpsendtoextension.gui;

import net.bytebutcher.burpsendtoextension.gui.action.SendToContextMenuItemAction;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholderParser;

import javax.swing.*;
import java.util.List;
import java.util.Map;

public class SendToContextMenuItem extends JMenuItem {

    public SendToContextMenuItem(String title, CommandObject commandObject, List<Map<String, IPlaceholderParser>> placeholders, Context context, SendToTableListener sendToTableListener) {
        String text = "";
        List<Map<String, IPlaceholderParser>> validEntries = commandObject.getValid(placeholders, context);
        if (placeholders.size() > 1) {
            text = title + " (" + validEntries.size() + "/" + placeholders.size() + ")";
        } else {
            text = title;
        }
        this.setAction(new SendToContextMenuItemAction(text, commandObject, placeholders, sendToTableListener, context));
        if (commandObject.shouldOutputReplaceSelection() && context.getSelectionBounds() == null) {
            // Always disable context menu item, when command should replace selection but no selection was made.
            this.setEnabled(false);
        } else {
            // Do only enable context menu item, when at least one HTTP-message can be used to construct the command.
            this.setEnabled(validEntries.size() > 0);
        }
    }

}

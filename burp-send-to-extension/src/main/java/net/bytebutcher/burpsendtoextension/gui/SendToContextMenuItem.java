package net.bytebutcher.burpsendtoextension.gui;

import burp.IContextMenuInvocation;
import net.bytebutcher.burpsendtoextension.gui.action.SendToContextMenuItemAction;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholder;

import javax.swing.*;
import java.util.List;
import java.util.Map;

public class SendToContextMenuItem extends JMenuItem {

    public SendToContextMenuItem(String title, CommandObject commandObject, List<Map<String, IPlaceholder>> placeholders, IContextMenuInvocation invocation, Context context, SendToTableListener sendToTableListener) {
        String text = "";
        List<Map<String, IPlaceholder>> validEntries = commandObject.getValid(placeholders, context);
        if (placeholders.size() > 1) {
            text = title + " (" + validEntries.size() + "/" + placeholders.size() + ")";
        } else {
            text = title;
        }
        this.setAction(new SendToContextMenuItemAction(text, commandObject, placeholders, invocation, sendToTableListener, context));
        this.setEnabled(validEntries.size() > 0);
    }

}

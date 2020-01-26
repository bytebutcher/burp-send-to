package net.bytebutcher.burpsendtoextension.gui;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.models.Placeholders;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholder;

import javax.swing.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SendToContextMenu implements IContextMenuFactory {

    private BurpExtender burpExtender;
    private SendToTableListener sendToTableListener;

    public SendToContextMenu(BurpExtender burpExtender, SendToTableListener sendToTableListener) {
        this.burpExtender = burpExtender;
        this.sendToTableListener = sendToTableListener;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<Map<String, IPlaceholder>> placeholders = Placeholders.get(BurpExtender.getCallbacks(), invocation);
        List<CommandObject> commandObjects = BurpExtender.getConfig().getSendToTableData();
        if (commandObjects.isEmpty()) {
            return Lists.newArrayList();
        }

        JMenu sendToMenu = new JMenu("Send to...");
        HashMap<String, List<CommandObject>> groupedCommandObjects = Maps.newLinkedHashMap();
        boolean hasEmptyGroup = false;
        for (final CommandObject commandObject : commandObjects) {
            String group = commandObject.getGroup();
            if (group.isEmpty()) {
                addMenuItem(sendToMenu, commandObject, placeholders, invocation);
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
                addMenuItem(menuItem, commandObject, placeholders, invocation);
            }
            sendToMenu.add(menuItem);
        }
        return  Lists.newArrayList(sendToMenu);
    }

    private void addMenuItem(JMenu menu, CommandObject commandObject, List<Map<String, IPlaceholder>> placeholders, IContextMenuInvocation invocation) {

        JMenuItem item;
        if (commandObject.doesRequireRequestResponse(placeholders.get(0)) && Context.getContext(invocation) == Context.UNKNOWN) {
            item = new JMenu(commandObject.getName());
            SendToContextMenuItem request = new SendToContextMenuItem("request", commandObject, placeholders, invocation, Context.HTTP_REQUEST, sendToTableListener);
            SendToContextMenuItem response = new SendToContextMenuItem("response", commandObject, placeholders, invocation, Context.HTTP_RESPONSE, sendToTableListener);
            item.add(request);
            item.add(response);
            item.setEnabled(request.isEnabled() || response.isEnabled());
        } else {
            item = new SendToContextMenuItem(commandObject.getName(), commandObject, placeholders, invocation, Context.getContext(invocation), sendToTableListener);
        }
        menu.add(item);
    }

}

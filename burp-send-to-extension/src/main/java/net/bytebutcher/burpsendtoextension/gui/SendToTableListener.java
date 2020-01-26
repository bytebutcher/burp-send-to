package net.bytebutcher.burpsendtoextension.gui;

import burp.BurpExtender;
import net.bytebutcher.burpsendtoextension.models.CommandObject;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

public class SendToTableListener implements TableModelListener {

    private SendToTable sendToTable;
    private List<CommandsChangeListener> commandsChangeListeners = new ArrayList<CommandsChangeListener>();

    public SendToTableListener(JTable table, SendToTable sendToTable, BurpExtender burpExtender) {
        this.sendToTable = sendToTable;
    }

    @Override
    public void tableChanged(TableModelEvent e) {
        List<CommandObject> commandObjects = sendToTable.getCommandObjects();
        for (CommandsChangeListener commandsChangeListener : commandsChangeListeners) {
            commandsChangeListener.commandsChanged(commandObjects);
        }
        BurpExtender.getConfig().saveSendToTableData(sendToTable.getCommandObjects());
    }

    public void onAddButtonClick(ActionEvent e, CommandObject commandObject) {
        sendToTable.addCommandObject(commandObject);
    }

    public void onEditButtonClick(ActionEvent e, CommandObject commandObject) {
        sendToTable.editSelectedCommandObject(commandObject);
    }

    public void onRemoveButtonClick(ActionEvent e) {
        sendToTable.removeSelectedRow();
    }

    public void onUpButtonClick(ActionEvent e) {
        sendToTable.moveSelectedRowUp();
    }

    public void onDownButtonClick(ActionEvent e) {
        sendToTable.moveSelectedRowDown();
    }

    public void registerCommandsChangeLister(CommandsChangeListener commandsChangeListener) {
        commandsChangeListeners.add(commandsChangeListener);
    }

    public void onShowPreviewChange(ActionEvent e, String commandId, boolean showPreview) {
        CommandObject commandObject = sendToTable.getCommandObjectById(commandId);
        commandObject.setShowPreview(showPreview);
        sendToTable.editCommandObject(commandObject);
    }
}

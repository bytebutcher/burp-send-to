package net.bytebutcher.burpsendtoextension.gui;

import burp.BurpExtender;
import com.google.gson.Gson;
import net.bytebutcher.burpsendtoextension.models.CommandObject;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

public class SendToTableListener implements TableModelListener {

    private SendToTable sendToTable;
    private final JTable table;
    private final DefaultTableModel model;
    private BurpExtender burpExtender;
    private List<CommandsChangeListener> commandsChangeListeners = new ArrayList<CommandsChangeListener>();

    SendToTableListener(JTable table, SendToTable sendToTable, BurpExtender burpExtender) {
        this.sendToTable = sendToTable;
        this.table = table;
        this.model = sendToTable.getDefaultModel();
        this.burpExtender = burpExtender;
    }

    @Override
    public void tableChanged(TableModelEvent e) {
        List<CommandObject> commandObjects = sendToTable.getCommandObjects();
        for (CommandsChangeListener commandsChangeListener : commandsChangeListeners) {
            commandsChangeListener.commandsChanged(commandObjects);
        }
        this.burpExtender.getConfig().saveSendToTableData(new Gson().toJson(sendToTable.getCommandObjects()));
    }

    void onAddButtonClick(ActionEvent e, CommandObject commandObject) {
        sendToTable.addCommandObject(commandObject);
    }

    void onEditButtonClick(ActionEvent e, CommandObject commandObject) {
        sendToTable.editSelectedCommandObject(commandObject);
    }

    void onRemoveButtonClick(ActionEvent e) {
        sendToTable.removeSelectedRow();
    }

    void onUpButtonClick(ActionEvent e) {
        sendToTable.moveSelectedRowUp();
    }

    void onDownButtonClick(ActionEvent e) {
        sendToTable.moveSelectedRowDown();
    }

    void registerCommandsChangeLister(CommandsChangeListener commandsChangeListener) {
        commandsChangeListeners.add(commandsChangeListener);
    }

    void onShowPreviewChange(ActionEvent e, String commandId, boolean showPreview) {
        CommandObject commandObject = sendToTable.getCommandObjectById(commandId);
        commandObject.setShowPreview(showPreview);
        sendToTable.editCommandObject(commandObject);
    }
}

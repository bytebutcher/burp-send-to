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

    public SendToTableListener(SendToTable sendToTable) {
        this.sendToTable = sendToTable;
    }

    @Override
    public void tableChanged(TableModelEvent e) {
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

    public void onShowPreviewChange(ActionEvent e, String commandId, boolean showPreview) {
        CommandObject commandObject = sendToTable.getCommandObjectById(commandId);
        commandObject.setShowPreview(showPreview);
        sendToTable.editCommandObject(commandObject);
    }
}

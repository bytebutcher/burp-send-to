package net.bytebutcher.burpsendtoextension.gui;

import burp.BurpExtender;
import com.google.common.collect.Lists;
import com.google.common.primitives.Ints;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.ERuntimeBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.PlaceholderBehaviour;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.*;
import java.util.stream.Collectors;

public class SendToTable extends JTable {

    private final DefaultTableModel defaultModel;
    private BurpExtender burpExtender;

    private enum Column {
        ID(0),
        NAME(1),
        COMMAND(2),
        GROUP(3),
        RUNTIME_BEHAVIOUR(4),
        SHOW_PREVIEW(5),
        PLACEHOLDER_BEHAVIOUR(6);

        private final int index;

        Column(int id) {
            this.index = id;
        }

        public int getIndex() {
            return index;
        }
    }

    public SendToTable(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;

        this.defaultModel = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        this.defaultModel.addColumn("Id");
        this.defaultModel.addColumn("Name");
        this.defaultModel.addColumn("Command");
        this.defaultModel.addColumn("Group name");
        this.defaultModel.addColumn("Runtime behaviour");
        this.defaultModel.addColumn("Show preview");
        this.defaultModel.addColumn("Placeholder behaviour");
        setModel(this.defaultModel);
        hideColumns(Column.ID, Column.COMMAND, Column.PLACEHOLDER_BEHAVIOUR);
    }

    private void hideColumns(Column ... c) {
        List<Column> collect = Arrays.stream(c).sorted(Comparator.comparingInt(Column::getIndex).reversed()).collect(Collectors.toList());
        for (Column column : collect) {
            this.removeColumn(this.getColumnModel().getColumn(column.getIndex()));
        }
    }

    public CommandObject getSelectedCommandObject() {
        int[] selectedRows = this.getSelectedRows();
        if (selectedRows.length > 0) {
            int selectedRow = selectedRows[0];
            return getCommandObjectByRowIndex(selectedRow);
        }
        throw new IllegalStateException("No row selected!");
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }

    public String getSelectedNames() {
        int[] selectedRows = this.getSelectedRows();
        if (selectedRows.length > 0) {
            int selectedRow = selectedRows[0];
            return getNameByRowIndex(selectedRow);
        }
        throw new IllegalStateException("No row selected!");
    }

    private String getNameByRowIndex(int rowIndex) {
        return Optional.ofNullable(this.getModel().getValueAt(rowIndex, Column.NAME.getIndex())).orElse("").toString();
    }

    private boolean getShowPreviewByRowIndex(int rowIndex) {
        return Boolean.parseBoolean(Optional.ofNullable(this.getModel().getValueAt(rowIndex, Column.SHOW_PREVIEW.getIndex())).orElse("").toString());
    }

    private ERuntimeBehaviour getRuntimeBehaviourByRowIndex(int rowIndex) {
        return ERuntimeBehaviour.getEnum(Optional.ofNullable(this.getModel().getValueAt(rowIndex, Column.RUNTIME_BEHAVIOUR.getIndex())).orElse("").toString());
    }

    private String getGroupByRowIndex(int rowIndex) {
        return Optional.ofNullable(this.getModel().getValueAt(rowIndex, Column.GROUP.getIndex())).orElse("").toString();
    }

    private String getCommandByRowIndex(int rowIndex) {
        return Optional.ofNullable(this.getModel().getValueAt(rowIndex, Column.COMMAND.getIndex())).orElse("").toString();
    }

    private List<PlaceholderBehaviour> getPlaceholderBehaviourByRowIndex(int rowIndex) {
        try {
            return (List<PlaceholderBehaviour>) this.getModel().getValueAt(rowIndex, Column.PLACEHOLDER_BEHAVIOUR.getIndex());
        } catch (Exception e) {
            BurpExtender.printErr("Casting of placeholder behaviour failed for row " + rowIndex);
            return Lists.newArrayList();
        }
    }

    public List<CommandObject> getCommandObjects() {
        List<CommandObject> commandObjects = new ArrayList<CommandObject>();
        for (int i = 0; i < this.getDefaultModel().getRowCount(); i++) {
            commandObjects.add(getCommandObjectByRowIndex(i));
        }
        return commandObjects;
    }

    private CommandObject getCommandObjectByRowIndex(int rowIndex) {
        String id = this.getModel().getValueAt(rowIndex, Column.ID.getIndex()).toString();
        String name = getNameByRowIndex(rowIndex);
        String command = getCommandByRowIndex(rowIndex);
        String group = getGroupByRowIndex(rowIndex);
        ERuntimeBehaviour runtimeBehaviour = getRuntimeBehaviourByRowIndex(rowIndex);
        boolean showPreview = getShowPreviewByRowIndex(rowIndex);
        List<PlaceholderBehaviour> placeholderBehaviourList = getPlaceholderBehaviourByRowIndex(rowIndex);
        return new CommandObject(id, name, command, group, runtimeBehaviour, showPreview, placeholderBehaviourList);
    }

    public CommandObject getCommandObjectById(String commandId) {
        if (commandId == null) {
            BurpExtender.printErr("CommandObject id should not be null!");
            throw new IllegalArgumentException("CommandObject id should not be null!");
        }
        for (int i = 0; i < this.getDefaultModel().getRowCount(); i++) {
            CommandObject commandObject = getCommandObjectByRowIndex(i);
            if (commandId.equals(commandObject.getId())) {
                return commandObject;
            }
        }
        BurpExtender.printErr("No command found with the specified id!");
        throw new IllegalStateException("No command found with the specified id!");
    }

    public void addCommandObjects(List<CommandObject> commandObjectList) {
        for (CommandObject commandObject : commandObjectList) {
            addCommandObject(commandObject);
        }
    }

    public void addCommandObject(CommandObject commandObject) {
        getDefaultModel().addRow(new Object[]{
                commandObject.getId(),
                commandObject.getName(),
                commandObject.getFormat(),
                commandObject.getGroup(),
                commandObject.getRuntimeBehaviour().alternateName(),
                commandObject.shouldShowPreview(),
                commandObject.getPlaceholderBehaviourList()
        });
    }

    public void editSelectedCommandObject(CommandObject commandObject) {
        int selectedRowIndex = this.getSelectedRow();
        if (selectedRowIndex >= 0) {
            editRow(selectedRowIndex, commandObject);
        }
    }

    private void editRow(int rowIndex, CommandObject commandObject) {
        DefaultTableModel model = getDefaultModel();
        model.setValueAt(commandObject.getId(), rowIndex, Column.ID.getIndex());
        model.setValueAt(commandObject.getName(), rowIndex, Column.NAME.getIndex());
        model.setValueAt(commandObject.getGroup(), rowIndex, Column.GROUP.getIndex());
        model.setValueAt(commandObject.getFormat(), rowIndex, Column.COMMAND.getIndex());
        model.setValueAt(commandObject.getRuntimeBehaviour().alternateName(), rowIndex, Column.RUNTIME_BEHAVIOUR.getIndex());
        model.setValueAt(commandObject.shouldShowPreview(), rowIndex, Column.SHOW_PREVIEW.getIndex());
        model.setValueAt(commandObject.getPlaceholderBehaviourList(), rowIndex, Column.PLACEHOLDER_BEHAVIOUR.getIndex());
    }

    public void editCommandObject(CommandObject commandObject) {
        for (int i = 0; i < this.getDefaultModel().getRowCount(); i++) {
            CommandObject commandObjectFromRow = getCommandObjectByRowIndex(i);
            if (commandObjectFromRow.getId().equals(commandObject.getId())) {
                editRow(i, commandObject);
                return;
            }
        }
    }

    public void removeSelectedRow() {
        List<Integer> rows = Ints.asList(this.getSelectedRows());
        Collections.sort(rows, Collections.reverseOrder());
        for (Integer row : rows) {
            getDefaultModel().removeRow(row);
        }
    }

    public void clearTable() {
        for (int row = this.getRowCount() - 1; row >= 0; row--) {
            getDefaultModel().removeRow(row);
        }
    }

    public void moveSelectedRowUp() {
        moveRowBy(-1);
    }

    public void moveSelectedRowDown() {
        moveRowBy(1);
    }

    private void moveRowBy(int index) {
        DefaultTableModel model = (DefaultTableModel) this.getModel();
        int[] rows = this.getSelectedRows();
        int destination = rows[0] + index;
        int rowCount = model.getRowCount();

        if (destination < 0 || destination >= rowCount) {
            return;
        }

        model.moveRow(rows[0], rows[rows.length - 1], destination);
        this.setRowSelectionInterval(rows[0] + index, rows[rows.length - 1] + index);
    }

    @Override
    public void removeAll() {
        DefaultTableModel model = (DefaultTableModel) this.getModel();
        for (int i = 0; i < model.getRowCount(); i++) {
            model.removeRow(i);
        }
    }
}

package net.bytebutcher.burpsendtoextension.gui;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import net.bytebutcher.burpsendtoextension.gui.listener.ToolTipActionListener;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

public class SendToAddDialog {
    private JTextField txtName;
    private JTextField txtCommand;
    private JButton btnCancel;
    private JButton btnOk;
    private JPanel formPanel;
    private JButton btnCommandHelp;
    private JCheckBox chkShowPreviewPriorToExecution;
    private JTextField txtGroup;
    private JRadioButton chkRunInTerminal;
    private JRadioButton chkOutputShouldReplaceSelection;
    private JRadioButton chkRunInBackground;
    private final JDialog dialog;

    private boolean success = false;
    private java.util.List<CommandObject> commandObjects;
    private AbstractAction onOkActionListener;
    private AbstractAction onCancelActionListener;

    public SendToAddDialog(JFrame parent, String title, java.util.List<CommandObject> commandObjects) {
        this.commandObjects = commandObjects;
        this.dialog = initDialog(parent, title);
        initEventListener();
        initKeyboardShortcuts();
    }

    public SendToAddDialog(JFrame parent, String title, java.util.List<CommandObject> commandObjects, CommandObject commandObject) {
        this(parent, title, commandObjects);
        commandObjects.remove(commandObject);
        txtName.setText(commandObject.getName());
        txtCommand.setText(commandObject.getCommand());
        txtGroup.setText(commandObject.getGroup());
        chkShowPreviewPriorToExecution.setSelected(commandObject.shouldShowPreview());
        chkRunInBackground.setSelected(commandObject.shouldRunInBackground());
        chkRunInTerminal.setSelected(commandObject.shouldRunInTerminal());
        chkOutputShouldReplaceSelection.setSelected(commandObject.shouldOutputReplaceSelection());
    }

    private void initKeyboardShortcuts() {
        bindKeyStrokeToAction("ESCAPE", onCancelActionListener);
        bindKeyStrokeToAction("ENTER", onOkActionListener);
    }

    private void bindKeyStrokeToAction(String keyStroke, Action action) {
        KeyStroke stroke = KeyStroke.getKeyStroke(keyStroke);
        InputMap inputMap = formPanel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        inputMap.put(stroke, keyStroke);
        formPanel.getActionMap().put(keyStroke, action);
    }

    private void initEventListener() {
        onOkActionListener = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (getName().isEmpty()) {
                    DialogUtil.showErrorDialog(
                            dialog,
                            "Name should not be empty!",
                            "Name is empty!"
                    );
                    return;
                }
                if (!commandObjects.stream().noneMatch(commandObject -> getName().equals(commandObject.getName()) && getGroup().equals(commandObject.getGroup()))) {
                    DialogUtil.showErrorDialog(
                            dialog,
                            "Name already exists within the specified group!",
                            "Combination of name and group already exists!"
                    );
                    return;
                }
                if (getCommand().isEmpty()) {
                    DialogUtil.showErrorDialog(
                            dialog,
                            "Command should not be empty!",
                            "Command is empty!"
                    );
                    return;
                }
                success = true;
                dialog.dispose();
            }
        };
        btnOk.addActionListener(onOkActionListener);
        onCancelActionListener = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                success = false;
                dialog.dispose();
            }
        };
        btnCancel.addActionListener(onCancelActionListener);
        btnCommandHelp.addActionListener(new ToolTipActionListener(btnCommandHelp, "" +
                "<html>" +
                "<p>%H = Host</p>" +
                "<p>%P = Port</p>" +
                "<p>%T = Protocol</p>" +
                "<p>%U = URL</p>" +
                "<p>%A = URL-Path</p>" +
                "<p>%Q = URL-Query</p>" +
                "<p>%C = Cookies</p>" +
                "<p>%M = HTTP-Method</p>" +
                "<p>%S = Selected text</p>" +
                "<p>%F = Path to file containing selected text</p>" +
                "<p>%R = Path to file containing focused HTTP-request/-response</p>" +
                "<p>%B = Path to file containing HTTP-body of focused request/response</p>" +
                "<p>%E = Path to file containing HTTP-header of focused request/response</p>" +
                "</html>")
        );
    }

    private JDialog initDialog(JFrame parent, String title) {
        JDialog dialog = new JDialog(parent, title, true);
        dialog.getContentPane().add(this.getRootPanel());
        dialog.setSize(450, 250);
        int x = DialogUtil.getX(parent, dialog);
        int y = DialogUtil.getY(parent, dialog);
        dialog.setLocation(x, y);
        dialog.pack();
        return dialog;
    }

    public boolean run() {
        this.dialog.setVisible(true);
        return this.success;
    }

    private JPanel getRootPanel() {
        return formPanel;
    }

    private String getName() {
        return txtName.getText();
    }

    private String getCommand() {
        return txtCommand.getText();
    }

    private String getGroup() {
        return txtGroup.getText();
    }

    private boolean shouldRunInTerminal() {
        return chkRunInTerminal.isSelected();
    }

    private boolean shouldOutputReplaceSelection() {
        return chkOutputShouldReplaceSelection.isSelected();
    }

    private boolean shouldShowPreview() {
        return chkShowPreviewPriorToExecution.isSelected();
    }

    public CommandObject getCommandObject() {
        return new CommandObject(getName(), getCommand(), getGroup(), shouldRunInTerminal(), shouldShowPreview(), shouldOutputReplaceSelection());
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        formPanel = new JPanel();
        formPanel.setLayout(new GridLayoutManager(3, 1, new Insets(10, 10, 10, 10), -1, -1));
        final JLabel label1 = new JLabel();
        label1.setText("Enter the details for the \"Send to...\" context menu entry.");
        formPanel.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridBagLayout());
        formPanel.add(panel1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Name:");
        label2.setDisplayedMnemonic('N');
        label2.setDisplayedMnemonicIndex(0);
        GridBagConstraints gbc;
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 10);
        panel1.add(label2, gbc);
        final JLabel label3 = new JLabel();
        label3.setText("Command:");
        label3.setDisplayedMnemonic('M');
        label3.setDisplayedMnemonicIndex(2);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 10);
        panel1.add(label3, gbc);
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.BOTH;
        panel1.add(panel2, gbc);
        txtCommand = new JTextField();
        txtCommand.setText("");
        panel2.add(txtCommand, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        btnCommandHelp = new JButton();
        btnCommandHelp.setText("?");
        panel2.add(btnCommandHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Group:");
        label4.setDisplayedMnemonic('G');
        label4.setDisplayedMnemonicIndex(0);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 10);
        panel1.add(label4, gbc);
        chkRunInTerminal = new JRadioButton();
        chkRunInTerminal.setText("Run in terminal");
        chkRunInTerminal.setMnemonic('T');
        chkRunInTerminal.setDisplayedMnemonicIndex(7);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 4;
        gbc.anchor = GridBagConstraints.WEST;
        panel1.add(chkRunInTerminal, gbc);
        chkOutputShouldReplaceSelection = new JRadioButton();
        chkOutputShouldReplaceSelection.setText("Output should replace selection");
        chkOutputShouldReplaceSelection.setMnemonic('R');
        chkOutputShouldReplaceSelection.setDisplayedMnemonicIndex(14);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 5;
        gbc.anchor = GridBagConstraints.WEST;
        panel1.add(chkOutputShouldReplaceSelection, gbc);
        chkShowPreviewPriorToExecution = new JCheckBox();
        chkShowPreviewPriorToExecution.setSelected(true);
        chkShowPreviewPriorToExecution.setText("Show preview prior to execution");
        chkShowPreviewPriorToExecution.setMnemonic('P');
        chkShowPreviewPriorToExecution.setDisplayedMnemonicIndex(5);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 6;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(5, 2, 2, 2);
        panel1.add(chkShowPreviewPriorToExecution, gbc);
        txtGroup = new JTextField();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 2, 2, 2);
        panel1.add(txtGroup, gbc);
        txtName = new JTextField();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 2, 2, 2);
        panel1.add(txtName, gbc);
        chkRunInBackground = new JRadioButton();
        chkRunInBackground.setSelected(true);
        chkRunInBackground.setText("Run in background");
        chkRunInBackground.setMnemonic('B');
        chkRunInBackground.setDisplayedMnemonicIndex(7);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.anchor = GridBagConstraints.WEST;
        panel1.add(chkRunInBackground, gbc);
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        formPanel.add(panel3, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        btnCancel = new JButton();
        btnCancel.setText("Cancel");
        btnCancel.setMnemonic('C');
        btnCancel.setDisplayedMnemonicIndex(0);
        panel3.add(btnCancel, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnOk = new JButton();
        btnOk.setText("Ok");
        btnOk.setMnemonic('O');
        btnOk.setDisplayedMnemonicIndex(0);
        panel3.add(btnOk, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel3.add(spacer1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        label2.setLabelFor(txtName);
        label3.setLabelFor(txtCommand);
        label4.setLabelFor(txtGroup);
        ButtonGroup buttonGroup;
        buttonGroup = new ButtonGroup();
        buttonGroup.add(chkRunInTerminal);
        buttonGroup.add(chkOutputShouldReplaceSelection);
        buttonGroup.add(chkRunInBackground);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return formPanel;
    }

}

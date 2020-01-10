package net.bytebutcher.burpsendtoextension.gui;

import burp.BurpExtender;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import net.bytebutcher.burpsendtoextension.gui.listener.ToolTipActionListener;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.gui.util.WebUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URL;

public class SendToTab {
    private BurpExtender burpExtender;
    private JButton btnRemove;
    private JButton btnEdit;
    private JButton btnAdd;
    private JTable tblSendTo;

    private SendToTable sendToTable;
    private JPanel formPanel;
    private JButton btnUp;
    private JButton btnDown;
    private JLabel lblSettings;
    private JLabel lblHelp;
    private JTextField txtRunInTerminal;
    private JButton btnRunInTerminalHelp;
    private SendToTableListener sendToTableListener;
    private final SendToTabSettingsContextMenu sendToTabSettingsContextMenu;


    public SendToTab(final BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        $$$setupUI$$$();
        this.lblHelp.setIcon(this.burpExtender.createImageIcon("/panel_help.png", "", 24, 24));
        this.lblSettings.setIcon(this.burpExtender.createImageIcon("/panel_settings.png", "", 24, 24));
        this.sendToTableListener = new SendToTableListener(this.tblSendTo, this.sendToTable, burpExtender);
        this.tblSendTo.getModel().addTableModelListener(sendToTableListener);
        btnAdd.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                new Thread(new Runnable() {
                    public void run() {
                        SendToAddDialog addDialog = new SendToAddDialog(getParent(), "Add context menu entry", sendToTable.getCommandObjects());
                        if (addDialog.run()) {
                            sendToTableListener.onAddButtonClick(e, addDialog.getCommandObject());
                        }
                    }
                }).start();
            }
        });
        btnEdit.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CommandObject selectedCommandObject = sendToTable.getSelectedCommandObject();
                SendToAddDialog editDialog = new SendToAddDialog(getParent(), "Edit context menu entry", sendToTable.getCommandObjects(), selectedCommandObject);
                if (editDialog.run()) {
                    sendToTableListener.onEditButtonClick(e, editDialog.getCommandObject());
                }
            }
        });
        btnRemove.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean result = DialogUtil.showConfirmationDialog(getParent(), "Delete context menu entries",
                        "Do you really want to delete the selected context menu entries?");
                if (result) {
                    sendToTableListener.onRemoveButtonClick(e);
                }
            }
        });
        btnUp.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToTableListener.onUpButtonClick(e);
            }
        });
        btnDown.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToTableListener.onDownButtonClick(e);
            }
        });
        lblHelp.addMouseListener(new LabelIconImageHoverAdapter(lblHelp, "/panel_help.png", "/panel_help_highlighted.png"));
        lblSettings.addMouseListener(new LabelIconImageHoverAdapter(lblSettings, "/panel_settings.png", "/panel_settings_highlighted.png"));
        lblHelp.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    WebUtil.openWebpage(new URL("https://github.com/bytebutcher/burp-send-to"));
                } catch (MalformedURLException e1) {
                    // Nothing to do here...
                }
            }
        });
        sendToTabSettingsContextMenu = new SendToTabSettingsContextMenu(burpExtender, this);
        lblSettings.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                sendToTabSettingsContextMenu.show(lblSettings, lblSettings.getX() + lblSettings.getWidth(), lblSettings.getY());
            }
        });
        txtRunInTerminal.setText(this.burpExtender.getConfig().getRunInTerminalCommand());
        txtRunInTerminal.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                save();
            }

            public void removeUpdate(DocumentEvent e) {
                save();
            }

            public void insertUpdate(DocumentEvent e) {
                save();
            }

            public void save() {
                burpExtender.getConfig().setRunInTerminalCommand(txtRunInTerminal.getText());
            }
        });
        btnRunInTerminalHelp.addActionListener(new ToolTipActionListener(btnRunInTerminalHelp, "" +
                "<html>" +
                "<p>%C = Command</p>" +
                "</html>")
        );
    }

    public void resetOptions() {
        resetSendToTableData();
        resetRunInTerminalOption();
    }

    private void resetSendToTableData() {
        sendToTable.clearTable();
        sendToTable.addCommandObjects(this.burpExtender.getConfig().getDefaultSendToTableData());
    }

    private void resetRunInTerminalOption() {
        this.burpExtender.getConfig().resetRunInTerminalCommand();
        txtRunInTerminal.setText(this.burpExtender.getConfig().getRunInTerminalCommand());
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        createUIComponents();
        formPanel = new JPanel();
        formPanel.setLayout(new GridLayoutManager(5, 1, new Insets(10, 10, 10, 10), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(3, 2, new Insets(0, 0, 0, 0), -1, -1));
        formPanel.add(panel1, new GridConstraints(0, 0, 3, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(6, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        btnRemove = new JButton();
        btnRemove.setText("Remove");
        panel3.add(btnRemove, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnEdit = new JButton();
        btnEdit.setText("Edit");
        panel3.add(btnEdit, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnAdd = new JButton();
        btnAdd.setText("Add");
        panel3.add(btnAdd, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel3.add(spacer1, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        btnUp = new JButton();
        btnUp.setText("Up");
        panel3.add(btnUp, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnDown = new JButton();
        btnDown.setText("Down");
        panel3.add(btnDown, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        panel2.add(scrollPane1, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        scrollPane1.setViewportView(tblSendTo);
        final JLabel label1 = new JLabel();
        label1.setText("Manage entries of the \"Send to...\" context menu.");
        panel1.add(label1, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        Font label2Font = this.$$$getFont$$$("Tahoma", Font.BOLD, 14, label2.getFont());
        if (label2Font != null) label2.setFont(label2Font);
        label2.setForeground(new Color(-1341440));
        label2.setText("Context Menu Entries");
        panel1.add(label2, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(1, 1, new Insets(2, 2, 2, 2), -1, -1));
        panel1.add(panel4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, new Dimension(26, 26), 0, false));
        lblSettings = new JLabel();
        lblSettings.setText("");
        panel4.add(lblSettings, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 1, new Insets(2, 2, 2, 2), -1, -1));
        panel1.add(panel5, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, new Dimension(26, 26), 0, false));
        lblHelp = new JLabel();
        lblHelp.setText("");
        panel5.add(lblHelp, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new GridLayoutManager(3, 2, new Insets(0, 0, 0, 0), -1, -1));
        formPanel.add(panel6, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        Font label3Font = this.$$$getFont$$$("Tahoma", Font.BOLD, 14, label3.getFont());
        if (label3Font != null) label3.setFont(label3Font);
        label3.setForeground(new Color(-1341440));
        label3.setText("Miscellaneous Options");
        panel6.add(label3, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new GridLayoutManager(1, 1, new Insets(2, 2, 2, 2), -1, -1));
        panel6.add(panel7, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, new Dimension(26, 26), null, new Dimension(26, 26), 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("");
        panel7.add(label4, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Manage miscellaneous options.");
        panel6.add(label5, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel6.add(panel8, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("Run in terminal:");
        panel8.add(label6, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtRunInTerminal = new JTextField();
        txtRunInTerminal.setText("/bin/bash -c {CMD}");
        panel8.add(txtRunInTerminal, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        btnRunInTerminalHelp = new JButton();
        btnRunInTerminalHelp.setText("?");
        panel8.add(btnRunInTerminalHelp, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        formPanel.add(spacer2, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    private Font $$$getFont$$$(String fontName, int style, int size, Font currentFont) {
        if (currentFont == null) return null;
        String resultName;
        if (fontName == null) {
            resultName = currentFont.getName();
        } else {
            Font testFont = new Font(fontName, Font.PLAIN, 10);
            if (testFont.canDisplay('a') && testFont.canDisplay('1')) {
                resultName = fontName;
            } else {
                resultName = currentFont.getName();
            }
        }
        return new Font(resultName, style >= 0 ? style : currentFont.getStyle(), size >= 0 ? size : currentFont.getSize());
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return formPanel;
    }

    class LabelIconImageHoverAdapter extends MouseAdapter {

        private String resource;
        private String resourceHovered;
        private JLabel label;

        public LabelIconImageHoverAdapter(JLabel label, String resource, String resourceHovered) {
            this.label = label;
            this.resource = resource;
            this.resourceHovered = resourceHovered;
        }

        @Override
        public void mouseEntered(MouseEvent e) {
            label.setIcon(SendToTab.this.burpExtender.createImageIcon(resourceHovered, "", 24, 24));
        }

        @Override
        public void mouseExited(MouseEvent e) {
            label.setIcon(SendToTab.this.burpExtender.createImageIcon(resource, "", 24, 24));
        }
    }

    public JPanel getRootPanel() {
        return formPanel;
    }

    public JFrame getParent() {
        return (JFrame) SwingUtilities.getRootPane(this.getRootPanel()).getParent();
    }

    public SendToTable getSendToTable() {
        return sendToTable;
    }

    /**
     * Creates Custom GUI forms
     */
    private void createUIComponents() {
        this.tblSendTo = this.sendToTable = new SendToTable(this.burpExtender);
    }

    public SendToTableListener getSendToTableListener() {
        return this.sendToTableListener;
    }
}

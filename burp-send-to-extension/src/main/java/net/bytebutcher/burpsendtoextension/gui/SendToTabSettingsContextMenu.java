package net.bytebutcher.burpsendtoextension.gui;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.List;

class SendToTabSettingsContextMenu extends JPopupMenu {

    private BurpExtender burpExtender;
    private final JMenuItem restoreDefaults;
    private final JMenuItem loadOptions;
    private final JMenuItem saveOptions;

    private SendToTable sendToTable;
    private SendToTab sendToTab;

    public SendToTabSettingsContextMenu(final BurpExtender burpExtender, final SendToTab sendToTab) {
        this.burpExtender = burpExtender;
        this.sendToTab = sendToTab;
        this.sendToTable = sendToTab.getSendToTable();
        restoreDefaults = new JMenuItem("Restore defaults");
        restoreDefaults.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean result = DialogUtil.showConfirmationDialog(sendToTab.getParent(), "Reset \"Send to\"-options",
                        "Do you really want to reset the \"Send to\"-options?");
                if (result) {
                    sendToTab.resetOptions();
                }
            }
        });
        add(restoreDefaults);
        loadOptions = new JMenuItem("Load options");
        loadOptions.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Load \"Send to\" options from file...");
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                int result = fileChooser.showOpenDialog(getParent());
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    try {
                        List<CommandObject> commandObjectList = new Gson().fromJson(new FileReader(selectedFile), new TypeToken<List<CommandObject>>(){}.getType());
                        sendToTable.removeAll();
                        sendToTable.addCommandObjects(commandObjectList);
                    } catch (FileNotFoundException e1) {
                        DialogUtil.showErrorDialog(
                                sendToTab.getParent(),
                                "Error while loading options!",
                                "<html><p>There was an unknown error while loading the options!</p>" +
                                        "<p>For more information check out the \"Send to\" extension error log!</p></html>"
                        );
                        burpExtender.getCallbacks().printError("Error while loading options: " + e1);
                        return;
                    }
                    burpExtender.getCallbacks().printOutput("Successfully loaded options from '" + selectedFile.getAbsolutePath() + "'!");
                }
            }
        });
        add(loadOptions);
        saveOptions = new JMenuItem("Save options");
        saveOptions.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save \"Send to\" options to file...");

                int userSelection = fileChooser.showSaveDialog(getParent());
                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    String json = new Gson().toJson(sendToTable.getCommandObjects());
                    try (PrintWriter out = new PrintWriter(fileToSave)) {
                        out.write(json);
                    } catch (FileNotFoundException e1) {
                        DialogUtil.showErrorDialog(
                                sendToTab.getParent(),
                                "Error while saving options!",
                                "<html><p>There was an unknown error while saving the options!</p>" +
                                        "<p>For more information check out the \"Send to\" extension error log!</p></html>"
                        );
                        burpExtender.getCallbacks().printError("Error while saving options: " + e1);
                        return;
                    }
                    burpExtender.getCallbacks().printOutput("Successfully saved options in '" + fileToSave.getAbsolutePath() + "'!");
                }
            }
        });
        add(saveOptions);
    }
}

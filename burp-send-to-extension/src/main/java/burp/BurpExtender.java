package burp;

import net.bytebutcher.burpsendtoextension.gui.SendToContextMenu;
import net.bytebutcher.burpsendtoextension.gui.SendToTab;
import net.bytebutcher.burpsendtoextension.gui.SendToTable;
import net.bytebutcher.burpsendtoextension.models.Config;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, ITab {

    private JPanel tab = null;
    private SendToContextMenu sendToContextMenu;
    private SendToTable sendToTable;

    private static IBurpExtenderCallbacks callbacks;
    private static Config config;
    private static SendToTab sendToTab = null;

    private static PrintWriter stdout;
    private static PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        initLogHandler(callbacks);
        BurpExtender.printOut("Initializing Send to Extension...");
        BurpExtender.callbacks.setExtensionName("Send to");
        BurpExtender.printOut("Initializing config...");
        BurpExtender.config = new Config(this);
        BurpExtender.printOut("Initializing tab...");
        BurpExtender.sendToTab = new SendToTab(this);
        BurpExtender.printOut("Registering context menu...");
        this.sendToContextMenu = new SendToContextMenu(this, sendToTab.getSendToTableListener());
        BurpExtender.callbacks.registerContextMenuFactory(sendToContextMenu);
        this.tab = sendToTab.getRootPanel();
        BurpExtender.printOut("Loading table data...");
        this.sendToTable = sendToTab.getSendToTable();
        this.sendToTable.addCommandObjects(config.getSendToTableData());
        callbacks.addSuiteTab(this);
        BurpExtender.printOut("----------------------------------------------------------------------");
    }

    private void initLogHandler(IBurpExtenderCallbacks callbacks) {
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    @Override
    public String getTabCaption() {
        return "Send to";
    }

    @Override
    public Component getUiComponent() {
        return this.tab;
    }

    public ImageIcon createImageIcon(String path, String description, int width, int height) {
        java.net.URL imgURL = getClass().getResource(path);
        if (imgURL != null) {
            ImageIcon icon = new ImageIcon(imgURL);
            Image image = icon.getImage().getScaledInstance(width, height,  Image.SCALE_SMOOTH);
            return new ImageIcon(image, description);
        } else {
            BurpExtender.printErr("Couldn't find file: " + path);
            return null;
        }
    }

    public static JFrame getParent() {
        return sendToTab.getParent();
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static Config getConfig() {
        return config;
    }

    public static void printOut(String s) {
        stdout.println(s);
    }

    public static void printErr(String s) {
        stderr.println(s);
    }
}

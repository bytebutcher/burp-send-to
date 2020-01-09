package burp;

import net.bytebutcher.burpsendtoextension.gui.SendToContextMenu;
import net.bytebutcher.burpsendtoextension.gui.SendToTab;
import net.bytebutcher.burpsendtoextension.gui.SendToTable;
import net.bytebutcher.burpsendtoextension.models.Config;
import net.bytebutcher.burpsendtoextension.utils.OsUtils;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, ITab {

    private JPanel tab = null;
    private SendToTab sendToTab = null;
    private IBurpExtenderCallbacks callbacks;
    private SendToContextMenu sendToContextMenu;
    private Config config;
    private SendToTable sendToTable;

    private static PrintWriter stdout;
    private static PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        initLogHandler(callbacks);
        BurpExtender.printOut("Initializing Send to Extension...");
        this.callbacks.setExtensionName("Send to");
        BurpExtender.printOut("Initializing config...");
        this.config = new Config(this);
        BurpExtender.printOut("Initializing tab...");
        this.sendToTab = new SendToTab(this);
        BurpExtender.printOut("Registering context menu...");
        this.sendToContextMenu = new SendToContextMenu(this, this.sendToTab.getSendToTableListener());
        this.callbacks.registerContextMenuFactory(sendToContextMenu);
        this.tab = sendToTab.getRootPanel();
        BurpExtender.printOut("Loading table data...");
        this.sendToTable = this.sendToTab.getSendToTable();
        this.sendToTable.addCommandObjects(this.config.getSendToTableData());
        callbacks.addSuiteTab(this);
        BurpExtender.printOut("----------------------------------------------------------------------");
    }

    private void initLogHandler(IBurpExtenderCallbacks callbacks) {
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
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

    public Config getConfig() {
        return this.config;
    }

    public JFrame getParent() {
        return this.sendToTab.getParent();
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    public static void printOut(String s) {
        stdout.println(s);
    }

    public static void printErr(String s) {
        stderr.println(s);
    }
}

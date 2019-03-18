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
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.callbacks.setExtensionName("Send to");
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.config = new Config(this);
        this.sendToTab = new SendToTab(this);
        this.sendToContextMenu = new SendToContextMenu(this, this.sendToTab.getSendToTableListener());
        this.callbacks.registerContextMenuFactory(sendToContextMenu);
        this.tab = sendToTab.getRootPanel();
        this.sendToTable = this.sendToTab.getSendToTable();
        this.sendToTable.addCommandObjects(this.config.getSendToTableData());
        callbacks.addSuiteTab(this);
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
            stderr.println("Couldn't find file: " + path);
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

}

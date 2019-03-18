package com.monikamorrow;

import burp.ITab;
import burp.IBurpExtenderCallbacks;
import java.awt.Color;
import java.awt.Component;
import java.util.Timer;
import java.util.TimerTask;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

/**
 *
 * @author Monika Morrow Original URL: https://github.com/monikamorrow/Burp-Suite-Extension-Examples/tree/master/GUI%20Utils
 * @author August Detlefsen
 */
public class BurpSuiteTab extends JPanel implements ITab {
    IBurpExtenderCallbacks mCallbacks;
    String tabName;
    JPanel userDefinedPanel;

    /**
     * Creates new form BurpSuiteTab
     * @param tabName     The name displayed on the tab
     * @param callbacks   For UI Look and Feel
     */
    public BurpSuiteTab(String tabName, IBurpExtenderCallbacks callbacks) {
        this.tabName = tabName;
        mCallbacks = callbacks;

        mCallbacks.customizeUiComponent(this);
        mCallbacks.addSuiteTab(this);
    }

    public void addComponent(JPanel customPanel) {
        this.add(customPanel);
        this.revalidate();
        this.doLayout();
    }

    public String getTabCaption() {
        return tabName;
    }

    public Component getUiComponent() {
        return this;
    }

    /**
     * Highlights the tab using Burp's color scheme. The highlight disappears
     * after 3 seconds.
     */
    public void highlight() {
        final JTabbedPane parent = (JTabbedPane) this.getUiComponent().getParent();

        //search through tabs until we find this one
        for (int i = 0; i < parent.getTabCount(); i++) {
            String title = parent.getTitleAt(i);

            if (getTabCaption().equals(title)) {  //found this tab
                //create new colored label and set it into the tab
                final JLabel label = new JLabel(getTabCaption());
                label.setForeground(new Color(0xff6633));
                parent.setTabComponentAt(i, label);

                //schedule a task to change back to original color
                Timer timer = new Timer();

                TimerTask task = new TimerTask() {
                    @Override
                    public void run() {
                        label.setForeground(Color.black);
                    }
                };

                timer.schedule(task, 3000);

                break;
            }
        }
    }

}
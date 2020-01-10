package net.bytebutcher.burpsendtoextension.gui.listener;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ToolTipActionListener implements ActionListener {

    private JComponent component;
    private String toolTipText;

    public ToolTipActionListener(JComponent component, String toolTipText) {
        this.component = component;
        this.toolTipText = toolTipText;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        JToolTip toolTip = this.component.createToolTip();
        toolTip.setTipText(this.toolTipText);
        PopupFactory popupFactory = PopupFactory.getSharedInstance();
        int x = this.component.getLocationOnScreen().x;
        int y = this.component.getLocationOnScreen().y;
        x += this.component.getWidth() / 2;
        y += this.component.getHeight();
        final Popup tooltipContainer = popupFactory.getPopup(this.component, toolTip, x, y);
        tooltipContainer.show();
        (new Thread(new Runnable() {
            public void run() {
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException ex) {
                    // Nothing to do here.
                }
                tooltipContainer.hide();
            }

        })).start();
    }

    public String getToolTipText() {
        return toolTipText;
    }

    public void setToolTipText(String toolTipText) {
        this.toolTipText = toolTipText;
    }

    public JComponent getComponent() {
        return component;
    }
}

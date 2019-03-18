package net.bytebutcher.burpsendtoextension.gui.util;

import javax.swing.*;
import java.awt.*;

public final class DialogUtil {

    public static void showErrorDialog(Component parent, String title, String message) {
        final JDialog dlgError = new JOptionPane(message, JOptionPane.ERROR_MESSAGE).createDialog(parent, title);
        dlgError.setLocation(getX(parent, dlgError),getY(parent, dlgError));
        dlgError.setVisible(true);
    }

    public static boolean showConfirmationDialog(Component parent, String title, String message) {
        JOptionPane jOptionPane = new JOptionPane(message, JOptionPane.QUESTION_MESSAGE, JOptionPane.YES_NO_OPTION);
        final JDialog dlgError = jOptionPane.createDialog(parent, title);
        dlgError.setLocation(getX(parent, dlgError),getY(parent, dlgError));
        dlgError.setVisible(true);
        return ((Integer) jOptionPane.getValue()).intValue() == JOptionPane.YES_OPTION;
    }

    public static int getX(Component parent, Component child) {
        try {
            return parent.getX() + (parent.getWidth() / 2) - (child.getWidth() / 2);
        } catch (NullPointerException e) {
            return 0;
        }
    }

    public static int getY(Component parent, Component child) {
        try {
            return parent.getY() + (parent.getHeight() / 2) - (child.getHeight() / 2);
        } catch (NullPointerException e) {
            return 0;
        }
    }

}

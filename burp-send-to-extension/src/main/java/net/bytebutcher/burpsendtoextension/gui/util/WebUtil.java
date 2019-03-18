package net.bytebutcher.burpsendtoextension.gui.util;

import java.awt.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class WebUtil {

    public static boolean openWebpage(URI uri) {
        Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
        if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
            try {
                desktop.browse(uri);
                return true;
            } catch (Exception e) {
                // Nothing to do here...
            }
        }
        return false;
    }

    public static boolean openWebpage(URL url) {
        try {
            return openWebpage(url.toURI());
        } catch (URISyntaxException e) {
            // Nothing to do here...
        }
        return false;
    }

}

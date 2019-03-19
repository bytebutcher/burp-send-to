package net.bytebutcher.burpsendtoextension.gui.util;

import com.google.common.escape.Escaper;
import com.google.common.escape.Escapers;

public class ShellEscapeUtil {

    public static final Escaper shellEscaper;
    static {
        final Escapers.Builder builder = Escapers.builder();
        builder.addEscape('\'', "'\"'\"'");
        shellEscaper = builder.build();
    }

    public static String shellEscape(String command) {
        return shellEscaper.escape(command);
    }


}

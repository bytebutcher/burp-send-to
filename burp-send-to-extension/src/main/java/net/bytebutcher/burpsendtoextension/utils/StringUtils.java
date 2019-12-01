package net.bytebutcher.burpsendtoextension.utils;

import com.google.common.escape.Escaper;
import com.google.common.escape.Escapers;
import com.google.common.io.CharStreams;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class StringUtils {

    public static final Escaper shellEscaper;
    static {
        final Escapers.Builder builder = Escapers.builder();
        builder.addEscape('\'', "'\"'\"'");
        shellEscaper = builder.build();
    }

    public static String shellEscape(String command) {
        return shellEscaper.escape(command);
    }

    public static String fromInputStream(InputStream inputStream) throws IOException {
        return CharStreams.toString(new InputStreamReader(inputStream));
    }

}

package net.bytebutcher.burpsendtoextension.gui.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class SelectionUtil {

    public static byte[] replaceSelectedText(byte[] message, int[] bounds, String replaceText) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
        outputStream.write(replaceText.getBytes());
        outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
        outputStream.flush();
        return outputStream.toByteArray();
    }

}

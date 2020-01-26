package net.bytebutcher.burpsendtoextension.gui.util;

import burp.BurpExtender;
import burp.IContextMenuInvocation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class SelectionUtil {
    public static void replaceSelectedText(IContextMenuInvocation invocation, String replaceText) {
        try {
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                int[] bounds = invocation.getSelectionBounds();
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                outputStream.write(replaceText.getBytes());
                outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
                outputStream.flush();
                invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
            }
        } catch (IOException e) {
            BurpExtender.getCallbacks().printError("Error during replacing selection with output: " + e.toString());
        }
    }
}

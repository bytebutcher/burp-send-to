package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;

import javax.annotation.Nullable;

public class SelectedTextPlaceholder extends AbstractPlaceholder {

    public SelectedTextPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%S", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    protected SelectedTextPlaceholder(String placeholder, boolean doShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder, IContextMenuInvocation contextMenuInvocation) {
        super(placeholder, doShellEscape, doWriteToFile, requestResponseHolder, contextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue() {
        String value = null;
        int[] selectionBounds = getSelectionBounds();
        if (selectionBounds != null) {
            byte[] requestResponse = getRequestResponse();
            if (requestResponse != null) {
                boolean isSelectionEmpty = selectionBounds[0] == selectionBounds[1];
                if (!isSelectionEmpty) {
                    value = new String(requestResponse).substring(selectionBounds[0], selectionBounds[1]);
                }
            } else {
                BurpExtender.printErr("Error parsing selected text! No request/response found!");
            }
        } else {
            BurpExtender.printErr("Error parsing selected text! No selection bounds!");
        }
        return value;
    }

}

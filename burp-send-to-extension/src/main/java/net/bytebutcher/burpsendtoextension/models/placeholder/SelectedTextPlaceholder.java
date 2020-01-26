package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class SelectedTextPlaceholder extends AbstractRequestResponsePlaceholder {

    public SelectedTextPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%S", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    protected SelectedTextPlaceholder(String placeholder, boolean doShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder, IContextMenuInvocation contextMenuInvocation) {
        super(placeholder, doShellEscape, doWriteToFile, requestResponseHolder, contextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        String value = null;
        int[] selectionBounds = getSelectionBounds();
        if (selectionBounds != null) {
            byte[] requestResponse = getRequestResponseAsByteArray(context);
            if (requestResponse != null) {
                boolean isSelectionEmpty = selectionBounds[0] == selectionBounds[1];
                if (!isSelectionEmpty) {
                    value = new String(requestResponse).substring(selectionBounds[0], selectionBounds[1]);
                }
            }
        }
        return value;
    }

}

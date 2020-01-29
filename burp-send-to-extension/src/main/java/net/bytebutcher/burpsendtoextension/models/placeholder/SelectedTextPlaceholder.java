package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class SelectedTextPlaceholder extends AbstractRequestResponsePlaceholder {

    public SelectedTextPlaceholder(RequestResponseHolder requestResponseHolder) {
        super("%S", true, false, requestResponseHolder);
    }

    protected SelectedTextPlaceholder(String placeholder, boolean doShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder) {
        super(placeholder, doShellEscape, doWriteToFile, requestResponseHolder);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        String value = null;
        int[] selectionBounds = context.getSelectionBounds();
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

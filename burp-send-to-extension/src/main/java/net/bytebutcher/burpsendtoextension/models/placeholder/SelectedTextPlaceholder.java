package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class SelectedTextPlaceholder extends AbstractPlaceholder {

    public SelectedTextPlaceholder() {
        super("%S", true, false);
    }

    protected SelectedTextPlaceholder(String placeholder, boolean doShellEscape, boolean doWriteToFile) {
        super(placeholder, doShellEscape, doWriteToFile);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestResponsePlaceholder(this, requestResponseHolder) {
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
        };
    }
}

package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class PortPlaceholder extends AbstractRequestPlaceholder {

    public PortPlaceholder(RequestResponseHolder requestResponseHolder) {
        super("%P", false, false, requestResponseHolder);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return String.valueOf(getHttpRequestResponse().getHttpService().getPort());
    }
}

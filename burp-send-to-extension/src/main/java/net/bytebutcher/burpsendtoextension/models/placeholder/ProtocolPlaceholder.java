package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class ProtocolPlaceholder extends AbstractRequestPlaceholder {

    public ProtocolPlaceholder(RequestResponseHolder requestResponseHolder) {
        super("%T", true, false, requestResponseHolder);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return getHttpRequestResponse().getHttpService().getProtocol();
    }
}

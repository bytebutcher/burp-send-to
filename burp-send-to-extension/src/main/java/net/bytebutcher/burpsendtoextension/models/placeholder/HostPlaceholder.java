package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HostPlaceholder extends AbstractRequestPlaceholder {

    public HostPlaceholder(RequestResponseHolder requestResponseHolder) {
        super("%H", true, false, requestResponseHolder);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return getHttpRequestResponse().getHttpService().getHost();
    }
}

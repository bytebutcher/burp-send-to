package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpMethodPlaceholder extends AbstractRequestInfoPlaceholder {

    public HttpMethodPlaceholder(RequestResponseHolder requestResponseHolder) {
        super("%M", true, false, requestResponseHolder);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return getRequestInfo().getMethod();
    }

}

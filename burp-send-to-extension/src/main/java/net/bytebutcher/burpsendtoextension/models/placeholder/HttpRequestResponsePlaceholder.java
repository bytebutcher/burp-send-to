package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpRequestResponsePlaceholder extends AbstractRequestResponsePlaceholder {

    public HttpRequestResponsePlaceholder(RequestResponseHolder requestResponseHolder) {
        super("%R", false, true, requestResponseHolder);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        byte[] requestResponse = getRequestResponseAsByteArray(context);
        return requestResponse != null ? new String(requestResponse) : null;
    }

}

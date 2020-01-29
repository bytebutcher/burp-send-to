package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpBodyToFilePlaceholder extends AbstractRequestResponseInfoPlaceholder {

    public HttpBodyToFilePlaceholder(RequestResponseHolder requestResponseHolder) {
        super("%B", false, true, requestResponseHolder);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        switch(context.getOrigin()) {
            case HTTP_REQUEST:
                return getRequestInfo().getBody();
            case HTTP_RESPONSE:
                return getResponseInfo().getBody();
        }
        return null;
    }

}

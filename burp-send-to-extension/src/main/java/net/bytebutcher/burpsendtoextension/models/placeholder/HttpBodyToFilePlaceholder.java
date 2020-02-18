package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpBodyToFilePlaceholder extends AbstractPlaceholder {

    public HttpBodyToFilePlaceholder() {
        super("%B", false, true);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestResponseInfoPlaceholder(this, requestResponseHolder) {
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
        };
    }
}

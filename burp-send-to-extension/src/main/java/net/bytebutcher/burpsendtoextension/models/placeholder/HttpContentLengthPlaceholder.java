package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpContentLengthPlaceholder extends AbstractPlaceholder {

    public HttpContentLengthPlaceholder() {
        super("%L", false, false);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestResponseInfoPlaceholder(this, requestResponseHolder) {
            @Nullable
            @Override
            protected String getInternalValue(Context context) {
                switch(context.getOrigin()) {
                    case HTTP_REQUEST:
                         return String.valueOf(getRequestInfo().getBody() == null ? 0 : getRequestInfo().getBody().length());
                    case HTTP_RESPONSE:
                        return String.valueOf(getResponseInfo().getBody() == null ? 0 : getResponseInfo().getBody().length());
                }
                return null;
            }
        };
    }
}

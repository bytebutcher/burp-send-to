package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpRequestResponsePlaceholder extends AbstractPlaceholder {

    public HttpRequestResponsePlaceholder() {
        super("%R", false, true);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestResponsePlaceholder(this, requestResponseHolder) {
            @Nullable
            @Override
            protected String getInternalValue(Context context) {
                byte[] requestResponse = getRequestResponseAsByteArray(context);
                return requestResponse != null ? new String(requestResponse) : null;
            }
        };
    }
}

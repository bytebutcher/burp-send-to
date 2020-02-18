package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpMethodPlaceholder extends AbstractPlaceholder {

    public HttpMethodPlaceholder() {
        super("%M", true, false);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestInfoPlaceholder(this, requestResponseHolder) {
            @Nullable
            @Override
            protected String getInternalValue(Context context) {
                return getRequestInfo().getMethod();
            }
        };
    }
}

package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpStatusCodePlaceholder extends AbstractPlaceholder {

    public HttpStatusCodePlaceholder() {
        super("%O", false, false);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestResponseInfoPlaceholder(this, requestResponseHolder) {
            @Nullable
            @Override
            protected String getInternalValue(Context context) {
                short statusCode = -1;
                if (context.getOrigin() == Context.Origin.HTTP_RESPONSE) {
                    statusCode = getResponseInfo().getStatusCode();
                }
                return statusCode == -1 ? null : String.valueOf(statusCode);
            }
        };
    }
}

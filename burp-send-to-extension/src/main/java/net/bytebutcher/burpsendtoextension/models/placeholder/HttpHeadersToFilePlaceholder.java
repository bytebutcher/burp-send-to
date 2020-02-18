package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import com.google.common.collect.Lists;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.util.List;

public class HttpHeadersToFilePlaceholder extends AbstractPlaceholder {

    public HttpHeadersToFilePlaceholder() {
        super("%E", false, true);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestResponseInfoPlaceholder(this, requestResponseHolder) {
            @Nullable
            @Override
            protected String getInternalValue(Context context) {
                List<String> headers = Lists.newArrayList();
                switch(context.getOrigin()) {
                    case HTTP_REQUEST:
                        headers = getRequestInfo().getHeaders();
                        break;
                    case HTTP_RESPONSE:
                        headers = getResponseInfo().getHeaders();
                        break;
                }
                return headers.isEmpty() ? null : String.join(System.lineSeparator(), headers);
            }
        };
    }
}

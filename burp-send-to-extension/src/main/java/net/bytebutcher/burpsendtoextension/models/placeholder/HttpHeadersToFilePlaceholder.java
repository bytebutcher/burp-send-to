package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import com.google.common.collect.Lists;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.util.List;

public class HttpHeadersToFilePlaceholder extends AbstractRequestResponseInfoPlaceholder {

    public HttpHeadersToFilePlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%E", false, true, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        List<String> headers = Lists.newArrayList();
        switch(context) {
            case HTTP_REQUEST:
                headers = getRequestInfo().getHeaders();
                break;
            case HTTP_RESPONSE:
                headers = getResponseInfo().getHeaders();
                break;
        }
        return headers.isEmpty() ? null : String.join(System.lineSeparator(), headers);
    }

}

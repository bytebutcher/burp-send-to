package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import com.google.common.collect.Lists;

import javax.annotation.Nullable;
import java.util.List;

public class HttpHeadersToFilePlaceholder extends AbstractPlaceholder {

    public HttpHeadersToFilePlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%E", false, true, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue() {
        List<String> headers = Lists.newArrayList();
        switch(getContext()) {
            case HTTP_REQUEST:
                headers = getRequestResponseHolder().getRequestInfo().getHeaders();
                break;
            case HTTP_RESPONSE:
                headers = getRequestResponseHolder().getResponseInfo().getHeaders();
                break;
        }
        return headers.isEmpty() ? null : String.join(System.lineSeparator(), headers);
    }

}

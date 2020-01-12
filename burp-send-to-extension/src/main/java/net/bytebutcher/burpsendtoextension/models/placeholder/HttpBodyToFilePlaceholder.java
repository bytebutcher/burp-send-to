package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;

import javax.annotation.Nullable;

public class HttpBodyToFilePlaceholder extends AbstractPlaceholder {

    public HttpBodyToFilePlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%B", false, true, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue() {
        switch(getContext()) {
            case HTTP_REQUEST:
                return getRequestResponseHolder().getRequestInfo().getBody();
            case HTTP_RESPONSE:
                return getRequestResponseHolder().getResponseInfo().getBody();
        }
        return null;
    }

}

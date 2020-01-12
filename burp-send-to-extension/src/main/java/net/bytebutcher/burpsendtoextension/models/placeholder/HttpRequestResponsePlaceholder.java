package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;

import javax.annotation.Nullable;

public class HttpRequestResponsePlaceholder extends AbstractPlaceholder {

    public HttpRequestResponsePlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%R", false, true, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue() {
        byte[] requestResponse = getRequestResponse();
        return requestResponse != null ? new String(requestResponse) : null;
    }

}

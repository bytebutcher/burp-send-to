package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

public abstract class AbstractRequestResponsePlaceholder extends AbstractRequestResponsePlaceholderBase {

    private final RequestResponseHolder requestResponseHolder;

    public AbstractRequestResponsePlaceholder(String placeholder, boolean doesRequireShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder, IContextMenuInvocation contextMenuInvocation) {
        super(placeholder, doesRequireShellEscape, doWriteToFile, requestResponseHolder, contextMenuInvocation);
        this.requestResponseHolder = requestResponseHolder;
    }

    protected byte[] getRequestResponseAsByteArray(Context context) {
        switch(context) {
            case HTTP_REQUEST:
                return requestResponseHolder.getHttpRequestResponse().getRequest();
            case HTTP_RESPONSE:
                return requestResponseHolder.getHttpRequestResponse().getResponse();
        }
        return null;
    }
}

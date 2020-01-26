package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.RequestResponseHolder;

public abstract class AbstractRequestPlaceholder extends AbstractRequestResponsePlaceholderBase {

    private final RequestResponseHolder requestResponseHolder;

    public AbstractRequestPlaceholder(String placeholder, boolean doesRequireShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder, IContextMenuInvocation contextMenuInvocation) {
        super(placeholder, doesRequireShellEscape, doWriteToFile, requestResponseHolder, contextMenuInvocation);
        this.requestResponseHolder = requestResponseHolder;
    }

    protected IHttpRequestResponse getHttpRequestResponse() {
        return requestResponseHolder.getHttpRequestResponse();
    }
}

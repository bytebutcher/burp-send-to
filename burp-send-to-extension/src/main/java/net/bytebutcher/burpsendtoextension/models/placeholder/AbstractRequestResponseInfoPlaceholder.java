package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.IRequestInfoWrapper;
import burp.IResponseInfoWrapper;
import burp.RequestResponseHolder;

/**
 * Placeholder which depends on a request/response is selected/focused.
 */
public abstract class AbstractRequestResponseInfoPlaceholder extends AbstractRequestResponsePlaceholderBase {

    private final RequestResponseHolder requestResponseHolder;

    public AbstractRequestResponseInfoPlaceholder(String placeholder, boolean doesRequireShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder, IContextMenuInvocation contextMenuInvocation) {
        super(placeholder, doesRequireShellEscape, doWriteToFile, requestResponseHolder, contextMenuInvocation);
        this.requestResponseHolder = requestResponseHolder;
    }

    protected IRequestInfoWrapper getRequestInfo() {
        return requestResponseHolder.getRequestInfo();
    }

    protected IResponseInfoWrapper getResponseInfo() {
        return requestResponseHolder.getResponseInfo();
    }
}

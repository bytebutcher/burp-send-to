package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.IRequestInfoWrapper;
import burp.RequestResponseHolder;

/**
 * Placeholders which do require additional information from a request.
 */
public abstract class AbstractRequestInfoPlaceholder extends AbstractRequestResponsePlaceholderBase {

    private final RequestResponseHolder requestResponseHolder;

    public AbstractRequestInfoPlaceholder(String placeholder, boolean doesRequireShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder, IContextMenuInvocation contextMenuInvocation) {
        super(placeholder, doesRequireShellEscape, doWriteToFile, requestResponseHolder, contextMenuInvocation);
        this.requestResponseHolder = requestResponseHolder;
    }

    protected IRequestInfoWrapper getRequestInfo() {
        return requestResponseHolder.getRequestInfo();
    }

}

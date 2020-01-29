package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IHttpRequestResponse;
import burp.RequestResponseHolder;

public abstract class AbstractRequestPlaceholder extends AbstractRequestResponsePlaceholderBase {

    private final RequestResponseHolder requestResponseHolder;

    public AbstractRequestPlaceholder(String placeholder, boolean doesRequireShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder) {
        super(placeholder, doesRequireShellEscape, doWriteToFile, requestResponseHolder);
        this.requestResponseHolder = requestResponseHolder;
    }

    protected IHttpRequestResponse getHttpRequestResponse() {
        return requestResponseHolder.getHttpRequestResponse();
    }
}

package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IHttpRequestResponse;
import burp.RequestResponseHolder;

public abstract class AbstractRequestPlaceholder extends AbstractRequestResponsePlaceholderBase {

    private final RequestResponseHolder requestResponseHolder;

    public AbstractRequestPlaceholder(IPlaceholder placeholder, RequestResponseHolder requestResponseHolder) {
        super(placeholder, requestResponseHolder);
        this.requestResponseHolder = requestResponseHolder;
    }

    protected IHttpRequestResponse getHttpRequestResponse() {
        return requestResponseHolder.getHttpRequestResponse();
    }
}

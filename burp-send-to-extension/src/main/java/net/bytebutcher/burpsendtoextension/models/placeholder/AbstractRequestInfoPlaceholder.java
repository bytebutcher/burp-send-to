package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IRequestInfoWrapper;
import burp.RequestResponseHolder;

/**
 * Placeholders which do require additional information from a request.
 */
public abstract class AbstractRequestInfoPlaceholder extends AbstractRequestResponsePlaceholderBase {

    private final RequestResponseHolder requestResponseHolder;

    public AbstractRequestInfoPlaceholder(IPlaceholder placeholder, RequestResponseHolder requestResponseHolder) {
        super(placeholder, requestResponseHolder);
        this.requestResponseHolder = requestResponseHolder;
    }

    protected IRequestInfoWrapper getRequestInfo() {
        return requestResponseHolder.getRequestInfo();
    }

}

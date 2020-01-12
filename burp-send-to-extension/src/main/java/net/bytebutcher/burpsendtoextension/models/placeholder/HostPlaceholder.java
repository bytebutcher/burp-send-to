package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;

import javax.annotation.Nullable;

public class HostPlaceholder extends AbstractPlaceholder {

    public HostPlaceholder(RequestResponseHolder requestResponseHolder,IContextMenuInvocation iContextMenuInvocation) {
        super("%H", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue() {
        return getRequestResponseHolder().getHttpRequestResponse().getHttpService().getHost();
    }
}

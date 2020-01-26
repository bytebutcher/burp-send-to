package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class ProtocolPlaceholder extends AbstractRequestPlaceholder {

    public ProtocolPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%T", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return getHttpRequestResponse().getHttpService().getProtocol();
    }
}

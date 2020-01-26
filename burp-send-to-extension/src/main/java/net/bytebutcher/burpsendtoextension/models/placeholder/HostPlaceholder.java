package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HostPlaceholder extends AbstractRequestPlaceholder {

    public HostPlaceholder(RequestResponseHolder requestResponseHolder,IContextMenuInvocation iContextMenuInvocation) {
        super("%H", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return getHttpRequestResponse().getHttpService().getHost();
    }
}

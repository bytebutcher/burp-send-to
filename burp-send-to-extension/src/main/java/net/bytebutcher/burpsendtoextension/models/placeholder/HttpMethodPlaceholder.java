package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HttpMethodPlaceholder extends AbstractRequestInfoPlaceholder {

    public HttpMethodPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%M", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return getRequestInfo().getMethod();
    }

}

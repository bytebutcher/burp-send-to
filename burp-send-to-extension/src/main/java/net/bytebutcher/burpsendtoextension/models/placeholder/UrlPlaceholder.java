package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.util.Objects;

public class UrlPlaceholder extends AbstractRequestInfoPlaceholder {

    public UrlPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%U", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return Objects.toString(getRequestInfo().getUrl());
    }

}

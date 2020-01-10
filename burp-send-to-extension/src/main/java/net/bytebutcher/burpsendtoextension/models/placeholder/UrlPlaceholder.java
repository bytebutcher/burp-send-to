package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;

import javax.annotation.Nullable;
import java.util.Objects;

public class UrlPlaceholder extends AbstractPlaceholder {

    public UrlPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%U", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getValue() {
        return Objects.toString(getRequestResponseHolder().getRequestInfo().getUrl());
    }

}

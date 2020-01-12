package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;

import javax.annotation.Nullable;
import java.net.URL;
import java.util.Optional;

public class UrlPathPlaceholder extends AbstractPlaceholder {

    public UrlPathPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%A", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue() {
        return Optional.ofNullable(getRequestResponseHolder().getRequestInfo().getUrl()).map(URL::getPath).orElse(null);
    }

}

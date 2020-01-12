package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;

import javax.annotation.Nullable;
import java.net.URL;
import java.util.Optional;

public class UrlQueryPlaceholder extends AbstractPlaceholder {

    public UrlQueryPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%Q", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue() {
        return Optional.ofNullable(getRequestResponseHolder().getRequestInfo().getUrl()).map(URL::getQuery).orElse(null);
    }

}

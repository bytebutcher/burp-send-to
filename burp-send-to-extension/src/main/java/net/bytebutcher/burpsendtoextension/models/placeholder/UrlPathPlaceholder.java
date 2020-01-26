package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.net.URL;
import java.util.Optional;

public class UrlPathPlaceholder extends AbstractRequestInfoPlaceholder {

    public UrlPathPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%A", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        return Optional.ofNullable(getRequestInfo().getUrl()).map(URL::getPath).orElse(null);
    }

}

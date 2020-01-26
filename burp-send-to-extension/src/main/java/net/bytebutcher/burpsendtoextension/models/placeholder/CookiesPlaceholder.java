package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.ICookie;
import burp.RequestResponseHolder;
import com.google.common.collect.Lists;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Collectors;

public class CookiesPlaceholder extends AbstractRequestResponseInfoPlaceholder {

    public CookiesPlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation iContextMenuInvocation) {
        super("%C", true, false, requestResponseHolder, iContextMenuInvocation);
    }

    @Nullable
    @Override
    protected String getInternalValue(Context context) {
        List<ICookie> cookies = Lists.newArrayList();
        switch (context) {
            case HTTP_REQUEST:
                cookies = getRequestInfo().getCookies();
                break;
            case HTTP_RESPONSE:
                cookies = getResponseInfo().getCookies();
                break;
        }
        return cookies.isEmpty() ? null : cookies.stream().map(iCookie -> iCookie.getName() + "=" + iCookie.getValue()).collect(Collectors.joining(","));
    }

}

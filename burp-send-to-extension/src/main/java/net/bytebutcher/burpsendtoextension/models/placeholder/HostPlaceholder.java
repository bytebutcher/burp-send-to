package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;

public class HostPlaceholder extends AbstractPlaceholder {

    public HostPlaceholder() {
        super("%H", true, false);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestPlaceholder(this, requestResponseHolder) {

            @Nullable
            @Override
            protected String getInternalValue(Context context) {
                return getHttpRequestResponse().getHttpService().getHost();
            }

        };
    }
}

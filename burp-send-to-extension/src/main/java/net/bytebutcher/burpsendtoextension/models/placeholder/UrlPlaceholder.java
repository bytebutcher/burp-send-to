package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.util.Objects;

public class UrlPlaceholder extends AbstractPlaceholder {

    public UrlPlaceholder() {
        super("%U", true, false);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestInfoPlaceholder(this, requestResponseHolder) {
            @Nullable
            @Override
            protected String getInternalValue(Context context) {
                return Objects.toString(getRequestInfo().getUrl());
            }
        };
    }
}

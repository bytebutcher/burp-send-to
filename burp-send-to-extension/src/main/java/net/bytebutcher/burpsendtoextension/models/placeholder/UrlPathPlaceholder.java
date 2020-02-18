package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.net.URL;
import java.util.Optional;

public class UrlPathPlaceholder extends AbstractPlaceholder {

    public UrlPathPlaceholder() {
        super("%A", true, false);
    }

    @Override
    public IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder) {
        return new AbstractRequestInfoPlaceholder(this, requestResponseHolder) {
            @Nullable
            @Override
            protected String getInternalValue(Context context) {
                return Optional.ofNullable(getRequestInfo().getUrl()).map(URL::getPath).orElse(null);
            }
        };
    }
}

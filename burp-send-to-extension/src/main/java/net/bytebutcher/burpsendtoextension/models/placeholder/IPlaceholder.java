package net.bytebutcher.burpsendtoextension.models.placeholder;

import net.bytebutcher.burpsendtoextension.models.Context;

public interface IPlaceholder {
    String getPlaceholder();

    String getValue(Context context) throws RuntimeException;

    boolean doesRequireShellEscape();

    boolean isValid(Context context);
}

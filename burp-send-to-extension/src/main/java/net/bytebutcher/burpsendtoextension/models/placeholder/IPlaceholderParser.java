package net.bytebutcher.burpsendtoextension.models.placeholder;

import net.bytebutcher.burpsendtoextension.models.Context;

public interface IPlaceholderParser extends IPlaceholder {

    String getValue(Context context) throws RuntimeException;

    boolean isValid(Context context);

}

package net.bytebutcher.burpsendtoextension.models.placeholder;

public interface IPlaceholder {
    String getPlaceholder();

    String getValue(String text) throws RuntimeException;

    boolean doesRequireShellEscape();

    boolean isValid();
}

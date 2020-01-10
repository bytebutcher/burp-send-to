package net.bytebutcher.burpsendtoextension.models.placeholder;

public interface IPlaceholder {
    String getPlaceholder();

    String replace(String text) throws Exception;

    boolean isValid();
}

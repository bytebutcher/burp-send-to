package net.bytebutcher.burpsendtoextension.models.placeholder;

public interface IPlaceholder {

    String getPlaceholder();

    boolean doesRequireShellEscape();

    boolean shouldWriteToFile();
}

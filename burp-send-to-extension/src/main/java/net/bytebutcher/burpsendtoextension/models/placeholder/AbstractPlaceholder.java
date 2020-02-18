package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;

public abstract class AbstractPlaceholder implements IPlaceholder, IPlaceholderParserFactory {

    private final String placeholder;
    private final boolean doesRequireShellEscape;
    private final boolean shouldWriteToFile;

    public AbstractPlaceholder(String placeholder, boolean doesRequireShellEscape, boolean shouldWriteToFile) {
        this.placeholder = placeholder;
        this.doesRequireShellEscape = doesRequireShellEscape;
        this.shouldWriteToFile = shouldWriteToFile;
    }

    public String getPlaceholder() {
        return placeholder;
    }

    /**
     * Returns whether the placeholder requires shell-escaping.
     */
    public boolean doesRequireShellEscape() {
        return doesRequireShellEscape;
    }


    public boolean shouldWriteToFile() {
        return shouldWriteToFile;
    }

    public abstract IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder);
}

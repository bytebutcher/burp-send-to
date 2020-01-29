package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.io.File;
import java.io.PrintWriter;
import java.util.Optional;

public abstract class AbstractRequestResponsePlaceholderBase implements IPlaceholder {

    private final RequestResponseHolder requestResponseHolder;
    private final String placeholder;
    private final boolean doesRequireShellEscape;
    private final boolean doWriteToFile;

    public AbstractRequestResponsePlaceholderBase(String placeholder, boolean doesRequireShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder) {
        this.requestResponseHolder = requestResponseHolder;
        this.placeholder = placeholder;
        this.doesRequireShellEscape = doesRequireShellEscape;
        this.doWriteToFile = doWriteToFile;
    }

    @Override
    public String getPlaceholder() {
        return placeholder;
    }

    /**
     * Returns the value associated with the placeholder.
     *
     * @return the value associated with the placeholder.
     */
    @Nullable
    protected abstract String getInternalValue(Context context) throws Exception;

    /**
     * Returns whether the placeholder requires shell-escaping.
     */
    public boolean doesRequireShellEscape() {
        return doesRequireShellEscape;
    }

    @Override
    public String getValue(Context context) throws RuntimeException {
        try {
            String value = Optional.ofNullable(getInternalValue(context)).orElse("");
            if (doWriteToFile) {
                value = writeToFile(value);
            }
            return value;
        } catch (Exception e) {
            // This exception is thrown when the placeholder can not be constructed (e.g. no text selected,
            // no url-query-parameter present, etc.). This is done in favor of returning empty text.
            // In practice this exception should not be thrown anyway since menu items which contain this placeholder
            // are disabled and can not be selected anyway (see isValid()).
            throw new RuntimeException("Error replacing placeholder " + getPlaceholder() + " !", e);
        }
    }

    private String writeToFile(String value) throws Exception {
        try {
            File tmp = File.createTempFile("burp_", ".snd");
            PrintWriter out = new PrintWriter(tmp.getPath());
            out.write(value);
            out.flush();
            return tmp.getAbsolutePath();
        } catch (RuntimeException e) {
            throw new Exception(this.getClass().getSimpleName() + ": Error writing to temporary file!", e);
        }
    }

    @Override
    public boolean isValid(Context context) {
        try {
            return getInternalValue(context) != null;
        } catch (Exception e) {
            return false;
        }
    }
}

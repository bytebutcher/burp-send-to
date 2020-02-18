package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;
import net.bytebutcher.burpsendtoextension.models.Context;

import javax.annotation.Nullable;
import java.io.File;
import java.io.PrintWriter;
import java.util.Optional;

public abstract class AbstractRequestResponsePlaceholderBase implements IPlaceholderParser {

    private final IPlaceholder placeholder;
    private final RequestResponseHolder requestResponseHolder;

    public AbstractRequestResponsePlaceholderBase(IPlaceholder placeholder, RequestResponseHolder requestResponseHolder) {
        this.placeholder = placeholder;
        this.requestResponseHolder = requestResponseHolder;
    }

    public String getPlaceholder() {
        return placeholder.getPlaceholder();
    }

    public boolean doesRequireShellEscape() {
        return placeholder.doesRequireShellEscape();
    }

    public boolean shouldWriteToFile() { return placeholder.shouldWriteToFile(); }

    /**
     * Returns the value associated with the placeholder.
     *
     * @return the value associated with the placeholder.
     */
    @Nullable
    protected abstract String getInternalValue(Context context) throws Exception;

    @Override
    public String getValue(Context context) throws RuntimeException {
        try {
            String value = Optional.ofNullable(getInternalValue(context)).orElse("");
            if (placeholder.shouldWriteToFile()) {
                value = writeToFile(value);
            }
            return value;
        } catch (Exception e) {
            // This exception is thrown when the placeholder can not be constructed (e.g. no text selected,
            // no url-query-parameter present, etc.). This is done in favor of returning empty text.
            // In practice this exception should not be thrown anyway since menu items which contain this placeholder
            // are disabled and can not be selected anyway (see isValid()).
            throw new RuntimeException("Error replacing placeholder " + placeholder.getPlaceholder() + " !", e);
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

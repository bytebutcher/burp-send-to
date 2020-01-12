package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;
import com.google.common.collect.Lists;

import javax.annotation.Nullable;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Optional;

public abstract class AbstractPlaceholder implements IPlaceholder {

    protected enum Context {HTTP_RESPONSE, HTTP_REQUEST, UNKNOWN}

    private final RequestResponseHolder requestResponseHolder;
    private final String placeholder;
    private final boolean doesRequireShellEscape;
    private final boolean doWriteToFile;
    private final IContextMenuInvocation contextMenuInvocation;
    private Context context;

    public AbstractPlaceholder(String placeholder, boolean doesRequireShellEscape, boolean doWriteToFile, RequestResponseHolder requestResponseHolder, IContextMenuInvocation contextMenuInvocation) {
        this.requestResponseHolder = requestResponseHolder;
        this.placeholder = placeholder;
        this.doesRequireShellEscape = doesRequireShellEscape;
        this.doWriteToFile = doWriteToFile;
        this.contextMenuInvocation = contextMenuInvocation;
        this.context = getContext();
    }

    /**
     * NOTE: Access to IContextMenuInvocation is restricted to prevent accessing getSelectedMessage.
     *       Messages should always be accessed via RequestResponseHolder. Notably using IContextMenuInvocation
     *       within this class is a minor design issue.
     */
    private IContextMenuInvocation getContextMenuInvocation() {
        return contextMenuInvocation;
    }

    protected int[] getSelectionBounds() {
        return this.getContextMenuInvocation().getSelectionBounds();
    }

    protected RequestResponseHolder getRequestResponseHolder() {
        return requestResponseHolder;
    }

    protected Context getContext() {
        if (context == null) {
            ArrayList<Byte> requestContext = Lists.newArrayList(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST);
            ArrayList<Byte> responseContext = Lists.newArrayList(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE);
            if (requestContext.contains(contextMenuInvocation.getInvocationContext())) {
                context = Context.HTTP_REQUEST;
            } else if (responseContext.contains(contextMenuInvocation.getInvocationContext())) {
                context = Context.HTTP_RESPONSE;
            } else {
                context = Context.UNKNOWN;
            }
        }
        return context;
    }

    @Override
    public String getPlaceholder() {
        return placeholder;
    }

    public byte[] getRequestResponse() {
        switch(getContext()) {
            case HTTP_REQUEST:
                return getRequestResponseHolder().getHttpRequestResponse().getRequest();
            case HTTP_RESPONSE:
                return getRequestResponseHolder().getHttpRequestResponse().getResponse();
        }
        return null;
    }

    /**
     * Returns the value associated with the placeholder.
     *
     * @return the value associated with the placeholder.
     */
    @Nullable
    protected abstract String getInternalValue() throws Exception;

    /**
     * Returns whether the placeholder requires shell-escaping.
     */
    public boolean doesRequireShellEscape() {
        return doesRequireShellEscape;
    }

    @Override
    public String getValue(String text) throws RuntimeException {
        try {
            String value = Optional.ofNullable(getInternalValue()).orElse("");
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
    public boolean isValid() {
        try {
            return getInternalValue() != null;
        } catch (Exception e) {
            return false;
        }
    }
}

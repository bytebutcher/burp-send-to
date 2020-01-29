package net.bytebutcher.burpsendtoextension.models;

import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import com.google.common.collect.Lists;

import java.util.ArrayList;

public class Context {
    private final Origin origin;
    private final IContextMenuInvocation invocation;

    public enum Origin {
        HTTP_RESPONSE, HTTP_REQUEST, UNKNOWN;

        public static Origin getTarget(IContextMenuInvocation contextMenuInvocation) {
            ArrayList<Byte> requestContext = Lists.newArrayList(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST);
            ArrayList<Byte> responseContext = Lists.newArrayList(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE);
            if (requestContext.contains(contextMenuInvocation.getInvocationContext())) {
                return Origin.HTTP_REQUEST;
            } else if (responseContext.contains(contextMenuInvocation.getInvocationContext())) {
                return Origin.HTTP_RESPONSE;
            } else {
                return Origin.UNKNOWN;
            }
        }

    }

    public Context(Origin origin, IContextMenuInvocation invocation) {
        this.origin = origin;
        this.invocation = invocation;
    }

    public Context(IContextMenuInvocation invocation) {
        this(Origin.getTarget(invocation), invocation);
    }

    public Origin getOrigin() {
        return origin;
    }

    /**
     * NOTE: Access to getSelectedMessages should be restricted, since messages should always be accessed via
     *       RequestResponseHolder. Notably the definition and usage of this function here is a minor design issue.
     */
    public IHttpRequestResponse[] getSelectedMessages() {
        return invocation.getSelectedMessages();
    }

    public int[] getSelectionBounds() {
        return invocation.getSelectionBounds();
    }

}
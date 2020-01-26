package net.bytebutcher.burpsendtoextension.models;

import burp.IContextMenuInvocation;
import com.google.common.collect.Lists;

import java.util.ArrayList;

public enum Context {
    HTTP_RESPONSE, HTTP_REQUEST, UNKNOWN;

    public static Context getContext(IContextMenuInvocation contextMenuInvocation) {
        ArrayList<Byte> requestContext = Lists.newArrayList(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST);
        ArrayList<Byte> responseContext = Lists.newArrayList(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE);
        if (requestContext.contains(contextMenuInvocation.getInvocationContext())) {
            return Context.HTTP_REQUEST;
        } else if (responseContext.contains(contextMenuInvocation.getInvocationContext())) {
            return Context.HTTP_RESPONSE;
        } else {
            return Context.UNKNOWN;
        }
    }

}

package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.IContextMenuInvocation;
import burp.RequestResponseHolder;

public class SelectedTextToFilePlaceholder extends SelectedTextPlaceholder {

    public SelectedTextToFilePlaceholder(RequestResponseHolder requestResponseHolder, IContextMenuInvocation contextMenuInvocation) {
        super("%F", false, true, requestResponseHolder, contextMenuInvocation);
    }

}

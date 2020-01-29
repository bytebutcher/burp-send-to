package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;

public class SelectedTextToFilePlaceholder extends SelectedTextPlaceholder {

    public SelectedTextToFilePlaceholder(RequestResponseHolder requestResponseHolder) {
        super("%F", false, true, requestResponseHolder);
    }

}

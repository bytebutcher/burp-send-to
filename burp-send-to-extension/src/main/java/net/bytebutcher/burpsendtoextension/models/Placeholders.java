package net.bytebutcher.burpsendtoextension.models;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.RequestResponseHolder;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.bytebutcher.burpsendtoextension.models.placeholder.*;

import java.util.List;
import java.util.Map;

public class Placeholders {

    /**
     * Initializes the placeholders for each selected message and returns them in a list.
     */
    public static List<Map<String, IPlaceholder>> get(IBurpExtenderCallbacks burpExtenderCallbacks, IContextMenuInvocation invocation) {
        List<Map<String, IPlaceholder>> result = Lists.newArrayList();
        for (IHttpRequestResponse selectedMessage : invocation.getSelectedMessages()) {
            RequestResponseHolder requestResponseHolder = new RequestResponseHolder(burpExtenderCallbacks, selectedMessage);
            Map<String, IPlaceholder> placeholderMap = Maps.newHashMap();
            List<IPlaceholder> placeholderList = Lists.newArrayList(
                    new CookiesPlaceholder(requestResponseHolder, invocation),
                    new HostPlaceholder(requestResponseHolder, invocation),
                    new HttpBodyToFilePlaceholder(requestResponseHolder, invocation),
                    new HttpHeadersToFilePlaceholder(requestResponseHolder, invocation),
                    new HttpMethodPlaceholder(requestResponseHolder, invocation),
                    new HttpRequestResponsePlaceholder(requestResponseHolder, invocation),
                    new PortPlaceholder(requestResponseHolder, invocation),
                    new ProtocolPlaceholder(requestResponseHolder, invocation),
                    new SelectedTextPlaceholder(requestResponseHolder, invocation),
                    new SelectedTextToFilePlaceholder(requestResponseHolder, invocation),
                    new UrlPathPlaceholder(requestResponseHolder, invocation),
                    new UrlPlaceholder(requestResponseHolder, invocation),
                    new UrlQueryPlaceholder(requestResponseHolder, invocation));
            for (IPlaceholder placeholder : placeholderList) {
                placeholderMap.put(placeholder.getPlaceholder(), placeholder);
            }
            result.add(placeholderMap);
        }
        return result;
    }
}

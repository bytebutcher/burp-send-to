package net.bytebutcher.burpsendtoextension.models;

import burp.IBurpExtenderCallbacks;
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
    public static List<Map<String, IPlaceholder>> get(IBurpExtenderCallbacks burpExtenderCallbacks, IHttpRequestResponse[] selectedMessages) {
        List<Map<String, IPlaceholder>> result = Lists.newArrayList();
        if (selectedMessages == null) {
            return result;
        }
        for (IHttpRequestResponse selectedMessage : selectedMessages) {
            RequestResponseHolder requestResponseHolder = new RequestResponseHolder(burpExtenderCallbacks, selectedMessage);
            Map<String, IPlaceholder> placeholderMap = Maps.newHashMap();
            List<IPlaceholder> placeholderList = Lists.newArrayList(
                    new CookiesPlaceholder(requestResponseHolder),
                    new HostPlaceholder(requestResponseHolder),
                    new HttpBodyToFilePlaceholder(requestResponseHolder),
                    new HttpHeadersToFilePlaceholder(requestResponseHolder),
                    new HttpMethodPlaceholder(requestResponseHolder),
                    new HttpRequestResponsePlaceholder(requestResponseHolder),
                    new PortPlaceholder(requestResponseHolder),
                    new ProtocolPlaceholder(requestResponseHolder),
                    new SelectedTextPlaceholder(requestResponseHolder),
                    new SelectedTextToFilePlaceholder(requestResponseHolder),
                    new UrlPathPlaceholder(requestResponseHolder),
                    new UrlPlaceholder(requestResponseHolder),
                    new UrlQueryPlaceholder(requestResponseHolder));
            for (IPlaceholder placeholder : placeholderList) {
                placeholderMap.put(placeholder.getPlaceholder(), placeholder);
            }
            result.add(placeholderMap);
        }
        return result;
    }
}

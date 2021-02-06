package net.bytebutcher.burpsendtoextension.models;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.RequestResponseHolder;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.bytebutcher.burpsendtoextension.models.placeholder.*;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Placeholders {

    public static List<AbstractPlaceholder> get() {
        return Lists.newArrayList(
                new CookiesPlaceholder(),
                new HostPlaceholder(),
                new HttpBodyToFilePlaceholder(),
                new HttpContentLengthPlaceholder(),
                new HttpHeadersToFilePlaceholder(),
                new HttpMethodPlaceholder(),
                new HttpRequestResponsePlaceholder(),
                new HttpStatusCodePlaceholder(),
                new PortPlaceholder(),
                new ProtocolPlaceholder(),
                new SelectedTextPlaceholder(),
                new SelectedTextToFilePlaceholder(),
                new UrlPathPlaceholder(),
                new UrlPlaceholder(),
                new UrlQueryPlaceholder());
    }

    /**
     * Initializes the placeholders for each selected message and returns them in a list.
     */
    public static List<Map<String, IPlaceholderParser>> get(IBurpExtenderCallbacks burpExtenderCallbacks, IHttpRequestResponse[] selectedMessages) {
        List<Map<String, IPlaceholderParser>> result = Lists.newArrayList();
        if (selectedMessages == null) {
            return result;
        }
        List<AbstractPlaceholder> placeholderList = Placeholders.get();
        for (IHttpRequestResponse selectedMessage : selectedMessages) {
            RequestResponseHolder requestResponseHolder = new RequestResponseHolder(burpExtenderCallbacks, selectedMessage);
            Map<String, IPlaceholderParser> placeholderMap = Maps.newHashMap();
            for (AbstractPlaceholder placeholder : placeholderList) {
                placeholderMap.put(placeholder.getPlaceholder(), placeholder.createParser(requestResponseHolder));
            }
            result.add(placeholderMap);
        }
        return result;
    }

    public static List<CommandObject.Placeholder> get(String format) {
        List<String> validPlaceholders = Placeholders.get().stream().map(AbstractPlaceholder::getPlaceholder).collect(Collectors.toList());
        List<CommandObject.Placeholder> placeholders = Lists.newArrayList();
        if (format != null && !format.isEmpty()) {
            Matcher m = Pattern.compile("(\\%[A-Z])").matcher(format);
            while (m.find()) {
                String placeholder = m.group(1);
                if (validPlaceholders.contains(placeholder)) {
                    placeholders.add(new CommandObject.Placeholder(placeholder, null, m.start(), m.end()));
                }
            }
        }
        return placeholders;
    }
}

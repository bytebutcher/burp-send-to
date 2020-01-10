package burp;

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class RequestInfoWrapper implements IRequestInfoWrapper {

    private IHttpRequestResponse httpRequestResponse;
    private IRequestInfo requestInfo;
    private List<ICookie> cookies;
    private String requestBody;

    public RequestInfoWrapper(IHttpRequestResponse httpRequestResponse, IRequestInfo requestInfo) {
        this.httpRequestResponse = httpRequestResponse;
        this.requestInfo = requestInfo;
    }

    @Override
    public List<ICookie> getCookies() {
        if (cookies == null) {
            String cookieHeaderPrefix = "cookie: ";
            cookies = Cookie.parseRequestCookies(requestInfo.getHeaders().stream().filter(s -> s.toLowerCase().startsWith(cookieHeaderPrefix)).map(s -> s.substring(cookieHeaderPrefix.length() - 1)).collect(Collectors.toList()));
        }
        return cookies;
    }

    @Override
    public String getBody() {
        if (requestBody == null) {
            byte[] request = httpRequestResponse.getRequest();
            int bodyOffset = this.getBodyOffset();
            requestBody = new String(Arrays.copyOfRange(request, bodyOffset, request.length));
        }
        return requestBody;
    }

    @Override
    public String getMethod() {
        return requestInfo.getMethod();
    }

    @Override
    public URL getUrl() {
        return requestInfo.getUrl();
    }

    @Override
    public List<String> getHeaders() {
        return requestInfo.getHeaders();
    }

    @Override
    public List<IParameter> getParameters() {
        return requestInfo.getParameters();
    }

    @Override
    public int getBodyOffset() {
        return requestInfo.getBodyOffset();
    }

    @Override
    public byte getContentType() {
        return requestInfo.getContentType();
    }
}

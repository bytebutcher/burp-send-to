package burp;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class ResponseInfoWrapper implements IResponseInfoWrapper {

    private IHttpRequestResponse httpRequestResponse;
    private IResponseInfo responseInfo;
    private List<ICookie> cookies;
    private String responseBody;

    public ResponseInfoWrapper(IHttpRequestResponse httpRequestResponse, IResponseInfo responseInfo) {
        this.httpRequestResponse = httpRequestResponse;
        this.responseInfo = responseInfo;
    }

    @Override
    public List<String> getHeaders() {
        return responseInfo.getHeaders();
    }

    @Override
    public int getBodyOffset() {
        return responseInfo.getBodyOffset();
    }

    @Override
    public short getStatusCode() {
        return responseInfo.getStatusCode();
    }

    @Override
    public List<ICookie> getCookies() {
        if (cookies == null) {
            String cookieHeaderPrefix = "set-cookie: ";
            cookies = Cookie.parseResponseCookies(responseInfo.getHeaders().stream().filter(s -> s.toLowerCase().startsWith(cookieHeaderPrefix)).map(s -> s.substring(cookieHeaderPrefix.length() - 1)).collect(Collectors.toList()));
        }
        return cookies;
    }

    @Override
    public String getStatedMimeType() {
        return responseInfo.getStatedMimeType();
    }

    @Override
    public String getInferredMimeType() {
        return responseInfo.getInferredMimeType();
    }

    @Override
    public String getBody() {
        if (responseBody == null) {
            byte[] response = httpRequestResponse.getResponse();
            int bodyOffset = this.getBodyOffset();
            responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length));
        }
        return responseBody;
    }
}

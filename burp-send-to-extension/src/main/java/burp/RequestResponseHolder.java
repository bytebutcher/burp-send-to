package burp;

public class RequestResponseHolder implements IRequestResponseHolder {

    private final IBurpExtenderCallbacks burpExtenderCallbacks;
    private final IHttpRequestResponse httpRequestResponse;
    private IRequestInfoWrapper requestInfo;
    private IResponseInfoWrapper responseInfo;

    public RequestResponseHolder(IBurpExtenderCallbacks burpExtenderCallbacks, IHttpRequestResponse httpRequestResponse) {
        this.burpExtenderCallbacks = burpExtenderCallbacks;
        this.httpRequestResponse = httpRequestResponse;
    }

    @Override
    public IRequestInfoWrapper getRequestInfo() {
        if (requestInfo == null) {
            requestInfo = new RequestInfoWrapper(httpRequestResponse, burpExtenderCallbacks.getHelpers().analyzeRequest(httpRequestResponse.getHttpService(), httpRequestResponse.getRequest()));
        }
        return requestInfo;
    }

    @Override
    public IResponseInfoWrapper getResponseInfo() {
        if (responseInfo == null) {
            responseInfo = new ResponseInfoWrapper(httpRequestResponse, burpExtenderCallbacks.getHelpers().analyzeResponse(httpRequestResponse.getResponse()));
        }
        return responseInfo;
    }

    @Override
    public IBurpExtenderCallbacks getBurpExtenderCallbacks() {
        return burpExtenderCallbacks;
    }

    @Override
    public IHttpRequestResponse getHttpRequestResponse() {
        return httpRequestResponse;
    }

}

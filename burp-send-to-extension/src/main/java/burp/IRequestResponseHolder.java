package burp;

public interface IRequestResponseHolder {
    IRequestInfo getRequestInfo();

    IResponseInfo getResponseInfo();

    IBurpExtenderCallbacks getBurpExtenderCallbacks();

    IHttpRequestResponse getHttpRequestResponse();
}

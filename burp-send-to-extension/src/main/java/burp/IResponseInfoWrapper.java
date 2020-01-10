package burp;

import java.util.List;

public interface IResponseInfoWrapper extends IResponseInfo {

    List<ICookie> getCookies();
    String getBody();

}

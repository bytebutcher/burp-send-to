package burp;

import java.util.List;

public interface IRequestInfoWrapper extends IRequestInfo {

    List<ICookie> getCookies();
    String getBody();

}

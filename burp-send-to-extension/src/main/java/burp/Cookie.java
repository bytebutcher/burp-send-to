package burp;

import com.google.common.collect.Lists;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Implements the ICookie interface which holds details about an HTTP cookie.
 * @author Thomas Engel
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class Cookie implements ICookie {

    private String name;
    private String value;
    private String domain;
    private String path;
    private Date expiration;
    private Long maxAge;
    private Boolean secure = false;
    private Boolean httpOnly = false;

    public Cookie(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public Cookie(ICookie cookie) {
        this.name = cookie.getName();
        this.value = cookie.getValue();
        this.domain = cookie.getDomain();
        this.path = cookie.getPath();
        this.expiration = cookie.getExpiration();
    }

    /**
     * Parses a list of HTTP response header fields containing the raw cookie
     * _value_ (Minus "Set-Cookie:").
     *
     * @param rawCookies A list of string containing the raw cookie
     * @return A list of ICookie objects parsed from a list of raw cookie strings
     */
    public static List<ICookie> parseResponseCookies(List<String> rawCookies) {
        return rawCookies.stream().map(Cookie::parseResponseCookie).filter(Optional::isPresent).map(Optional::get).collect(Collectors.toList());
    }

    /**
     * Parses a cookie from a String containing the raw HTTP response header
     * _value_ (Minus "Set-Cookie:").
     *
     * @param rawCookie A String containing the raw cookie
     * @return A Cookie object parsed from the raw cookie string
     */
    private static Optional<ICookie> parseResponseCookie(String rawCookie) {
        String[] rawCookieParams = rawCookie.split(";");

        //get the cookie name, check for valid cookie
        String[] rawCookieNameAndValue = rawCookieParams[0].split("=");
        String cookieName = rawCookieNameAndValue[0].trim();
        if (cookieName.isEmpty()) {
            BurpExtender.printErr("Invalid cookie: missing name");
            return Optional.empty();
        }

        //get the cookie value
        String cookieValue = rawCookieNameAndValue[1].trim();

        //construct output
        Cookie output = new Cookie(cookieName, cookieValue);

        //parse other cookie params
        for (int i = 1; i < rawCookieParams.length; i++) {
            String[] rawCookieParam = rawCookieParams[i].trim().split("=");

            String paramName = rawCookieParam[0].trim();

            if ("secure".equalsIgnoreCase(paramName)) {
                output.setSecure(true);

            } else if ("HttpOnly".equalsIgnoreCase(paramName)) {
                output.setHttpOnly(true);

            } else {
                if (rawCookieParam.length != 2) {
                    //attribute not a flag or missing value
                    continue;
                }
                String paramValue = rawCookieParam[1].trim();

                if ("expires".equalsIgnoreCase(paramName)) {
                    try {
                        SimpleDateFormat format = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss zzz");
                        Date expiryDate = format.parse(paramValue);
                        output.setExpiration(expiryDate);
                    } catch (Exception e) {
                        //couldn't parse date, ignore
                        BurpExtender.printErr("WARNING: unable to parse cookie expiration: " + paramValue);
                    }
                } else if ("max-age".equalsIgnoreCase(paramName)) {
                    long maxAge = Long.parseLong(paramValue);
                    output.setMaxAge(maxAge);
                } else if ("domain".equalsIgnoreCase(paramName)) {
                    output.setDomain(paramValue);
                } else if ("path".equalsIgnoreCase(paramName)) {
                    output.setPath(paramValue);
                }
            }
        }

        return Optional.of(output);
    }

    /**
     * Parses cookies from a list of raw HTTP request headers
     * _value_ (Minus "Cookie:").
     *
     * @param rawCookies A list of strings containing the raw cookie
     * @return A list of ICookie objects parsed from a list of raw cookie strings
     */
    public static List<ICookie> parseRequestCookies(List<String> rawCookies) {
        return rawCookies.stream().map(Cookie::parseRequestCookies).flatMap(Collection::stream).collect(Collectors.toList());
    }

    /**
     * Parses a cookie from a String containing the raw HTTP request header
     * _value_ (Minus "Cookie:").
     *
     * @param rawCookie A String containing the raw cookie
     * @return A list of Cookie objects parsed from the raw cookie string
     */
    public static List<ICookie> parseRequestCookies(String rawCookie) {
        List<ICookie> cookies = Lists.newArrayList();
        String[] rawCookieParams = rawCookie.split(";");
        for (String rawCookieParam : rawCookieParams) {
            //get the cookie name, check for valid cookie
            String[] rawCookieNameAndValue = rawCookieParam.split("=");
            String cookieName = rawCookieNameAndValue[0].trim();
            if (cookieName.isEmpty() || !rawCookieParam.contains("=")) {
                BurpExtender.printErr("Invalid cookie: missing name");
                continue;
            }

            //get the cookie value
            String cookieValue = "";
            if (rawCookieNameAndValue.length != 1) {
                cookieValue = rawCookieNameAndValue[1].trim();
            }

            //construct output
            cookies.add(new Cookie(cookieName, cookieValue));
        }

        return cookies;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    @Override
    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public Date getExpiration() {
        return expiration;
    }

    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

    public Long getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(Long maxAge) {
        this.maxAge = maxAge;
    }

    public Boolean getSecure() {
        return secure;
    }

    public void setSecure(Boolean secure) {
        this.secure = secure;
    }

    public Boolean getHttpOnly() {
        return httpOnly;
    }

    public void setHttpOnly(Boolean httpOnly) {
        this.httpOnly = httpOnly;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Cookie cookie = (Cookie) o;
        return Objects.equals(name, cookie.name) &&
                Objects.equals(value, cookie.value) &&
                Objects.equals(domain, cookie.domain) &&
                Objects.equals(path, cookie.path) &&
                Objects.equals(expiration, cookie.expiration) &&
                Objects.equals(maxAge, cookie.maxAge) &&
                Objects.equals(secure, cookie.secure) &&
                Objects.equals(httpOnly, cookie.httpOnly);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, value, domain, path, expiration, maxAge, secure, httpOnly);
    }
}
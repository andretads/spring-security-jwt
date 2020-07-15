package br.com.damsete.security.cookies;

import br.com.damsete.security.ciphers.SecurityCipher;
import br.com.damsete.security.properties.SecurityProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Service
public class CookieProvider {

    private final SecurityProperty securityProperty;
    private final SecurityCipher securityCipher;

    @Autowired
    public CookieProvider(SecurityProperty securityProperty,
                          SecurityCipher securityCipher) {
        this.securityProperty = securityProperty;
        this.securityCipher = securityCipher;
    }

    public HttpCookie createAccessTokenCookie(String token, long duration) {
        var encryptedToken = this.securityCipher.encrypt(token);
        return ResponseCookie.from("accessToken", encryptedToken)
                .secure(this.securityProperty.isEnableHttps())
                .maxAge(duration)
                .httpOnly(true)
                .path("/")
                .build();
    }

    public HttpCookie createRefreshTokenCookie(String token, long duration) {
        var encryptedToken = this.securityCipher.encrypt(token);
        return ResponseCookie.from("refreshToken", encryptedToken)
                .secure(this.securityProperty.isEnableHttps())
                .maxAge(duration)
                .httpOnly(true)
                .path("/")
                .build();
    }

    public void deleteTokensCookie(HttpServletRequest request, HttpServletResponse response) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                cookie.setSecure(this.securityProperty.isEnableHttps());
                cookie.setMaxAge(0);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setValue("");
                response.addCookie(cookie);
            }
        }
    }
}

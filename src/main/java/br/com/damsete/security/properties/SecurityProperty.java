package br.com.damsete.security.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SecurityProperty.class)
@ConfigurationProperties(prefix = "security")
public class SecurityProperty {

    private String allowOrigin;
    private boolean enableHttps = false;
    private String tokenSecret;
    private Long tokenExpiration;
    private Long refreshTokenExpiration;

    public String getAllowOrigin() {
        return allowOrigin;
    }

    public void setAllowOrigin(String allowOrigin) {
        this.allowOrigin = allowOrigin;
    }

    public boolean isEnableHttps() {
        return enableHttps;
    }

    public void setEnableHttps(boolean enableHttps) {
        this.enableHttps = enableHttps;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    public Long getTokenExpiration() {
        return tokenExpiration;
    }

    public void setTokenExpiration(Long tokenExpiration) {
        this.tokenExpiration = tokenExpiration;
    }

    public Long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }

    public void setRefreshTokenExpiration(Long refreshTokenExpiration) {
        this.refreshTokenExpiration = refreshTokenExpiration;
    }
}

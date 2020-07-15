package br.com.damsete.security.tokens;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.time.LocalDateTime;

public class Tokens {

    private final Token accessToken;
    private final Token refreshToken;

    public Tokens(Token accessToken, Token refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public boolean hasRefreshToken() {
        return this.refreshToken != null;
    }

    public String getAccessTokenValue() {
        return this.accessToken.getTokenValue();
    }

    public long getAccessTokenDuration() {
        return this.accessToken.getDuration();
    }

    public String getRefreshTokenValue() {
        return this.refreshToken.getTokenValue();
    }

    public long getRefreshTokenDuration() {
        return this.refreshToken.getDuration();
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
    }

    public static class Token {

        private final LocalDateTime expiryDate;
        private final TokenType tokenType;
        private final String tokenValue;
        private final long duration;

        public Token(LocalDateTime expiryDate, TokenType tokenType, String tokenValue, long duration) {
            this.expiryDate = expiryDate;
            this.tokenType = tokenType;
            this.tokenValue = tokenValue;
            this.duration = duration;
        }

        public LocalDateTime getExpiryDate() {
            return expiryDate;
        }

        public TokenType getTokenType() {
            return tokenType;
        }

        public String getTokenValue() {
            return tokenValue;
        }

        public long getDuration() {
            return duration;
        }

        @Override
        public String toString() {
            return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
        }

        public enum TokenType {
            ACCESS, REFRESH
        }
    }
}

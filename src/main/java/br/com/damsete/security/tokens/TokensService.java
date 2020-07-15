package br.com.damsete.security.tokens;

import br.com.damsete.security.ciphers.SecurityCipher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TokensService {

    private final SecurityCipher securityCipher;
    private final TokenProvider tokenProvider;

    @Autowired
    public TokensService(SecurityCipher securityCipher,
                         TokenProvider tokenProvider) {
        this.securityCipher = securityCipher;
        this.tokenProvider = tokenProvider;
    }

    public Tokens getTokens(String username, String accessToken, String refreshToken) {
        var decryptedAccessToken = this.securityCipher.decrypt(accessToken);
        var decryptedRefreshToken = this.securityCipher.decrypt(refreshToken);

        var accessTokenValid = this.tokenProvider.validateToken(decryptedAccessToken);
        var refreshTokenValid = this.tokenProvider.validateToken(decryptedRefreshToken);

        Tokens tokens = null;
        if (!accessTokenValid && !refreshTokenValid) {
            tokens = new Tokens(this.tokenProvider.generateAccessToken(username),
                    this.tokenProvider.generateRefreshToken(username));
        }

        if (!accessTokenValid && refreshTokenValid) {
            tokens = new Tokens(this.tokenProvider.generateAccessToken(username), null);
        }

        if (accessTokenValid && refreshTokenValid) {
            tokens = new Tokens(this.tokenProvider.generateAccessToken(username),
                    this.tokenProvider.generateRefreshToken(username));
        }

        return tokens;
    }

    public Tokens.Token refreshToken(String refreshToken) {
        var decryptedRefreshToken = this.securityCipher.decrypt(refreshToken);

        var refreshTokenValid = this.tokenProvider.validateToken(decryptedRefreshToken);
        if (!refreshTokenValid) {
            return null;
        }

        var username = this.tokenProvider.getUsernameFromToken(decryptedRefreshToken);

        return this.tokenProvider.generateAccessToken(username);
    }
}

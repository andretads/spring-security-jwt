package br.com.damsete.security.tokens;

import br.com.damsete.security.properties.SecurityProperty;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Service
public class TokenProvider {

    private final Logger logger = LogManager.getLogger();
    private final SecurityProperty securityProperty;

    @Autowired
    public TokenProvider(SecurityProperty securityProperty) {
        this.securityProperty = securityProperty;
    }

    public Tokens.Token generateAccessToken(String subject) {
        var now = new Date();
        var duration = now.getTime() + this.securityProperty.getTokenExpiration() * 1000;
        var expiryDate = new Date(duration);
        var token = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, this.securityProperty.getTokenSecret())
                .compact();
        return new Tokens.Token(LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault()),
                Tokens.Token.TokenType.ACCESS, token, duration);
    }

    public Tokens.Token generateRefreshToken(String subject) {
        var now = new Date();
        var duration = now.getTime() + this.securityProperty.getRefreshTokenExpiration() * 1000;
        var expiryDate = new Date(duration);
        var token = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, this.securityProperty.getTokenSecret())
                .compact();
        return new Tokens.Token(LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault()),
                Tokens.Token.TokenType.REFRESH, token, duration);
    }

    public String getUsernameFromToken(String token) {
        var claims = Jwts.parser().setSigningKey(this.securityProperty.getTokenSecret()).parseClaimsJws(token).getBody();
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(this.securityProperty.getTokenSecret()).parse(token);
            return true;
        } catch (Exception e) {
            this.logger.warn(e.getMessage(), e);
        }
        return false;
    }
}

package br.com.damsete.security.filters;

import br.com.damsete.security.ciphers.SecurityCipher;
import br.com.damsete.security.tokens.TokenProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Nonnull;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthenticationTokenFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final SecurityCipher securityCipher;
    private final TokenProvider tokenProvider;

    public AuthenticationTokenFilter(UserDetailsService userDetailsService,
                                     SecurityCipher securityCipher,
                                     TokenProvider tokenProvider) {
        this.userDetailsService = userDetailsService;
        this.securityCipher = securityCipher;
        this.tokenProvider = tokenProvider;
    }

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest httpServletRequest,
                                    @Nonnull HttpServletResponse httpServletResponse,
                                    @Nonnull FilterChain filterChain) throws ServletException, IOException {
        var jwtToken = getJwtToken(httpServletRequest);
        if (StringUtils.hasText(jwtToken) && this.tokenProvider.validateToken(jwtToken)) {
            var username = this.tokenProvider.getUsernameFromToken(jwtToken);
            var userDetails = this.userDetailsService.loadUserByUsername(username);
            var authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
            logger.info("authenticated user " + username + ", setting security context");
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private String getJwtToken(HttpServletRequest request) {
        var jwtToken = getJwtFromRequest(request);
        if (jwtToken == null) {
            jwtToken = getJwtFromCookie(request);
        }
        return jwtToken;
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        var bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            var accessToken = bearerToken.replace("Bearer ", "");
            return this.securityCipher.decrypt(accessToken);
        }
        return null;
    }

    private String getJwtFromCookie(HttpServletRequest request) {
        var cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("accessToken".equals(cookie.getName())) {
                    var accessToken = cookie.getValue();
                    return this.securityCipher.decrypt(accessToken);
                }
            }
        }
        return null;
    }
}

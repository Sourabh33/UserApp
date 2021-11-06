package com.library.UserApp.security.jwt;

import com.library.UserApp.exception.JwtAuthException;
import com.library.UserApp.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder().setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public boolean validateJwtToken(String authToken) throws JwtAuthException {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error(e.getMessage());
            throw new JwtAuthException("Invalid JWT signature: "+ e.getMessage(), e);
        } catch (MalformedJwtException e) {
            logger.error(e.getMessage());
            throw new JwtAuthException("Invalid JWT token: "+ e.getMessage(), e);
        } catch (ExpiredJwtException e) {
            logger.error(e.getMessage());
            throw new JwtAuthException("JWT token is expired: "+ e.getMessage(), e);
        } catch (UnsupportedJwtException e) {
            logger.error(e.getMessage());
            throw new JwtAuthException("JWT token is unsupported: "+ e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            logger.error(e.getMessage());
            throw new JwtAuthException("JWT claims string is empty: "+ e.getMessage(), e);
        }
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }
}

package me.pinitgateway.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtTokenProvider {
    private final PublicKey publicKey;

    public JwtTokenProvider(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = parse(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public Long getMemberId(String token) {
        return Long.parseLong(parse(token).getSubject());
    }

    public Claims parse(String token){
        return buildParser()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Collection<? extends GrantedAuthority> getAuthorities(String token) {
        Claims claims = parse(token);
        String roles = claims.get("roles", String.class);
        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.stream(roles.split(","))
                .map(String::trim)
                .filter(r -> !r.isEmpty())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private JwtParser buildParser() {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build();
    }
}

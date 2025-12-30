package me.pinitgateway.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private final Long memberId;
    private final String token;

    public JwtAuthenticationToken(String token) {
        super(Collections.emptyList());
        this.memberId = null;
        this.token = token;
        super.setAuthenticated(false);
    }

    public JwtAuthenticationToken(Long principal, String token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.memberId = principal;
        this.token = token;
        super.setAuthenticated(true);
    }

    @Override
    public String getCredentials() {
        return token;
    }

    @Override
    public Long getPrincipal() {
        return memberId;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException("인증 상태 설정은 생성자에서만 할 수 있습니다.");
        }
        super.setAuthenticated(false);
    }

}

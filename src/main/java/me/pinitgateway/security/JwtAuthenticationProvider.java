package me.pinitgateway.security;

import me.pinitgateway.jwt.JwtAuthenticationToken;
import me.pinitgateway.jwt.JwtTokenProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import reactor.core.publisher.Mono;

import java.util.Collection;

public class JwtAuthenticationProvider  implements ReactiveAuthenticationManager {
    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationProvider(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
        if(!(authentication instanceof JwtAuthenticationToken)){
            return Mono.empty();
        }

        String token = (String) authentication.getCredentials();

        return Mono.fromCallable(() -> {
            if(!jwtTokenProvider.validateToken(token)) {
                throw new BadCredentialsException("Invalid token");
            }

            Long memberId = jwtTokenProvider.getMemberId(token);
            Collection<? extends GrantedAuthority> authorities = jwtTokenProvider.getAuthorities(token);

            return new JwtAuthenticationToken(memberId, token, authorities);
        });
    }
}


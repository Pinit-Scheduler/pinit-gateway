package me.pinitgateway.security;

import me.pinitgateway.jwt.JwtAuthenticationFilter;
import me.pinitgateway.jwt.JwtTokenProvider;
import me.pinitgateway.jwt.RsaKeyProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.net.InetSocketAddress;
import java.security.PublicKey;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${path.key.jwt.public}")
    private String publicKeyPath;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityWebFilterChain authPublicChain(ServerHttpSecurity http) {
        return applyCommon(http)
                .securityMatcher(ServerWebExchangeMatchers.matchers(authHostMatcher(), authPathMatcher()))
                .authorizeExchange(auth -> auth.anyExchange().permitAll())
                .build();
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    public SecurityWebFilterChain mainSecurityFilterChain(ServerHttpSecurity http,
                                                          JwtAuthenticationFilter jwtAuthenticationFilter) {
        return applyCommon(http)
                .authorizeExchange(auth -> auth
                        .pathMatchers("/actuator/health/liveness", "/actuator/health/readiness", "/v3/**", "/swagger-ui/**", "/async-api/**").permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager(JwtAuthenticationProvider jwtAuthenticationProvider) {
        return jwtAuthenticationProvider;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(ReactiveAuthenticationManager authenticationManager) {
        return new JwtAuthenticationFilter(authenticationManager);
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(JwtTokenProvider jwtTokenProvider) {
        return new JwtAuthenticationProvider(jwtTokenProvider);
    }

    @Bean
    public JwtTokenProvider jwtTokenProvider() {
        PublicKey publicKey = RsaKeyProvider.loadPublicKey(publicKeyPath);
        return new JwtTokenProvider(publicKey);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(CorsProperties corsProperties) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(corsProperties.getAllowedOrigins());
        config.setAllowedMethods(corsProperties.getAllowedMethods());
        config.setAllowedHeaders(corsProperties.getAllowedHeaders());
        config.setAllowCredentials(corsProperties.getAllowCredentials());
        config.setMaxAge(corsProperties.getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private ServerHttpSecurity applyCommon(ServerHttpSecurity http) {
        return http
                .cors(Customizer.withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
    }

    private ServerWebExchangeMatcher authHostMatcher() {
        return exchange -> {
            InetSocketAddress host = exchange.getRequest().getHeaders().getHost();
            if (host == null) {
                return ServerWebExchangeMatcher.MatchResult.notMatch();
            }

            String hostString = host.getHostString();
            int port = host.getPort();
            boolean isAuthHost = "auth.pinit.go-gradually.me".equals(hostString)
                    || ("localhost".equals(hostString) && (port == 8081 || port == -1));

            return isAuthHost
                    ? ServerWebExchangeMatcher.MatchResult.match()
                    : ServerWebExchangeMatcher.MatchResult.notMatch();
        };
    }

    private ServerWebExchangeMatcher authPathMatcher() {
        return ServerWebExchangeMatchers.pathMatchers(
                "/login",
                "/signup",
                "/refresh",
                "/login/**"
        );
    }
}

/**
 * 현재 필터 규칙
 * - /actuator/health/liveness : 인증 안함
 * - /actuator/health/readiness : 인증 안함
 * - /v3/** : 인증 안함
 * - /swagger-ui/** : 인증 안함
 * - /async-api/** : 인증 안함
 * - auth host + /login : 인증 안함
 * - auth host + /signup : 인증 안함
 * - auth host + /refresh : 인증 안함
 * - auth host + /login/** : 인증 안함
 * - 그 외 : 인증 필요
 */

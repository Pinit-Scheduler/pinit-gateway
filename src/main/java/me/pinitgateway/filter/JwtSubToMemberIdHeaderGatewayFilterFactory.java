package me.pinitgateway.filter;

import me.pinitgateway.jwt.JwtAuthenticationToken;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

@Component
public class JwtSubToMemberIdHeaderGatewayFilterFactory
        extends AbstractGatewayFilterFactory<JwtSubToMemberIdHeaderGatewayFilterFactory.Config> {

    public JwtSubToMemberIdHeaderGatewayFilterFactory() {
        super(Config.class);
    }

    public static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) ->
                exchange.getPrincipal()
                        .filter(Authentication.class::isInstance)
                        .cast(Authentication.class)
                        .flatMap(auth -> {
                            String sub = extractSub(auth);

                            // JWT 검증은 SecurityWebFilterChain에서 이미 처리되었으므로, sub이 없으면 그대로 진행
                            if (sub == null || sub.isBlank()) {
                                return chain.filter(exchange);
                            }

                            ServerWebExchange mutated = mutateHeader(exchange, sub);
                            return chain.filter(mutated);
                        })
                        .switchIfEmpty(chain.filter(exchange));
    }

    private String extractSub(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            return String.valueOf(jwtAuth.getPrincipal()); // = sub
        }
        return null;
    }

    private ServerWebExchange mutateHeader(ServerWebExchange exchange, String sub) {
        var request = exchange.getRequest().mutate()
                // 외부에서 X-Member-Id를 임의로 넣어오는 spoofing 방지
                .headers(headers -> headers.remove("X-Member-Id"))
                .header("X-Member-Id", sub)
                .build();

        return exchange.mutate().request(request).build();
    }
}

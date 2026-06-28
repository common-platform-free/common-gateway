package com.example.gateway.filter;

import com.example.gateway.config.GatewayAuthProperties;
import com.example.gateway.jwt.JwtTokenService;
import com.example.gateway.jwt.JwtUserInfo;
import com.example.gateway.response.ErrorResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String X_USER_ID = "X-User-Id";
    private static final String X_USERNAME = "X-Username";
    private static final String X_ROLES = "X-Roles";
    private static final String UNAUTHORIZED_MESSAGE = "token无效或已过期";

    private final GatewayAuthProperties authProperties;
    private final JwtTokenService jwtTokenService;
    private final ObjectMapper objectMapper;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public AuthGlobalFilter(GatewayAuthProperties authProperties,
                            JwtTokenService jwtTokenService,
                            ObjectMapper objectMapper) {
        this.authProperties = authProperties;
        this.jwtTokenService = jwtTokenService;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (isWhiteListed(path)) {
            return chain.filter(exchange);
        }

        String token = resolveToken(exchange);
        if (!StringUtils.hasText(token)) {
            return unauthorized(exchange);
        }

        try {
            JwtUserInfo userInfo = jwtTokenService.parseAndValidate(token);
            ServerHttpRequest request = exchange.getRequest()
                    .mutate()
                    .headers(headers -> {
                        headers.remove(X_USER_ID);
                        headers.remove(X_USERNAME);
                        headers.remove(X_ROLES);
                    })
                    .header(X_USER_ID, userInfo.userId())
                    .header(X_USERNAME, userInfo.username())
                    .header(X_ROLES, String.join(",", userInfo.roles()))
                    .build();

            return chain.filter(exchange.mutate().request(request).build());
        } catch (Exception ex) {
            return unauthorized(exchange);
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private boolean isWhiteListed(String path) {
        return authProperties.getWhiteList()
                .stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    private String resolveToken(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authorization)) {
            if (!authorization.startsWith(BEARER_PREFIX)) {
                return null;
            }
            return authorization.substring(BEARER_PREFIX.length()).trim();
        }

        HttpCookie accessTokenCookie = exchange.getRequest()
                .getCookies()
                .getFirst(authProperties.getAccessTokenCookieName());
        return accessTokenCookie == null ? null : accessTokenCookie.getValue();
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.parseMediaType("application/json;charset=UTF-8"));

        byte[] body = toJsonBytes(new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), UNAUTHORIZED_MESSAGE));
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    private byte[] toJsonBytes(ErrorResponse errorResponse) {
        try {
            return objectMapper.writeValueAsBytes(errorResponse);
        } catch (JsonProcessingException ex) {
            String fallback = "{\"code\":401,\"message\":\"token无效或已过期\"}";
            return fallback.getBytes(StandardCharsets.UTF_8);
        }
    }
}

package com.example.gateway.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class JwtTokenService {

    private final SecretKey secretKey;
    private final ObjectMapper objectMapper;

    public JwtTokenService(@Value("${jwt.secret-url}") String secretUrl,
                           @Value("${jwt.secret-fetch-timeout-seconds:5}") long timeoutSeconds,
                           WebClient.Builder webClientBuilder,
                           ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;

        String secret = fetchSecret(secretUrl, timeoutSeconds, webClientBuilder);
        if (!StringUtils.hasText(secret)) {
            throw new IllegalStateException("JWT secret fetched from IAM/Auth is empty");
        }
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public JwtUserInfo parseAndValidate(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        String userId = claims.getSubject();
        String username = claims.get("username", String.class);
        List<String> roles = parseRoles(claims.get("roles"));

        if (userId == null || userId.isBlank() || username == null || username.isBlank()) {
            throw new IllegalArgumentException("JWT missing required user claims");
        }

        return new JwtUserInfo(userId, username, roles);
    }

    private List<String> parseRoles(Object rolesClaim) {
        if (rolesClaim == null) {
            return Collections.emptyList();
        }

        if (rolesClaim instanceof List<?> rawRoles) {
            List<String> roles = new ArrayList<>();
            for (Object role : rawRoles) {
                if (role != null) {
                    roles.add(role.toString());
                }
            }
            return roles;
        }

        if (rolesClaim instanceof String roleText && !roleText.isBlank()) {
            return List.of(roleText.split(","));
        }

        return Collections.emptyList();
    }

    private String fetchSecret(String secretUrl, long timeoutSeconds, WebClient.Builder webClientBuilder) {
        try {
            String responseBody = webClientBuilder
                    .build()
                    .get()
                    .uri(secretUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(Duration.ofSeconds(timeoutSeconds));

            return extractSecret(responseBody);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to fetch JWT secret from IAM/Auth: " + secretUrl, ex);
        }
    }

    private String extractSecret(String responseBody) throws Exception {
        if (!StringUtils.hasText(responseBody)) {
            return null;
        }

        String trimmedBody = responseBody.trim();
        if (!trimmedBody.startsWith("{") && !trimmedBody.startsWith("\"")) {
            return trimmedBody;
        }

        JsonNode root = objectMapper.readTree(trimmedBody);
        if (root.isTextual()) {
            return root.asText();
        }

        JsonNode secretNode = firstTextNode(root, "secret", "jwtSecret", "value");
        if (secretNode != null) {
            return secretNode.asText();
        }

        JsonNode dataNode = root.get("data");
        if (dataNode != null) {
            JsonNode dataSecretNode = firstTextNode(dataNode, "secret", "jwtSecret", "value");
            if (dataSecretNode != null) {
                return dataSecretNode.asText();
            }
        }

        throw new IllegalArgumentException("IAM/Auth secret response must be plain text or contain secret");
    }

    private JsonNode firstTextNode(JsonNode root, String... fieldNames) {
        for (String fieldName : fieldNames) {
            JsonNode node = root.get(fieldName);
            if (node != null && node.isTextual() && StringUtils.hasText(node.asText())) {
                return node;
            }
        }
        return null;
    }
}

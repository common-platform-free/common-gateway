package com.example.gateway.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Service
public class JwtTokenService {

    private final PublicKey publicKey;
    private final ObjectMapper objectMapper;

    public JwtTokenService(@Value("${jwt.public-key-url}") String publicKeyUrl,
                           @Value("${jwt.public-key-fetch-timeout-seconds:5}") long timeoutSeconds,
                           WebClient.Builder webClientBuilder,
                           ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;

        String publicKeyPem = fetchPublicKey(publicKeyUrl, timeoutSeconds, webClientBuilder);
        if (!StringUtils.hasText(publicKeyPem)) {
            throw new IllegalStateException("JWT public key fetched from IAM/Auth is empty");
        }
        this.publicKey = parsePublicKey(publicKeyPem);
    }

    public JwtUserInfo parseAndValidate(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        String userId = claims.getSubject();
        String username = claims.get("username", String.class);
        List<String> roles = parseRoles(claims.get("roles"));

        if (userId == null || userId.isBlank() || username == null || username.isBlank()) {
            throw new IllegalArgumentException("JWT missing required user claims");
        }
        if (!"access".equals(claims.get("typ", String.class))) {
            throw new IllegalArgumentException("JWT typ must be access");
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

    private String fetchPublicKey(String publicKeyUrl, long timeoutSeconds, WebClient.Builder webClientBuilder) {
        try {
            String responseBody = webClientBuilder
                    .build()
                    .get()
                    .uri(publicKeyUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(Duration.ofSeconds(timeoutSeconds));

            return extractPublicKey(responseBody);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to fetch JWT public key from IAM/Auth: " + publicKeyUrl, ex);
        }
    }

    private String extractPublicKey(String responseBody) throws Exception {
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

        JsonNode publicKeyNode = firstTextNode(root, "publicKey", "accessPublicKey", "value");
        if (publicKeyNode != null) {
            return publicKeyNode.asText();
        }

        JsonNode dataNode = root.get("data");
        if (dataNode != null) {
            JsonNode dataPublicKeyNode = firstTextNode(dataNode, "publicKey", "accessPublicKey", "value");
            if (dataPublicKeyNode != null) {
                return dataPublicKeyNode.asText();
            }
        }

        throw new IllegalArgumentException("IAM/Auth public key response must be plain text or contain publicKey");
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

    private PublicKey parsePublicKey(String pem) {
        try {
            String content = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(content);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception ex) {
            throw new IllegalStateException("Invalid RSA public key from IAM/Auth", ex);
        }
    }
}

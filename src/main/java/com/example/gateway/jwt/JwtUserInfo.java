package com.example.gateway.jwt;

import java.util.List;

public record JwtUserInfo(
        String userId,
        String username,
        List<String> roles
) {
}

package com.example.gateway.response;

public record ErrorResponse(
        int code,
        String message
) {
}

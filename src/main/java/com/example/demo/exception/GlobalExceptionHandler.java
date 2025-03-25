package com.example.demo.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // Captura exceções genéricas
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGenericException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Erro interno do servidor: " + ex.getMessage());
    }

    @ExceptionHandler(UserAlreadyExistsException .class)
    public ResponseEntity<String> handleUserExistException(UserAlreadyExistsException  ex) { 
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage()); 
    }

    @ExceptionHandler(TokenInvalidException .class)
    public ResponseEntity<String> handleTokenInvalidException(TokenInvalidException  ex) { 
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage()); 
    }
}
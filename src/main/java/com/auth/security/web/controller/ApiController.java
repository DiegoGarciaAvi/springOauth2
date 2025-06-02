package com.auth.security.web.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class ApiController {

    @GetMapping("/scope")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello con scope");
    }

    @GetMapping("/roles")
    public ResponseEntity<String> roles() {
        return ResponseEntity.ok("Hello con roles");
    }
}

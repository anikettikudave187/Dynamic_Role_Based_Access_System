package com.example.rbac.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecureDataController {

    @GetMapping("/secure-data")
    @PreAuthorize("hasPermission('SECURE_DATA', 'READ')")
    public String getSecureData() {
        return "This is secure data";
    }
}

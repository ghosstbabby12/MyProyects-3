package com.security.network.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.network.service.URLAnalyzerService;

@RestController
@RequestMapping("/seguridad")
public class SecurityController {
    
    @Autowired
    private URLAnalyzerService urlAnalyzerService;

    @PostMapping("/proteger")
    public ResponseEntity<String> proteger(@RequestBody(required = false) Map<String, String> request) {
        if (request == null || !request.containsKey("url")) {
            return ResponseEntity.badRequest().body("❌ Error: Debes enviar un JSON con la clave 'url'.");
        }

        String url = request.get("url");

        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("❌ Error: La URL no puede estar vacía.");
        }

        String resultado = urlAnalyzerService.analizarURL(url);
        return ResponseEntity.ok(resultado);
    }
}

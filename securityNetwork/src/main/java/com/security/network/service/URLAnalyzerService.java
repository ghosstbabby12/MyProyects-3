package com.security.network.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class URLAnalyzerService {

    @Autowired
    private SafeBrowsingService safeBrowsingService;

    private static final List<String> BLACKLIST = Arrays.asList(
        "gaupof.com", "goalgoof.com"
    );

    public String analizarURL(String url) {
        // Verifica en la lista negra
        for (String maliciosa : BLACKLIST) {
            if (url.contains(maliciosa)) {
                return "⚠️ La URL ingresada es maliciosa.";
            }
        }

        // Verifica con Google Safe Browsing
        if (safeBrowsingService.esMaliciosa(url)) {
            return "⚠️ La URL ingresada ha sido reportada como maliciosa por Google Safe Browsing.";
        }

        return "✅ La URL ingresada es segura.";
    }
}

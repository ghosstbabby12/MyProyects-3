package com.security.network.decorator;

import com.security.network.service.SecurityService;

public class SQLInjectionProtectorDecorator implements SecurityService {
    private final SecurityService securityService;

    public SQLInjectionProtectorDecorator(SecurityService securityService) {
        this.securityService = securityService;
    }

    @Override
    public String analizarSolicitud(String request) {
        if (request.contains("' OR '1'='1") || request.toLowerCase().contains("drop table")) {
            return "⚠️ Solicitud bloqueada: Posible intento de SQL Injection";
        }
        return securityService.analizarSolicitud(request);
    }
}

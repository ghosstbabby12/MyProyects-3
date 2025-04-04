package com.security.network.decorator;

import java.util.Arrays;
import java.util.List;

import com.security.network.service.SecurityService;

public class IPBlockerDecorator implements SecurityService {
    private final SecurityService securityService;
    private final List<String> ipBloqueadas = Arrays.asList("192.168.1.100", "10.0.0.200");

    public IPBlockerDecorator(SecurityService securityService) {
        this.securityService = securityService;
    }

    @Override
    public String analizarSolicitud(String request) {
        String ip = request.split(":")[0]; // Suponiendo que la IP viene en el request
        if (ipBloqueadas.contains(ip)) {
            return "⚠️ Acceso denegado: IP bloqueada";
        }
        return securityService.analizarSolicitud(request);
    }
}

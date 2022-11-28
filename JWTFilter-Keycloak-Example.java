package com.knightarchtech.examples.security.jwt;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Filters incoming requests and installs a Spring Security principal if a header corresponding to a valid user is
 * found.
 */
public class JWTFilter extends GenericFilterBean {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;

    public JWTFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
        throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String jwt = resolveToken(httpServletRequest);
        if (StringUtils.hasText(jwt)) {
            System.out.println("DEBUG: JWT has been detected: " + jwt);
        }
        if (StringUtils.hasText(jwt) && this.tokenProvider.validateToken(jwt)) {
            Authentication authentication = this.tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            if (httpServletRequest.getParameter("code") != null) {
                String authorizationCode = httpServletRequest.getParameter("code");
                System.out.println("DEBUG: Detected authorization code = " + authorizationCode);
                System.out.println("DEBUG: fetching token based on authorization code ...");
                try {
                    Thread.sleep(Long.valueOf("3000"));
                } catch (NumberFormatException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                /**
                final String tokenUrl = "http://localhost:9080/auth/realms/dev/protocol/openid-connect/token";
                Map<String, String> parameters = new HashMap<>();
                parameters.put("grant_type", "authorization_code");
                parameters.put("client_id", "oauth2-demo");
                parameters.put("code", authorizationCode.toString());
                parameters.put("response_type", "token");
                parameters.put("redirect_uri", "http://localhost:8080/");

                String form = parameters.entrySet().stream()
                .map(entry -> String.join("=",
                         URLEncoder.encode((String)entry.getKey(), StandardCharsets.UTF_8),
                         URLEncoder.encode((String)entry.getValue(), StandardCharsets.UTF_8)))
                .collect(Collectors.joining("&"));

                HttpClient client = HttpClient.newHttpClient();

                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .headers("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();

                try {
                    HttpResponse<?> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    System.out.println("DEBUG: Token response code: " + response.statusCode());
                    System.out.println("DEBUG: Token response message: " + response.toString());
                    System.out.println("DEBUG: Token response body: " + response.body().toString());
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } finally {
                    client = null;
                }
                */


                RestTemplate restTemplate = new RestTemplate();
                final String tokenUrl = "http://localhost:9080/auth/realms/dev/protocol/openid-connect/token";
                HttpHeaders headers = new HttpHeaders();
                headers.add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED.toString());

                Map<String, String> map= new HashMap<>();
                map.put("grant_type", "authorization_code");
                map.put("client_id", "oauth2-demo");
                map.put("code", authorizationCode);
                map.put("response_type", "token");
                map.put("redirect_uri", "http://localhost:8080/");

                String form = map
                    .entrySet()
                    .stream()
                    .map(entry -> String.join("=",
                            URLEncoder.encode((String)entry.getKey(), StandardCharsets.UTF_8),
                            URLEncoder.encode((String)entry.getValue(), StandardCharsets.UTF_8)))
                    .collect(Collectors.joining("&"));

                System.out.println("Submitting encoded form: " + form);

                HttpEntity<String> request = new HttpEntity<>(form, headers);
                System.out.println("Request headers: " + request.getHeaders().toString());
                ResponseEntity<String> result = restTemplate.exchange(URI.create(tokenUrl), HttpMethod.POST, request, String.class);
                System.out.println("TOken result body: " + result.getBody());

            }

            if (httpServletRequest.getRequestURI().contains("/login")) {
                // String oidcUrl = "http://localhost:9080/auth/realms/dev/protocol/openid-connect/auth?response_type=token&client_id=oauth2-demo&scope=openid profile email roles&redirect_uri=http://localhost:8080/login/oauth2/code/oauth2-demo";
                String oidcUrl = "http://localhost:9080/auth/realms/dev/protocol/openid-connect/auth?response_type=code&client_id=oauth2-demo&scope=openid&redirect_uri=http://localhost:8080/";
                System.out.println("DEBUG: in JWTFilter token not found,  redirecting to " + oidcUrl + " ...");
                HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
                httpServletResponse.sendRedirect(oidcUrl);

                return;
            }
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}

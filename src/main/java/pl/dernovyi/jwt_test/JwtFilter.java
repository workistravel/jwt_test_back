package pl.dernovyi.jwt_test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sun.net.httpserver.Filter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;

public class JwtFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String authorization = httpServletRequest.getHeader("Authorization");
        UsernamePasswordAuthenticationToken authenticationToken = getUsernamePasswordAuthenticationToken(authorization);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(httpServletRequest, httpServletResponse );
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String authorization){
        RSAPublicKey publicKey = null;
        try {
            publicKey = (RSAPublicKey) getPublicKey();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        JWTVerifier jwtVerifier = JWT.require(Algorithm.RSA256( publicKey, null)).build();
        DecodedJWT verify = jwtVerifier.verify(authorization.substring(7));
        String name = verify.getClaim("name").asString();
        boolean isAdmin = verify.getClaim("admin").asBoolean();
        String role = "USER";
        if(isAdmin) {
            role = "ADMIN";
        }
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role);
        return new UsernamePasswordAuthenticationToken(name, null,  Collections.singleton(authority));


    }

    private PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String rsaPublicKey = "-----BEGIN PUBLIC KEY-----" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAibaJaUHEUs7xJ1pQkb8I" +
                "eXzNuNxR9gea8CEk3fCmMSkoFpsJzFB7v/T5v91HIyo62lKeqeCCDLDez5/ZElLP" +
                "f6kNGmH68CDaBAaV3wNTmGVDFMYc0NMZ09UJ4pvx+VVWh/3TC29WNF/HrPv2J/ZX" +
                "njYuZ0Wn1WEDNJHerCEbGUrsyv0s4TqYCfOoxT8nneXZi2KI0JEzXVhV+/ZltcoZ" +
                "9Gvbftz/Xx3CE1cBzGrn7fL9Wlxw4VDlbGEFCCpiznIhirueattat1PngHIJM4Zf" +
                "PctQIFHJVOtnN9knIhUsqju+t2KEu23Sxa2HVIi4WGz7Qg6abWD2HrrjNfnQbvoF" +
                "zQIDAQAB" +
                "-----END PUBLIC KEY-----";
        rsaPublicKey = rsaPublicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        rsaPublicKey = rsaPublicKey.replace("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(rsaPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }


}

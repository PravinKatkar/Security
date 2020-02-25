package com.example.demo.config;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil {

	public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

	@Value("${jwt.secret}")
	private String secret;

	// generate token for user
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		return doGenerateToken(claims, userDetails.getUsername());
	}

	// validate token
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	// -- Helper Methodd

	// while creating the token -
	// 1. Define claims of the token, like Issuer, Expiration, Subject, and the ID
	// 2. Sign the JWT using the HS512 algorithm and secret key.
	// 3. According to JWS Compact
	// Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
	// compaction of the JWT to a URL-safe string
	private String doGenerateToken(Map<String, Object> claims, String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	// retrieve username from jwt token
	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	// retrieve expiration date from jwt token
	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	// for retrieveing any information from token we will need the secret key
	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	//check if the token has expired
	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("MyMaster");
		try {
			String pass = "Usit1234";
			String ecodedString = Base64.getEncoder().encodeToString(pass.getBytes());
			System.out.println("ecodedString" + ecodedString);
			
			String password = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
			System.out.println("password    :  " + password);
			String actString = new String(Base64.getDecoder().decode(password));
			System.out.println("actString" + actString);
			
			String actString1 = "password";
			
		
			BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
			CharSequence charSeq = actString1.subSequence(0, actString1.length());
			System.out.println("charSeq : "+ charSeq);
			String ecodedString1 = encoder.encode(charSeq);
			System.out.println("ecodedString : " + ecodedString1);
			System.out.println("ecodedString : " + "$2a$10$rF/B9QvhPkmzumTqCBeupOHtyJ1BS2Cmcm6VkDZ16.KjGtVwINLua");		
			
		}
		catch(Exception ex) {
			ex.printStackTrace();
		}
				
	}
}
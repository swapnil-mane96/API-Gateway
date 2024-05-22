package com.photoapp.apigateway;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;


@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
	
	@Autowired
	private Environment environment;
	
	/*
	 * It will tell super class which Config class to use when apply method is called
	 *
	 */
	public AuthorizationHeaderFilter() {
		super(Config.class);
	}

	public static class Config{
		private List<String> authorities;

		public List<String> getAuthorities() {
			return authorities;
		}

		/*
		 * When the setter method is called, it will receive an argument that we have defined in the application 
		 * properties file as a single string. So I will have to change the data type from list to string.
		 */
		public void setAuthorities(String authorities) {
			this.authorities = Arrays.asList(authorities.split(" "));
		}
		
		// put configuration properties here
//		private String role;
//		private String authority;
//
//		public String getRole() {
//			return role;
//		}
//
//		public void setRole(String role) {
//			this.role = role;
//		}
//
//		public String getAuthority() {
//			return authority;
//		}
//
//		public void setAuthority(String authority) {
//			this.authority = authority;
//		}
		
	}
	
	/*
	 * Because there can be multiple arguments that can be passed to a filter class.
	   This method is used to return strings that represent names and order of arguments that are passed to the filter factory.
	 */
	@Override
	public List<String> shortcutFieldOrder() {
		return Arrays.asList("authorities");
		//return Arrays.asList("role","authority"); //The role here is the name of the instance variable in my config class.
	}

	/*
	 * This method contains main business logic of our custom filter leaves
	 * It accepts config object which we can use to access configuration properties 
	 * If needed customize behavior of our gateway filter 
	 * And apply method it will need to return an object of gateway filter
	 */
	@Override
	public GatewayFilter apply(Config config) {
		
		return (exchange, chain) ->{
			ServerHttpRequest serverHttpRequest = exchange.getRequest(); // Get request from Http server
			
			// Now we have serverHttpRequest object so we can check Http header with Authorization name 
			if (!serverHttpRequest.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
			}
			// Get entire jwt token including Bearer prefix and jwt token
			String authorizationHeader = serverHttpRequest.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			
			// It will remove Bearer prefix from jwt token and give jwt token only.
			String jwt = authorizationHeader.replace("Bearer", "").trim();
			
			List<String> authorities = getAuthorities(jwt);
			
			boolean hasRequiredAuthority = authorities.stream().anyMatch((authority) -> config.getAuthorities().contains(authority));
			
			if(!hasRequiredAuthority) 
	        	return onError(exchange,"User is not authorized to perform this operation", HttpStatus.FORBIDDEN);
			
//			String role = config.getRole();
//			String authority = config.getAuthority();
			
			//String jwt = jwtBearer.trim();
			
//			if (!isJwtValid(jwt)) {
//				return onError(exchange, "Jwt token is not valid!", HttpStatus.UNAUTHORIZED);
//			}
			return chain.filter(exchange);
		};
	}
	
	/*
	 * The method returns a Mono<Void> due to the asynchronous, non-blocking nature of Spring WebFlux,
	 *  which is used in Spring Cloud Gateway for handling HTTP requests and responses in a reactive way.
	 */
	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus){
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		
		DataBufferFactory dataBufferFactory = response.bufferFactory();
		DataBuffer buffer = dataBufferFactory.wrap(err.getBytes());
		return response.writeWith(Mono.just(buffer));
		//return response.setComplete();
	}
	
	private List<String> getAuthorities(String jwt) {
		
		List<String> returnValue = new ArrayList<>();

		String tokenSecret = this.environment.getProperty("token.secret");
		System.out.println("API Gateway Secret Token: "+tokenSecret);
		byte[] secretBytes = Base64.getEncoder().encode(tokenSecret.getBytes());
		SecretKey secretKey = Keys.hmacShaKeyFor(secretBytes);
		
		//To parse access token and to read it's claims we will need to use JWT parser
		JwtParser jwtParser = Jwts.parser()
				.verifyWith(secretKey)
				.build();

		try {
			Jws<Claims> parsedToken = jwtParser.parseSignedClaims(jwt);
			List<Map<String, String>> scopes = ((Claims)parsedToken.getPayload()).get("scope", List.class); //this will return list of mapped objects
			scopes.stream().map((scopeMap) -> returnValue.add(scopeMap.get("authority"))).collect(Collectors.toList());
			
		} catch (Exception exception) {
			exception.printStackTrace();
			System.out.println("API Gateway Exception is: "+exception.getMessage());
			return returnValue;
		}
		
		
		
		return returnValue;
	}
	

}

package com.photoapp.apigateway;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class MyPreFilter implements GlobalFilter, Ordered {
	
	final Logger logger = LoggerFactory.getLogger(MyPreFilter.class);

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		logger.info("My first pre-filter is executed...swap-First");
		
		// to get req path
		String requestPath = exchange.getRequest().getPath().toString();
		this.logger.info("Request Path: "+requestPath);
		
		// to get req headers
		HttpHeaders headers = exchange.getRequest().getHeaders();
		Set<String> headerNames = headers.keySet();
		
		// forEach method to traverse headerNames
		headerNames.forEach((headerName) -> {
			String headerValue = headers.getFirst(headerName);
			this.logger.info(headerValue);
		});
		
		return chain.filter(exchange);
	}

	@Override
	public int getOrder() {
		return 0;
	}

}

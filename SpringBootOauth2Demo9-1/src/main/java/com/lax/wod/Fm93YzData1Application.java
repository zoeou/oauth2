package com.lax.wod;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.context.request.RequestContextListener;

@SpringBootApplication
public class Fm93YzData1Application {

	public static void main(String[] args) {
		SpringApplication.run(Fm93YzData1Application.class, args);
	}
	
    @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }
}

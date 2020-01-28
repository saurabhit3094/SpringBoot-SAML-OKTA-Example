package com.sample.ssoapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import java.util.Arrays;

@SpringBootApplication
public class SsoappApplication {

	public static void main(String[] args) {
		ApplicationContext applicationContext = SpringApplication.run(SsoappApplication.class, args);
		//Uncomment to print all the beans loaded into context
//		String[] beans = applicationContext.getBeanDefinitionNames();
//		Arrays.sort(beans);
//		for (String bean : beans){
//			System.out.println(bean);
//		}
	}

}

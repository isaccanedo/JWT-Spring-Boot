package com.isaccanedo.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	@RequestMapping("/users")
	@ResponseBody
	public String getUsers() {
		return "{\"users\":[{\"name\":\"Isac\", \"country\":\"Brazil\"}," +
		           "{\"name\":\"Canedo\",\"country\":\"Brazil\"}]}";
	}
}

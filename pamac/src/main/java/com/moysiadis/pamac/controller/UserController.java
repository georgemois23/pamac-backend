package com.moysiadis.pamac.controller;

import com.moysiadis.pamac.model.User;
import com.moysiadis.pamac.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/user")
@CrossOrigin
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/add")
    public ResponseEntity<?> add(@RequestBody User user) {
        userService.saveUser(user);
        return ResponseEntity.ok(Collections.singletonMap("message", "New user added"));
    }

    @GetMapping("/getAll")
    public List<User> getAllUsers() {
        return userService.getAllUsers();  // Fixed this line
    }
}

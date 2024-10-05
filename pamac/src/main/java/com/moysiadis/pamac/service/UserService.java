package com.moysiadis.pamac.service;

import com.moysiadis.pamac.model.User;

import java.util.List;

public interface UserService {

    public User saveUser(User user);
    public List<User> getAllUsers();
}

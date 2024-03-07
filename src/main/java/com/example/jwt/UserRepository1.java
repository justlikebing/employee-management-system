package com.example.jwt;

import org.springframework.stereotype.Repository;

@Repository
public class UserRepository1 {
    public User2 findUserByEmail(String email){
        User2 user = new User2(email,"123456");
        user.setFirstName("FirstName");
        user.setLastName("LastName");
        return user;
    }
}
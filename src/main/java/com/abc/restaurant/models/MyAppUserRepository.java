package com.abc.restaurant.models;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface MyAppUserRepository extends JpaRepository<MyAppUser, Long> {
    
    Optional<MyAppUser> findByUserName(String userName);
}

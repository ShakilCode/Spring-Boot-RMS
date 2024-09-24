package com.abc.restaurant.models;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface StaffMyAppUserRepository extends JpaRepository<StaffMyAppUser, Long> {
    
    Optional<StaffMyAppUser> findByUserName(String userName);
}

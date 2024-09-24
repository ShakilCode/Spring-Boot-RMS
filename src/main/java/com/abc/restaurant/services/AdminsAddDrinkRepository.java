package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.AdminAddDrink;
import com.abc.restaurant.models.AdminAddDrinkDto;

                                              // Model name  // Type of the primary key
public interface AdminsAddDrinkRepository extends JpaRepository<AdminAddDrink, Integer> {

    public void save(AdminAddDrinkDto adminAddDrinkDto);
    
}

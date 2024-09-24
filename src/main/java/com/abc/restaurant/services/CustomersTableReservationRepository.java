package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.CustomerTableReservation;
import com.abc.restaurant.models.CustomerTableReservationDto;

                                              // Model name  // Type of the primary key
public interface CustomersTableReservationRepository extends JpaRepository<CustomerTableReservation, Integer> {

    public void save(CustomerTableReservationDto customerTableReservationDto);
    
}
    
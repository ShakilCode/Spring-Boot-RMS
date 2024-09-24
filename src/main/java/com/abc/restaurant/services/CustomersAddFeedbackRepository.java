package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.CustomerAddFeedback;
import com.abc.restaurant.models.CustomerAddFeedbackDto;

                                              // Model name  // Type of the primary key
public interface CustomersAddFeedbackRepository extends JpaRepository<CustomerAddFeedback, Integer> {

    public void save(CustomerAddFeedbackDto customerAddFeedbackDto);
    
}
package com.abc.restaurant.models;

import jakarta.validation.constraints.NotEmpty;

public class CustomerAddFeedbackDto {
    
    @NotEmpty(message= "The rate is required")
    private String rate;

    @NotEmpty(message= "The description is required")
    private String description;


    // Getters and Setters
    public String getRate() {
        return rate;
    }
    public void setRate(String rate) {
        this.rate = rate;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }

}

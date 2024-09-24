package com.abc.restaurant.models;

import jakarta.validation.constraints.NotEmpty;

public class CustomerOrderFoodDto {
    
    @NotEmpty(message= "The name is required")
    private String name;

    private String type;

    @NotEmpty(message= "The place is required")
    private String place;

    @NotEmpty(message= "The phone is required")
    private String phone;

    @NotEmpty(message= "The time is required")
    private String time;

    @NotEmpty(message= "The description is required")
    private String description;

    private String status;


    // Getters and Setters
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
    }
    public String getPlace() {
        return place;
    }
    public void setPlace(String place) {
        this.place = place;
    }
    public String getPhone() {
        return phone;
    }
    public void setPhone(String phone) {
        this.phone = phone;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public String getTime() {
        return time;
    }
    public void setTime(String time) {
        this.time = time;
    }
    public String getStatus() {
        return status;
    }
    public void setStatus(String status) {
        this.status = status;
    }

}

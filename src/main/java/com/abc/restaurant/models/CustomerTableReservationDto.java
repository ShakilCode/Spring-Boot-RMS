package com.abc.restaurant.models;

import jakarta.validation.constraints.NotEmpty;

public class CustomerTableReservationDto {
    
    @NotEmpty(message= "The name is required")
    private String name;

    @NotEmpty(message= "The email is required")
    private String email;

    @NotEmpty(message= "The phone is required")
    private String phone;
    
    @NotEmpty(message= "The date is required")
    private String date;

    @NotEmpty(message= "The time is required")
    private String time;

    @NotEmpty(message= "The person is required")
    private String person;

    private String status;


    // Getters and Setters
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public String getPhone() {
        return phone;
    }
    public void setPhone(String phone) {
        this.phone = phone;
    }
    public String getDate() {
        return date;
    }
    public void setDate(String date) {
        this.date = date;
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
    public String getPerson() {
        return person;
    }
    public void setPerson(String person) {
        this.person = person;
    }

}

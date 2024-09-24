package com.abc.restaurant.models;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class CustomerMakePaymentDto {
    
    @NotEmpty(message = "The name is required")
    private String name;

    @NotEmpty(message = "The card number is required")
    @Size(min = 16, max = 16, message = "Card number must be exactly 16 characters long")
    @Pattern(regexp = "\\d{16}", message = "Card number must contain only digits")
    private String cardnumber;

    @NotEmpty(message = "The expiration date is required")
    @Pattern(regexp = "(0[1-9]|1[0-2])/([0-9]{2})", message = "Expiration date must be in the format MM/YY")
    private String expdate;

    @NotEmpty(message = "The CVC is required")
    @Size(min = 3, max = 3, message = "CVC must be exactly 3 digits")
    @Pattern(regexp = "\\d{3}", message = "CVC must contain only digits")
    private String cvc;


    // Getters and Setters
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getCardnumber() {
        return cardnumber;
    }
    public void setCardnumber(String cardnumber) {
        this.cardnumber = cardnumber;
    }
    public String getExpdate() {
        return expdate;
    }
    public void setExpdate(String expdate) {
        this.expdate = expdate;
    }
    public String getCvc() {
        return cvc;
    }
    public void setCvc(String cvc) {
        this.cvc = cvc;
    }

}

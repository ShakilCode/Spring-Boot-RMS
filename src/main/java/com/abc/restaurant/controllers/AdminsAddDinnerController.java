package com.abc.restaurant.controllers;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.abc.restaurant.models.AdminAddDinner;
import com.abc.restaurant.models.AdminAddDinnerDto;
import com.abc.restaurant.services.AdminsAddDinnerRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/adminadddinner")
public class AdminsAddDinnerController {

    @GetMapping("/admin")
    public String adminAddPage(){
        return "adminadd/admin";
    } 
    
    @GetMapping("/adminaddlunch")
    public String adminAddLunchPage(){
        return "adminaddlunch/addfoodmenulunch";
    }

    @GetMapping("/googlemaps")
    public String adminGoogleMap(){
        return "adminadd/googlemaps";
    }

    @GetMapping("/viewaddfoodmenulunch")
    public String adminViewAddFoodMenuLunch(){
        return "adminaddlunch/viewaddfoodmenulunch";
    }

    @GetMapping("/viewaddfoodmenudinner")
    public String adminViewAddFoodMenuDinner(){
        return "adminadddinner/viewaddfoodmenudinner";
    }

    @Autowired
    private AdminsAddDinnerRepository repo;

    @GetMapping({"", "/"})
    public String showAdminAddList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddDinner> adminadddinner = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminadddinner", adminadddinner);
        return "adminadddinner/viewaddfoodmenudinner";
    }



    // Create new product
    @GetMapping("/addfoodmenudinner")
    public String showCreatePage(Model model){
        AdminAddDinnerDto adminAddDinnerDto = new AdminAddDinnerDto();
        model.addAttribute("adminAddDinnerDto", adminAddDinnerDto);
        // In the adminAddDinnerDto folder there is a adminadddinner called addfoodmenudinner
        return "adminadddinner/addfoodmenudinner";
    }

@PostMapping("/addfoodmenudinner")
public String addfoodmenuDinner(
    @Valid @ModelAttribute AdminAddDinnerDto adminAddDinnerDto,
    BindingResult result) {

        // Image file validation
        if (adminAddDinnerDto.getImageFile().isEmpty()) {
            result.addError(new FieldError("adminAddDinnerDto", "imageFile",
             "The image file is required"));
        }

        if (result.hasErrors()){
            return "adminadddinner/addfoodmenudinner";
        }

        // Save image file and view in the list
        MultipartFile image = adminAddDinnerDto.getImageFile();
        Date createdAt = new Date();
        String storageFileName = createdAt.getTime() + "_" + image.getOriginalFilename();

        try {
            String uploadDir = "public/images/";
            Path uploadPath = Paths.get(uploadDir);

            if (!Files.exists(uploadPath)){
                Files.createDirectories(uploadPath);
            }

            try (InputStream inputStream = image.getInputStream()) {
                Files.copy(inputStream, Paths.get(uploadDir + storageFileName),
                StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ex) {
            System.out.println("Exception : " + ex.getMessage());
        }

        AdminAddDinner adminAddDinner = new AdminAddDinner();
        adminAddDinner.setName(adminAddDinnerDto.getName());  // Fixing a typo here
        adminAddDinner.setCategory(adminAddDinnerDto.getCategory());
        adminAddDinner.setPrice(adminAddDinnerDto.getPrice());
        adminAddDinner.setDescription(adminAddDinnerDto.getDescription());
        adminAddDinner.setCreatedAt(new java.sql.Date(createdAt.getTime()));  // Fixed line
        adminAddDinner.setImageFileName(storageFileName);

        // Save this data on the database
        repo.save(adminAddDinner);

    return "redirect:/adminadddinner";
}

    // Update the adminAdd details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            AdminAddDinner adminAddDinner = repo.findById(id).get();
            model.addAttribute("adminAddDinner", adminAddDinner);

            AdminAddDinnerDto adminAddDinnerDto = new AdminAddDinnerDto();
            adminAddDinnerDto.setName(adminAddDinner.getName());
            adminAddDinnerDto.setCategory(adminAddDinner.getCategory());
            adminAddDinnerDto.setPrice(adminAddDinner.getPrice());
            adminAddDinnerDto.setDescription(adminAddDinner.getDescription());

            model.addAttribute("adminAddDinnerDto", adminAddDinnerDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/adminadddinner";
        }

        return "adminadddinner/editaddfoodmenudinner";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute AdminAddDinnerDto adminAddDinnerDto,
        BindingResult result
    ) {

        try {

            AdminAddDinner adminAddDinner = repo.findById(id).get();
            model.addAttribute("adminAddDinner", adminAddDinner);

            // Check do we have any errors or not
            if(result.hasErrors()) {
                return "adminadddinner/editaddfoodmenuDinner";
            }


            // Check we have the image file or not
            if (!adminAddDinnerDto.getImageFile().isEmpty()) {
                //Delete old image
                String uploadDir = "public/images/";
                Path oldImagePath = Paths.get(uploadDir + adminAddDinner.getImageFileName());

                try {
                    Files.delete(oldImagePath);
                } catch (IOException ex) {
                    System.out.println("Exception : " + ex.getMessage());
                }

                // Save new image file
                MultipartFile image = adminAddDinnerDto.getImageFile();
                Date createdAt = new Date();
                String storageFileName = createdAt.getTime() + "_" + image.getOriginalFilename();

                try (InputStream inputStream = image.getInputStream()) {
                    Files.copy(inputStream, Paths.get(uploadDir + storageFileName),
                    StandardCopyOption.REPLACE_EXISTING);
                }

                adminAddDinner.setImageFileName(storageFileName);
            }

            // Update the other details
            adminAddDinner.setName(adminAddDinnerDto.getName());
            adminAddDinner.setCategory(adminAddDinnerDto.getCategory());
            adminAddDinner.setPrice(adminAddDinnerDto.getPrice());
            adminAddDinner.setDescription(adminAddDinnerDto.getDescription());

            repo.save(adminAddDinner);


        } catch (IOException ex) {
            System.out.println("Exception : " + ex.getMessage());
        }


        return "redirect:/adminadddinner";
    }


    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            AdminAddDinner adminadddinner = repo.findById(id).get();

            //Delete product image
            Path imagePath = Paths.get("public/images/" + adminadddinner.getImageFileName());

            try {
                Files.delete(imagePath);
            } catch (IOException ex) {
                System.out.println("Exception: " + ex.getMessage());
            }

            //Delete the product
            repo.delete(adminadddinner);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/adminadddinner";
    }

}

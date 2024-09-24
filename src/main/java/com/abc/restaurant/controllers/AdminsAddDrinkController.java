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

import com.abc.restaurant.models.AdminAddDrink;
import com.abc.restaurant.models.AdminAddDrinkDto;
import com.abc.restaurant.services.AdminsAddDrinkRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/adminadddrink")
public class AdminsAddDrinkController {

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

    @GetMapping("/viewaddfoodmenudrink")
    public String adminViewAddFoodMenuDrink(){
        return "adminadddrink/viewaddfoodmenudrink";
    }

    @Autowired
    private AdminsAddDrinkRepository repo;

    @GetMapping({"", "/"})
    public String showAdminAddList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddDrink> adminadddrink = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminadddrink", adminadddrink);
        return "adminadddrink/viewaddfoodmenudrink";
    }



    // Create new product
    @GetMapping("/addfoodmenudrink")
    public String showCreatePage(Model model){
        AdminAddDrinkDto adminAddDrinkDto = new AdminAddDrinkDto();
        model.addAttribute("adminAddDrinkDto", adminAddDrinkDto);
        // In the adminAddDrinkDto folder there is a adminadddrink called addfoodmenudrink
        return "adminadddrink/addfoodmenudrink";
    }

@PostMapping("/addfoodmenudrink")
public String addfoodmenuDrink(
    @Valid @ModelAttribute AdminAddDrinkDto adminAddDrinkDto,
    BindingResult result) {

        // Image file validation
        if (adminAddDrinkDto.getImageFile().isEmpty()) {
            result.addError(new FieldError("adminAddDrinkDto", "imageFile",
             "The image file is required"));
        }

        if (result.hasErrors()){
            return "adminadddrink/addfoodmenudrink";
        }

        // Save image file and view in the list
        MultipartFile image = adminAddDrinkDto.getImageFile();
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

        AdminAddDrink adminAddDrink = new AdminAddDrink();
        adminAddDrink.setName(adminAddDrinkDto.getName());  // Fixing a typo here
        adminAddDrink.setCategory(adminAddDrinkDto.getCategory());
        adminAddDrink.setPrice(adminAddDrinkDto.getPrice());
        adminAddDrink.setDescription(adminAddDrinkDto.getDescription());
        adminAddDrink.setCreatedAt(new java.sql.Date(createdAt.getTime()));  // Fixed line
        adminAddDrink.setImageFileName(storageFileName);

        // Save this data on the database
        repo.save(adminAddDrink);

    return "redirect:/adminadddrink";
}

    // Update the adminAdd details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            AdminAddDrink adminAddDrink = repo.findById(id).get();
            model.addAttribute("adminAddDrink", adminAddDrink);

            AdminAddDrinkDto adminAddDrinkDto = new AdminAddDrinkDto();
            adminAddDrinkDto.setName(adminAddDrink.getName());
            adminAddDrinkDto.setCategory(adminAddDrink.getCategory());
            adminAddDrinkDto.setPrice(adminAddDrink.getPrice());
            adminAddDrinkDto.setDescription(adminAddDrink.getDescription());

            model.addAttribute("adminAddDrinkDto", adminAddDrinkDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/adminadddrink";
        }

        return "adminadddrink/editaddfoodmenudrink";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute AdminAddDrinkDto adminAddDrinkDto,
        BindingResult result
    ) {

        try {

            AdminAddDrink adminAddDrink = repo.findById(id).get();
            model.addAttribute("adminAddDrink", adminAddDrink);

            // Check do we have any errors or not
            if(result.hasErrors()) {
                return "adminadddrink/editaddfoodmenuDrink";
            }


            // Check we have the image file or not
            if (!adminAddDrinkDto.getImageFile().isEmpty()) {
                //Delete old image
                String uploadDir = "public/images/";
                Path oldImagePath = Paths.get(uploadDir + adminAddDrink.getImageFileName());

                try {
                    Files.delete(oldImagePath);
                } catch (IOException ex) {
                    System.out.println("Exception : " + ex.getMessage());
                }

                // Save new image file
                MultipartFile image = adminAddDrinkDto.getImageFile();
                Date createdAt = new Date();
                String storageFileName = createdAt.getTime() + "_" + image.getOriginalFilename();

                try (InputStream inputStream = image.getInputStream()) {
                    Files.copy(inputStream, Paths.get(uploadDir + storageFileName),
                    StandardCopyOption.REPLACE_EXISTING);
                }

                adminAddDrink.setImageFileName(storageFileName);
            }

            // Update the other details
            adminAddDrink.setName(adminAddDrinkDto.getName());
            adminAddDrink.setCategory(adminAddDrinkDto.getCategory());
            adminAddDrink.setPrice(adminAddDrinkDto.getPrice());
            adminAddDrink.setDescription(adminAddDrinkDto.getDescription());

            repo.save(adminAddDrink);


        } catch (IOException ex) {
            System.out.println("Exception : " + ex.getMessage());
        }


        return "redirect:/adminadddrink";
    }


    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            AdminAddDrink adminadddrink = repo.findById(id).get();

            //Delete product image
            Path imagePath = Paths.get("public/images/" + adminadddrink.getImageFileName());

            try {
                Files.delete(imagePath);
            } catch (IOException ex) {
                System.out.println("Exception: " + ex.getMessage());
            }

            //Delete the product
            repo.delete(adminadddrink);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/adminadddrink";
    }

}

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

import com.abc.restaurant.models.AdminAdd;
import com.abc.restaurant.models.AdminAddDto;
import com.abc.restaurant.services.AdminsAddRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/adminadd")
public class AdminsAddController {

    

    @GetMapping("/viewaddfoodmenu")
    public String adminViewAddFoodMenu(){
        return "adminadd/viewaddfoodmenu";
    }

    @GetMapping("/googlemaps")
    public String adminViewGoogleMap(){
        return "adminadd/googlemaps";
    }

    @GetMapping("/adminviewtablereservations")
    public String adminviewres(){
        return "customerinterface/adminviewtablereservations";
    }




    @Autowired
    private AdminsAddRepository repo;

    @GetMapping({"", "/"})
    public String showAdminAddList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAdd> adminadd = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminadd", adminadd);
        return "adminadd/viewaddfoodmenu";
    }


    // Create new product
    @GetMapping("/addfoodmenu")
    public String showCreatePage(Model model){
        AdminAddDto adminAddDto = new AdminAddDto();
        model.addAttribute("adminAddDto", adminAddDto);
        // In the adminadd folder there is a adminadd called addfoodmenu
        return "adminadd/addfoodmenu";
    }

@PostMapping("/addfoodmenu")
public String addfoodmenu(
    @Valid @ModelAttribute AdminAddDto adminAddDto,
    BindingResult result) {

        // Image file validation
        if (adminAddDto.getImageFile().isEmpty()) {
            result.addError(new FieldError("adminAddDto", "imageFile",
             "The image file is required"));
        }

        if (result.hasErrors()){
            return "adminadd/addfoodmenu";
        }

        // Save image file and view in the list
        MultipartFile image = adminAddDto.getImageFile();
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

        AdminAdd adminAdd = new AdminAdd();
        adminAdd.setName(adminAddDto.getName());  // Fixing a typo here
        adminAdd.setCategory(adminAddDto.getCategory());
        adminAdd.setPrice(adminAddDto.getPrice());
        adminAdd.setDescription(adminAddDto.getDescription());
        adminAdd.setCreatedAt(new java.sql.Date(createdAt.getTime()));  // Fixed line
        adminAdd.setImageFileName(storageFileName);

        // Save this data on the database
        repo.save(adminAdd);

    return "redirect:/adminadd";
}

    // Update the adminAdd details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            AdminAdd adminAdd = repo.findById(id).get();
            model.addAttribute("adminAdd", adminAdd);

            AdminAddDto adminAddDto = new AdminAddDto();
            adminAddDto.setName(adminAdd.getName());
            adminAddDto.setCategory(adminAdd.getCategory());
            adminAddDto.setPrice(adminAdd.getPrice());
            adminAddDto.setDescription(adminAdd.getDescription());

            model.addAttribute("adminAddDto", adminAddDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/adminadd";
        }

        return "adminadd/editaddfoodmenu";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute AdminAddDto adminAddDto,
        BindingResult result
    ) {

        try {

            AdminAdd adminAdd = repo.findById(id).get();
            model.addAttribute("adminAdd", adminAdd);

            // Check do we have any errors or not
            if(result.hasErrors()) {
                return "adminadd/editaddfoodmenu";
            }


            // Check we have the image file or not
            if (!adminAddDto.getImageFile().isEmpty()) {
                //Delete old image
                String uploadDir = "public/images/";
                Path oldImagePath = Paths.get(uploadDir + adminAdd.getImageFileName());

                try {
                    Files.delete(oldImagePath);
                } catch (IOException ex) {
                    System.out.println("Exception : " + ex.getMessage());
                }

                // Save new image file
                MultipartFile image = adminAddDto.getImageFile();
                Date createdAt = new Date();
                String storageFileName = createdAt.getTime() + "_" + image.getOriginalFilename();

                try (InputStream inputStream = image.getInputStream()) {
                    Files.copy(inputStream, Paths.get(uploadDir + storageFileName),
                    StandardCopyOption.REPLACE_EXISTING);
                }

                adminAdd.setImageFileName(storageFileName);
            }

            // Update the other details
            adminAdd.setName(adminAddDto.getName());
            adminAdd.setCategory(adminAddDto.getCategory());
            adminAdd.setPrice(adminAddDto.getPrice());
            adminAdd.setDescription(adminAddDto.getDescription());

            repo.save(adminAdd);


        } catch (IOException ex) {
            System.out.println("Exception : " + ex.getMessage());
        }


        return "redirect:/adminadd";
    }


    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            AdminAdd adminadd = repo.findById(id).get();

            //Delete product image
            Path imagePath = Paths.get("public/images/" + adminadd.getImageFileName());

            try {
                Files.delete(imagePath);
            } catch (IOException ex) {
                System.out.println("Exception: " + ex.getMessage());
            }

            //Delete the product
            repo.delete(adminadd);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/adminadd";
    }

}

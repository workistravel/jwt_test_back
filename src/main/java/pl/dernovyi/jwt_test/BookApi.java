package pl.dernovyi.jwt_test;

import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/books")
public class BookApi {

    private List<String> booksList;

    public BookApi() {
        this.booksList = new ArrayList<>();
        booksList.add("Spring Boot 2");
        booksList.add("Spring in Action 5");

    }
    @GetMapping
    public List<String> getBooks(){
        return booksList;
    }
    @PostMapping
    public List<String> addBooks(@RequestBody String book){
        booksList.add(book);
        return booksList;
    }
}

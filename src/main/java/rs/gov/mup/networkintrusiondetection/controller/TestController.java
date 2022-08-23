package rs.gov.mup.networkintrusiondetection.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rs.gov.mup.networkintrusiondetection.dto.CalculationDto;
import rs.gov.mup.networkintrusiondetection.model.Test;
import rs.gov.mup.networkintrusiondetection.service.TestService;

import java.util.List;

@RestController
@RequestMapping("/test")
public class TestController {

    private final TestService testService;

    @Autowired
    public TestController(TestService testService) {
        this.testService = testService;
    }

    @GetMapping("/findAll")
    public ResponseEntity<List<Test>> getAll() {
        return ResponseEntity.ok(testService.findAll());
    }

    @GetMapping("/predictAll")
    public ResponseEntity<String> predictAll() {
        return ResponseEntity.ok(testService.predictAll());
    }

    @GetMapping("/calculate")
    public ResponseEntity<CalculationDto> calculate() {
        return ResponseEntity.ok(testService.calculate());
    }

    @GetMapping("/check")
    public ResponseEntity<String> check() {
        return ResponseEntity.ok(testService.provera());
    }
}

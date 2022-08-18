package rs.gov.mup.networkintrusiondetection.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rs.gov.mup.networkintrusiondetection.dto.CalculationDto;
import rs.gov.mup.networkintrusiondetection.model.Train;
import rs.gov.mup.networkintrusiondetection.service.TrainService;

import java.util.List;

@RestController
@RequestMapping("/train")
public class TrainController {

    private final TrainService trainService;

    @Autowired
    public TrainController(TrainService trainService) {
        this.trainService = trainService;
    }

    @GetMapping("/findAll")
    public ResponseEntity<List<Train>> getAll() {
        return ResponseEntity.ok(trainService.findAll());
    }

    @GetMapping("/predictAll")
    public ResponseEntity<String> predictAll() {
        return ResponseEntity.ok(trainService.predictAll());
    }

    @GetMapping("/calculate")
    public ResponseEntity<CalculationDto> calculate() {
        return ResponseEntity.ok(trainService.calculate());
    }

    @GetMapping("/check")
    public ResponseEntity<Integer> check() {
        return ResponseEntity.ok(trainService.provera());
    }
}

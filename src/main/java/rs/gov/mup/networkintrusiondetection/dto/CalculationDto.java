package rs.gov.mup.networkintrusiondetection.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class CalculationDto {

    private int truePositive;
    private int trueNegative;
    private int falsePositive;
    private int falseNegative;
    private double accuracy;
    private double precision;
    private double sensitivity;
    private double specificity;
    private double tpr;
    private double fpr;
    private double fScore;
}

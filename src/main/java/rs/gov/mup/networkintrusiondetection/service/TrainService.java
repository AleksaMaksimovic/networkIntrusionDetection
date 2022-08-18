package rs.gov.mup.networkintrusiondetection.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import rs.gov.mup.networkintrusiondetection.dto.CalculationDto;
import rs.gov.mup.networkintrusiondetection.model.Train;
import rs.gov.mup.networkintrusiondetection.repository.TrainRepository;

import java.util.List;

@Service
public class TrainService {
    private final TrainRepository trainRepository;

    @Autowired
    public TrainService(TrainRepository trainRepository) {
        this.trainRepository = trainRepository;
    }

    public List<Train> findAll() {
        return trainRepository.getAll();
    }

    public String predictAll() {
        List<Train> trainList = findAll();
        for (Train train : trainList) {
            if (train.getSameSrvRate() <= 7) {
                if (train.getCount() <= 1) {
                    if (train.getDstHostSerrorRate() <= 1) {
                        if (train.getDstHostSrvRerrorRate() <= 14) {
                            if (train.getDstHostDiffSrvRate() <= 2) {
                                if (train.getRerrorRate() <= 2) {
                                    train.setTypePredicted("normal");
                                } else {
                                    if (train.getSrvRerrorRate() <= 10) {
                                        train.setTypePredicted("anomaly");
                                    } else {
                                        train.setTypePredicted("normal");
                                    }
                                }
                            } else {
                                if (train.getDiffSrvRate() <= 7) {
                                    if (!train.getLoggedIn()) {
                                        switch (train.getService()) {
                                            case "IRC", "efs", "X11", "Z39_50", "auth", "bgp", "courier", "csnet_ns",
                                                    "ctf", "daytime", "discard", "domain", "domain_u", "echo", "eco_i",
                                                    "ecr_i", "exec", "finger", "ftp", "ftp_data", "gopher", "hostnames",
                                                    "http", "http_443", "http_8001", "imap4", "iso_tsap", "klogin", "kshell",
                                                    "ldap", "login", "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn",
                                                    "netstat", "nnsp", "nntp", "ntp_u", "pm_dump", "pop_2", "pop_3", "printer",
                                                    "private", "red_i", "remote_job", "rje", "shell", "smtp", "sql_net", "ssh",
                                                    "sunrpc", "supdup", "systat", "telnet", "tim_i", "time", "urh_i", "urp_i",
                                                    "uucp", "uucp_path", "vmnet", "whois" ->
                                                    train.setTypePredicted("anomaly");
                                            case "other" -> {
                                                if (train.getDstHostDiffSrvRate() <= 7) {
                                                    train.setTypePredicted("anomaly");
                                                } else {
                                                    train.setTypePredicted("normal");
                                                }
                                            }
                                            default ->
                                                    throw new IllegalStateException("Unexpected value: " + train.getService());
                                        }
                                    } else {
                                        train.setTypePredicted("normal");
                                    }
                                } else {
                                    if (train.getSameSrvRate() <= 3) {
                                        if (train.getSerrorRate() <= 1) {
                                            train.setTypePredicted("anomaly");
                                        } else {
                                            train.setTypePredicted("normal");
                                        }
                                    } else {
                                        train.setTypePredicted("normal");
                                    }
                                }
                            }
                        } else {
                            train.setTypePredicted("anomaly");
                        }
                    } else {
                        train.setTypePredicted("anomaly");
                    }
                } else {
                    if (!train.getLoggedIn()) {
                        train.setTypePredicted("anomaly");
                    } else {
                        if (train.getDiffSrvRate() <= 9) {
                            train.setTypePredicted("normal");
                        } else {
                            train.setTypePredicted("anomaly");
                        }
                    }
                }
            } else {
                switch (train.getFlag()) {
                    case "OTH", "RSTOS0", "SH" -> train.setTypePredicted("anomaly");
                    case "S1", "S2", "S3" -> train.setTypePredicted("normal");
                    case "REJ" -> {
                        if (train.getDstHostSameSrvRate() < 3) {
                            if (train.getDstHostDiffSrvRate() <= 1) {
                                if (train.getDstHostSrvCount() <= 1) {
                                    train.setTypePredicted("normal");
                                } else {
                                    train.setTypePredicted("anomaly");
                                }
                            } else {
                                train.setTypePredicted("anomaly");
                            }
                        } else {
                            switch (train.getService()) {
                                case "IRC", "X11", "Z39_50", "auth", "bgp", "courier", "csnet_ns",
                                        "ctf", "daytime", "discard", "domain", "domain_u", "echo",
                                        "eco_i", "ecr_i", "efs", "exec", "finger", "ftp",
                                        "gopher", "hostnames", "http", "http_443", "http_8001",
                                        "imap4", "iso_tsap", "klogin", "kshell", "ldap", "link", "login",
                                        "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn", "netstat", "nnsp",
                                        "nntp", "ntp_u", "other", "pm_dump", "pop_2", "pop_3", "printer", "red_i", "remote_job",
                                        "rje", "shell", "smtp", "sql_net", "sunrpc", "supdup", "systat", "telnet", "tim_i",
                                        "time", "urh_i", "urp_i", "uucp", "uucp_path", "vmnet", "whois" ->
                                        train.setTypePredicted("normal");
                                case "ftp_data", "private", "ssh", "RSTOS0" -> train.setTypePredicted("anomaly");
                            }
                        }

                    }
                    case "RSTO" -> {
                        if (train.getDstHostSrvRerrorRate() <= 9) {
                            train.setTypePredicted("normal");
                        } else {
                            if (train.getDstHostSameSrvRate() <= 4) {
                                train.setTypePredicted("normal");
                            } else {
                                train.setTypePredicted("anomaly");
                            }
                        }
                    }
                    case "RSTR" -> {
                        if (train.getDstHostSameSrvRate() <= 1) {
                            train.setTypePredicted("anomaly");
                        } else {
                            if (train.getDstHostSameSrvRate() <= 14) {
                                if (train.getDstHostSrvCount() <= 3) {
                                    train.setTypePredicted("normal");
                                } else {
                                    train.setTypePredicted("anomaly");
                                }
                            } else {
                                train.setTypePredicted("anomaly");
                            }
                        }
                    }
                    case "S0" -> {
                        if (train.getDstHostSrvSerrorRate() <= 2) {
                            if (train.getDstHostSerrorRate() <= 11) {
                                train.setTypePredicted("normal");
                            } else {
                                switch (train.getService()) {
                                    case "IRC", "X11", "Z39_50", "auth", "bgp", "courier", "csnet_ns", "ctf", "daytime", "discard",
                                            "domain", "domain_u", "echo", "eco_i", "ecr_i", "efs", "exec", "finger", "ftp", "ftp_data",
                                            "gopher", "hostnames", "http_443", "http_8001", "imap4", "iso_tsap", "klogin", "kshell",
                                            "ldap", "link", "login", "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn",
                                            "netstat", "nnsp", "nntp", "ntp_u", "other", "pm_dump", "pop_2", "pop_3", "printer",
                                            "private", "red_i", "remote_job", "rje", "shell", "smtp", "sql_net", "ssh", "sunrpc",
                                            "supdup", "systat", "telnet", "tim_i", "time", "urh_i", "urp_i", "uucp", "uucp_path",
                                            "vmnet", "whois" -> train.setTypePredicted("anomaly");
                                    case "http" -> train.setTypePredicted("normal");
                                }
                            }
                        } else {
                            train.setTypePredicted("anomaly");
                        }
                    }
                    case "SF" -> {
                        switch (train.getService()) {
                            case "IRC", "X11", "Z39_50", "auth", "bgp", "courier", "csnet_ns", "ctf", "daytime",
                                    "discard", "domain", "domain_u", "echo", "efs", "exec", "finger", "hostnames",
                                    "http_443", "http_8001", "iso_tsap", "klogin", "kshell", "ldap", "link", "login",
                                    "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn", "netstat", "nnsp", "nntp",
                                    "ntp_u", "pm_dump", "pop_2", "pop_3", "printer", "red_i", "remote_job", "rje",
                                    "shell", "smtp", "sql_net", "sunrpc", "supdup", "systat", "telnet", "urh_i", "urp_i",
                                    "uucp", "uucp_path", "vmnet", "whois" -> train.setTypePredicted("normal");
                            case "gopher", "imap4", "ssh", "tim_i" -> train.setTypePredicted("anomaly");
                            case "eco_i" -> {
                                if (train.getDstHostCount() <= 2) {
                                    train.setTypePredicted("anomaly");
                                } else {
                                    if (train.getDstHostDiffSrvRate() <= 1) {
                                        train.setTypePredicted("normal");
                                    } else {
                                        train.setTypePredicted("anomaly");
                                    }
                                }
                            }
                            case "ecr_i" -> {
                                if (train.getCount() <= 1) {
                                    if (train.getSrvDiffHostRate() <= 4) {
                                        if (train.getDstHostCount() <= 15) {
                                            if (train.getDstHostSameSrvRate() <= 1) {
                                                if (train.getDstHostDiffSrvRate() <= 1) {
                                                    train.setTypePredicted("anomaly");
                                                } else {
                                                    train.setTypePredicted("normal");
                                                }
                                            } else {
                                                if (train.getDstHostSrvCount() <= 2) {
                                                    train.setTypePredicted("anomaly");
                                                } else {
                                                    train.setTypePredicted("normal");
                                                }
                                            }
                                        } else {
                                            train.setTypePredicted("anomaly");
                                        }
                                    } else {
                                        train.setTypePredicted("anomaly");
                                    }
                                } else {
                                    train.setTypePredicted("anomaly");
                                }
                            }
                            case "ftp" -> {
                                if (train.getDstHostSrvCount() <= 5) {
                                    if (train.getDstHostSrvCount() <= 4) {
                                        if (train.getDstHostSerrorRate() <= 1) {
                                            train.setTypePredicted("normal");
                                        } else {
                                            train.setTypePredicted("anomaly");
                                        }
                                    } else {
                                        if (train.getDstHostSameSrvRate() <= 6) {
                                            train.setTypePredicted("anomaly");
                                        } else {
                                            train.setTypePredicted("normal");
                                        }
                                    }
                                } else {
                                    train.setTypePredicted("anomaly");
                                }
                            }
                            case "ftp_data" -> {
                                if (train.getDstHostSameSrvRate() <= 14) {
                                    train.setTypePredicted("normal");
                                } else {
                                    if (train.getDstHostSrvDiffHostRate() <= 1) {
                                        if (train.getDstHostSrvCount() <= 3) {
                                            if (!train.getLoggedIn()) {
                                                train.setTypePredicted("anomaly");
                                            } else {
                                                if (train.getDstHostSrvCount() <= 2) {
                                                    train.setTypePredicted("normal");
                                                } else {
                                                    train.setTypePredicted("anomaly");
                                                }
                                            }
                                        } else {
                                            train.setTypePredicted("normal");
                                        }
                                    } else {
                                        train.setTypePredicted("anomaly");
                                    }
                                }
                            }
                            case "http" -> {
                                if (train.getSrvRerrorRate() <= 2) {
                                    if (train.getDstHostSrvCount() <= 11) {
                                        if (train.getDstHostSrvRerrorRate() <= 1) {
                                            if (train.getDstHostSrvDiffHostRate() <= 1) {
                                                if (train.getSrvDiffHostRate() <= 1) {
                                                    if (train.getDstHostCount() <= 4) {
                                                        train.setTypePredicted("normal");
                                                    } else {
                                                        if (train.getDstHostSameSrvRate() <= 15) {
                                                            train.setTypePredicted("normal");
                                                        } else {
                                                            train.setTypePredicted("anomaly");
                                                        }
                                                    }
                                                } else {
                                                    train.setTypePredicted("normal");
                                                }
                                            } else {
                                                train.setTypePredicted("normal");
                                            }
                                        } else {
                                            if (train.getDstHostSrvDiffHostRate() <= 2) {
                                                train.setTypePredicted("anomaly");
                                            } else {
                                                train.setTypePredicted("normal");
                                            }
                                        }
                                    } else {
                                        train.setTypePredicted("normal");
                                    }
                                } else {
                                    if (train.getDstHostSameSrvRate() <= 15) {
                                        train.setTypePredicted("normal");
                                    } else {
                                        if (train.getDstHostCount() <= 6) {
                                            if (train.getDstHostSrvCount() <= 3) {
                                                train.setTypePredicted("anomaly");
                                            } else {
                                                train.setTypePredicted("normal");
                                            }
                                        } else {
                                            train.setTypePredicted("anomaly");
                                        }
                                    }
                                }
                            }
                            case "other" -> {
                                if (train.getDstHostDiffSrvRate() <= 7) {
                                    if (train.getCount() <= 2) {
                                        if (train.getDuration() <= 1) {
                                            if (train.getDstHostDiffSrvRate() <= 4) {
                                                if (train.getDstHostCount() <= 15) {
                                                    train.setTypePredicted("normal");
                                                } else {
                                                    train.setTypePredicted("anomaly");
                                                }
                                            } else {
                                                train.setTypePredicted("normal");
                                            }
                                        } else {
                                            train.setTypePredicted("normal");
                                        }
                                    } else {
                                        train.setTypePredicted("normal");
                                    }
                                } else {
                                    train.setTypePredicted("normal");
                                }
                            }
                            case "private" -> {
                                if (train.getDstHostSrvCount() <= 13) {
                                    if (train.getDstHostSameSrvRate() <= 9) {
                                        if (train.getDstHostCount() <= 5) {
                                            if (train.getDstHostSrvCount() <= 1) {
                                                train.setTypePredicted("anomaly");
                                            } else {
                                                train.setTypePredicted("anomaly");
                                            }
                                        } else {
                                            if (train.getDstHostSrvCount() <= 5) {
                                                train.setTypePredicted("anomaly");
                                            } else {
                                                if (train.getCount() <= 1) {
                                                    if (train.getDstHostSerrorRate() <= 1) {
                                                        train.setTypePredicted("normal");
                                                    } else {
                                                        train.setTypePredicted("anomaly");
                                                    }
                                                } else {
                                                    train.setTypePredicted("anomaly");
                                                }
                                            }
                                        }

                                    } else {
                                        if (train.getCount() <= 1) {
                                            if (train.getDstHostDiffSrvRate() <= 1) {
                                                if (train.getDstHostSameSrvRate() <= 14) {
                                                    if (train.getDstHostSameSrvRate() <= 12) {
                                                        train.setTypePredicted("normal");
                                                    } else {
                                                        train.setTypePredicted("anomaly");
                                                    }
                                                } else {
                                                    train.setTypePredicted("normal");
                                                }
                                            } else {
                                                train.setTypePredicted("normal");
                                            }
                                        } else {
                                            train.setTypePredicted("anomaly");
                                        }
                                    }
                                } else {
                                    train.setTypePredicted("normal");
                                }
                            }
                            case "time" -> {
                                if (train.getDstHostSameSrvRate() <= 8) {
                                    train.setTypePredicted("anomaly");
                                } else {
                                    train.setTypePredicted("normal");
                                }
                            }
                        }
                    }
                }
            }
            trainRepository.save(train);
        }
        return "ok";
    }


    public CalculationDto calculate() {
        //  inicijalizacija objekta CalculationDto
        CalculationDto calculationDto = new CalculationDto();

        //  inicijalizacija promenljivih u koje će biti smešteni rezultati prebrojavanja
        int truePositive = 0;
        int trueNegative = 0;
        int falsePositive = 0;
        int falseNegative = 0;

        //inicijalizacija liste objekata tipa Train i njeno popunjavanje podacima iz baze podataka
        List<Train> list = findAll();

        //  foreach petlja koja prolazi kroz sve objekte unutar liste i inkrementuje brojače za TP,TN,FP,FN u zavisnosti od ispunjenosti uslova
        for (Train train : list) {
            if (train.getType().equals("normal")) {
                if (train.getTypePredicted().equals("normal")) {
                    truePositive += 1;
                } else {
                    falseNegative += 1;
                }
            } else {
                if (train.getTypePredicted().equals("normal")) {
                    falsePositive += 1;
                } else {
                    trueNegative += 1;
                }
            }
        }

        //  setovanje atributa objekta calculationDto na izračunate vrednosti
        calculationDto.setFalseNegative(falseNegative);
        calculationDto.setFalsePositive(falsePositive);
        calculationDto.setTrueNegative(trueNegative);
        calculationDto.setTruePositive(truePositive);

        //  programska implementacija formula za računanje vrednosti Accuracy, Precision, Sensitivity, Specificity, FScore, Tpr, Fpr
        calculationDto.setAccuracy((double) (truePositive + trueNegative) / (truePositive + trueNegative + falsePositive + falseNegative));
        calculationDto.setPrecision((double) truePositive / (truePositive + falsePositive));
        calculationDto.setSensitivity((double) truePositive / (truePositive + falseNegative));
        calculationDto.setSpecificity((double) trueNegative / (trueNegative + falsePositive));
        calculationDto.setFScore(2 * calculationDto.getPrecision() * calculationDto.getSensitivity() / (calculationDto.getPrecision() + calculationDto.getSensitivity()));
        calculationDto.setTpr((double) truePositive / (truePositive + falseNegative));
        calculationDto.setFpr((double) falsePositive / (falsePositive + trueNegative));

        //  vraćanje objekta calculationDto kao rezultat servisa
        return calculationDto;
    }

    public Integer provera() {
        Integer brojac = 0;
        List<Train> trainList = findAll();
        for (Train train : trainList) {
            if (train.getType().equals(train.getTypePredicted())) {
                brojac += 1;
            }
        }
        return brojac;
    }
}

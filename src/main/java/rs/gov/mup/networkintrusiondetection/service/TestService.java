package rs.gov.mup.networkintrusiondetection.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import rs.gov.mup.networkintrusiondetection.model.Test;
import rs.gov.mup.networkintrusiondetection.repository.TestRepository;

import java.util.List;

@Service
public class TestService {
    private final TestRepository testRepository;

    @Autowired
    public TestService(TestRepository testRepository) {
        this.testRepository = testRepository;
    }

    public List<Test> findAll() {
        return testRepository.getAll();
    }

    public String predictAll() {
        List<Test> testList = findAll();
        for (Test test : testList) {
            if (test.getSameSrvRate() <= 7) {
                if (test.getCount() <= 1) {
                    if (test.getDstHostSerrorRate() <= 1) {
                        if (test.getDstHostSrvRerrorRate() <= 14) {
                            if (test.getDstHostDiffSrvRate() <= 2) {
                                if (test.getRerrorRate() <= 2) {
                                    test.setTypePredicted("normal");
                                } else {
                                    if (test.getSrvRerrorRate() <= 10) {
                                        test.setTypePredicted("anomaly");
                                    } else {
                                        test.setTypePredicted("normal");
                                    }
                                }
                            } else {
                                if (test.getDiffSrvRate() <= 7) {
                                    if (!test.getLoggedIn()) {
                                        switch (test.getService()) {
                                            case "IRC", "efs", "X11", "Z39_50", "auth", "bgp", "courier", "csnet_ns",
                                                    "ctf", "daytime", "discard", "domain", "domain_u", "echo", "eco_i",
                                                    "ecr_i", "exec", "finger", "ftp", "ftp_data", "gopher", "hostnames",
                                                    "http", "http_443", "http_8001", "imap4", "iso_tsap", "klogin", "kshell",
                                                    "ldap", "login", "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn",
                                                    "netstat", "nnsp", "nntp", "ntp_u", "pm_dump", "pop_2", "pop_3", "printer",
                                                    "private", "red_i", "remote_job", "rje", "shell", "smtp", "sql_net", "ssh",
                                                    "sunrpc", "supdup", "systat", "telnet", "tim_i", "time", "urh_i", "urp_i",
                                                    "uucp", "uucp_path", "vmnet", "whois" ->
                                                    test.setTypePredicted("anomaly");
                                            case "other" -> {
                                                if (test.getDstHostDiffSrvRate() <= 7) {
                                                    test.setTypePredicted("anomaly");
                                                } else {
                                                    test.setTypePredicted("normal");
                                                }
                                            }
                                            default ->
                                                    throw new IllegalStateException("Unexpected value: " + test.getService());
                                        }
                                    } else {
                                        test.setTypePredicted("normal");
                                    }
                                } else {
                                    if (test.getSameSrvRate() <= 3) {
                                        if (test.getSerrorRate() <= 1) {
                                            test.setTypePredicted("anomaly");
                                        } else {
                                            test.setTypePredicted("normal");
                                        }
                                    } else {
                                        test.setTypePredicted("normal");
                                    }
                                }
                            }
                        } else {
                            test.setTypePredicted("anomaly");
                        }
                    } else {
                        test.setTypePredicted("anomaly");
                    }
                } else {
                    if (!test.getLoggedIn()) {
                        test.setTypePredicted("anomaly");
                    } else {
                        if (test.getDiffSrvRate() <= 9) {
                            test.setTypePredicted("normal");
                        } else {
                            test.setTypePredicted("anomaly");
                        }
                    }
                }
            } else {
                switch (test.getFlag()) {
                    case "OTH", "RSTOS0", "SH" -> test.setTypePredicted("anomaly");
                    case "S1", "S2", "S3" -> test.setTypePredicted("normal");
                    case "REJ" -> {
                        if (test.getDstHostSameSrvRate() < 3) {
                            if (test.getDstHostDiffSrvRate() <= 1) {
                                if (test.getDstHostSrvCount() <= 1) {
                                    test.setTypePredicted("normal");
                                } else {
                                    test.setTypePredicted("anomaly");
                                }
                            } else {
                                test.setTypePredicted("anomaly");
                            }
                        } else {
                            switch (test.getService()) {
                                case "IRC", "X11", "Z39_50", "auth", "bgp", "courier", "csnet_ns",
                                        "ctf", "daytime", "discard", "domain", "domain_u", "echo",
                                        "eco_i", "ecr_i", "efs", "exec", "finger", "ftp",
                                        "gopher", "hostnames", "http", "http_443", "http_8001",
                                        "imap4", "iso_tsap", "klogin", "kshell", "ldap", "link", "login",
                                        "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn", "netstat", "nnsp",
                                        "nntp", "ntp_u", "other", "pm_dump", "pop_2", "pop_3", "printer", "red_i", "remote_job",
                                        "rje", "shell", "smtp", "sql_net", "sunrpc", "supdup", "systat", "telnet", "tim_i",
                                        "time", "urh_i", "urp_i", "uucp", "uucp_path", "vmnet", "whois" ->
                                        test.setTypePredicted("normal");
                                case "ftp_data", "private", "ssh", "RSTOS0" -> test.setTypePredicted("anomaly");
                            }
                        }

                    }
                    case "RSTO" -> {
                        if (test.getDstHostSrvRerrorRate() <= 9) {
                            test.setTypePredicted("normal");
                        } else {
                            if (test.getDstHostSameSrvRate() <= 4) {
                                test.setTypePredicted("normal");
                            } else {
                                test.setTypePredicted("anomaly");
                            }
                        }
                    }
                    case "RSTR" -> {
                        if (test.getDstHostSameSrvRate() <= 1) {
                            test.setTypePredicted("anomaly");
                        } else {
                            if (test.getDstHostSameSrvRate() <= 14) {
                                if (test.getDstHostSrvCount() <= 3) {
                                    test.setTypePredicted("normal");
                                } else {
                                    test.setTypePredicted("anomaly");
                                }
                            } else {
                                test.setTypePredicted("anomaly");
                            }
                        }
                    }
                    case "S0" -> {
                        if (test.getDstHostSrvSerrorRate() <= 2) {
                            if (test.getDstHostSerrorRate() <= 11) {
                                test.setTypePredicted("normal");
                            } else {
                                switch (test.getService()) {
                                    case "IRC", "X11", "Z39_50", "auth", "bgp", "courier", "csnet_ns", "ctf", "daytime", "discard",
                                            "domain", "domain_u", "echo", "eco_i", "ecr_i", "efs", "exec", "finger", "ftp", "ftp_data",
                                            "gopher", "hostnames", "http_443", "http_8001", "imap4", "iso_tsap", "klogin", "kshell",
                                            "ldap", "link", "login", "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn",
                                            "netstat", "nnsp", "nntp", "ntp_u", "other", "pm_dump", "pop_2", "pop_3", "printer",
                                            "private", "red_i", "remote_job", "rje", "shell", "smtp", "sql_net", "ssh", "sunrpc",
                                            "supdup", "systat", "telnet", "tim_i", "time", "urh_i", "urp_i", "uucp", "uucp_path",
                                            "vmnet", "whois" -> test.setTypePredicted("anomaly");
                                    case "http" -> test.setTypePredicted("normal");
                                }
                            }
                        } else {
                            test.setTypePredicted("anomaly");
                        }
                    }
                    case "SF" -> {
                        switch (test.getService()) {
                            case "IRC", "X11", "Z39_50", "auth", "bgp", "courier", "csnet_ns", "ctf", "daytime",
                                    "discard", "domain", "domain_u", "echo", "efs", "exec", "finger", "hostnames",
                                    "http_443", "http_8001", "iso_tsap", "klogin", "kshell", "ldap", "link", "login",
                                    "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn", "netstat", "nnsp", "nntp",
                                    "ntp_u", "pm_dump", "pop_2", "pop_3", "printer", "red_i", "remote_job", "rje",
                                    "shell", "smtp", "sql_net", "sunrpc", "supdup", "systat", "telnet", "urh_i", "urp_i",
                                    "uucp", "uucp_path", "vmnet", "whois" -> test.setTypePredicted("normal");
                            case "gopher", "imap4", "ssh", "tim_i" -> test.setTypePredicted("anomaly");
                            case "eco_i" -> {
                                if (test.getDstHostCount() <= 2) {
                                    test.setTypePredicted("anomaly");
                                } else {
                                    if (test.getDstHostDiffSrvRate() <= 1) {
                                        test.setTypePredicted("normal");
                                    } else {
                                        test.setTypePredicted("anomaly");
                                    }
                                }
                            }
                            case "ecr_i" -> {
                                if (test.getCount() <= 1) {
                                    if (test.getSrvDiffHostRate() <= 4) {
                                        if (test.getDstHostCount() <= 15) {
                                            if (test.getDstHostSameSrvRate() <= 1) {
                                                if (test.getDstHostDiffSrvRate() <= 1) {
                                                    test.setTypePredicted("anomaly");
                                                } else {
                                                    test.setTypePredicted("normal");
                                                }
                                            } else {
                                                if (test.getDstHostSrvCount() <= 2) {
                                                    test.setTypePredicted("anomaly");
                                                } else {
                                                    test.setTypePredicted("normal");
                                                }
                                            }
                                        } else {
                                            test.setTypePredicted("anomaly");
                                        }
                                    } else {
                                        test.setTypePredicted("anomaly");
                                    }
                                } else {
                                    test.setTypePredicted("anomaly");
                                }
                            }
                            case "ftp" -> {
                                if (test.getDstHostSrvCount() <= 5) {
                                    if (test.getDstHostSrvCount() <= 4) {
                                        if (test.getDstHostSerrorRate() <= 1) {
                                            test.setTypePredicted("normal");
                                        } else {
                                            test.setTypePredicted("anomaly");
                                        }
                                    } else {
                                        if (test.getDstHostSameSrvRate() <= 6) {
                                            test.setTypePredicted("anomaly");
                                        } else {
                                            test.setTypePredicted("normal");
                                        }
                                    }
                                } else {
                                    test.setTypePredicted("anomaly");
                                }
                            }
                            case "ftp_data" -> {
                                if (test.getDstHostSameSrvRate() <= 14) {
                                    test.setTypePredicted("normal");
                                } else {
                                    if (test.getDstHostSrvDiffHostRate() <= 1) {
                                        if (test.getDstHostSrvCount() <= 3) {
                                            if (!test.getLoggedIn()) {
                                                test.setTypePredicted("anomaly");
                                            } else {
                                                if (test.getDstHostSrvCount() <= 2) {
                                                    test.setTypePredicted("normal");
                                                } else {
                                                    test.setTypePredicted("anomaly");
                                                }
                                            }
                                        } else {
                                            test.setTypePredicted("normal");
                                        }
                                    } else {
                                        test.setTypePredicted("anomaly");
                                    }
                                }
                            }
                            case "http" -> {
                                if (test.getSrvRerrorRate() <= 2) {
                                    if (test.getDstHostSrvCount() <= 11) {
                                        if (test.getDstHostSrvRerrorRate() <= 1) {
                                            if (test.getDstHostSrvDiffHostRate() <= 1) {
                                                if (test.getSrvDiffHostRate() <= 1) {
                                                    if (test.getDstHostCount() <= 4) {
                                                        test.setTypePredicted("normal");
                                                    } else {
                                                        if (test.getDstHostSameSrvRate() <= 15) {
                                                            test.setTypePredicted("normal");
                                                        } else {
                                                            test.setTypePredicted("anomaly");
                                                        }
                                                    }
                                                } else {
                                                    test.setTypePredicted("normal");
                                                }
                                            } else {
                                                test.setTypePredicted("normal");
                                            }
                                        } else {
                                            if (test.getDstHostSrvDiffHostRate() <= 2) {
                                                test.setTypePredicted("anomaly");
                                            } else {
                                                test.setTypePredicted("normal");
                                            }
                                        }
                                    } else {
                                        test.setTypePredicted("normal");
                                    }
                                } else {
                                    if (test.getDstHostSameSrvRate() <= 15) {
                                        test.setTypePredicted("normal");
                                    } else {
                                        if (test.getDstHostCount() <= 6) {
                                            if (test.getDstHostSrvCount() <= 3) {
                                                test.setTypePredicted("anomaly");
                                            } else {
                                                test.setTypePredicted("normal");
                                            }
                                        } else {
                                            test.setTypePredicted("anomaly");
                                        }
                                    }
                                }
                            }
                            case "other" -> {
                                if (test.getDstHostDiffSrvRate() <= 7) {
                                    if (test.getCount() <= 2) {
                                        if (test.getDuration() <= 1) {
                                            if (test.getDstHostDiffSrvRate() <= 4) {
                                                if (test.getDstHostCount() <= 15) {
                                                    test.setTypePredicted("normal");
                                                } else {
                                                    test.setTypePredicted("anomaly");
                                                }
                                            } else {
                                                test.setTypePredicted("normal");
                                            }
                                        } else {
                                            test.setTypePredicted("normal");
                                        }
                                    } else {
                                        test.setTypePredicted("normal");
                                    }
                                } else {
                                    test.setTypePredicted("normal");
                                }
                            }
                            case "private" -> {
                                if (test.getDstHostSrvCount() <= 13) {
                                    if (test.getDstHostSameSrvRate() <= 9) {
                                        if (test.getDstHostCount() <= 5) {
                                            if (test.getDstHostSrvCount() <= 1) {
                                                test.setTypePredicted("anomaly");
                                            } else {
                                                test.setTypePredicted("anomaly");
                                            }
                                        } else {
                                            if (test.getDstHostSrvCount() <= 5) {
                                                test.setTypePredicted("anomaly");
                                            } else {
                                                if (test.getCount() <= 1) {
                                                    if (test.getDstHostSerrorRate() <= 1) {
                                                        test.setTypePredicted("normal");
                                                    } else {
                                                        test.setTypePredicted("anomaly");
                                                    }
                                                } else {
                                                    test.setTypePredicted("anomaly");
                                                }
                                            }
                                        }

                                    } else {
                                        if (test.getCount() <= 1) {
                                            if (test.getDstHostDiffSrvRate() <= 1) {
                                                if (test.getDstHostSameSrvRate() <= 14) {
                                                    if (test.getDstHostSameSrvRate() <= 12) {
                                                        test.setTypePredicted("normal");
                                                    } else {
                                                        test.setTypePredicted("anomaly");
                                                    }
                                                } else {
                                                    test.setTypePredicted("normal");
                                                }
                                            } else {
                                                test.setTypePredicted("normal");
                                            }
                                        } else {
                                            test.setTypePredicted("anomaly");
                                        }
                                    }
                                } else {
                                    test.setTypePredicted("normal");
                                }
                            }
                            case "time" -> {
                                if (test.getDstHostSameSrvRate() <= 8) {
                                    test.setTypePredicted("anomaly");
                                } else {
                                    test.setTypePredicted("normal");
                                }
                            }
                        }
                    }
                }
            }
            testRepository.save(test);
        }
        return "ok";
    }
}

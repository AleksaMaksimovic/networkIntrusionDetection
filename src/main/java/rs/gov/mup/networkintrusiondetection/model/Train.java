package rs.gov.mup.networkintrusiondetection.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Train {

    @Id
    private Long id;
    private Long duration;
    private String protocolType;
    private String service;
    private String flag;
    private Long srcBytes;
    private Long dstBytes;
    private Long land;
    private Long wrongFragment;
    private Boolean urgent;
    private Boolean hot;
    private Long numFailedLogins;
    private Boolean loggedIn;
    private Long numCompromised;
    private Boolean rootShell;
    private Boolean suAttempted;
    private Long numRoot;
    private Long numFileCreations;
    private Long numShells;
    private Long numAccessFiles;
    private Long numOutboundCmds;
    private Boolean isHostLogin;
    private Boolean isGuestLogin;
    private Long count;
    private Long srvCount;
    private Long serrorRate;
    private Long srvSerrorRate;
    private Long rerrorRate;
    private Long srvRerrorRate;
    private Long sameSrvRate;
    private Long diffSrvRate;
    private Long srvDiffHostRate;
    private Long dstHostCount;
    private Long dstHostSrvCount;
    private Long dstHostSameSrvRate;
    private Long dstHostDiffSrvRate;
    private Long dstHostSameSrcPortRate;
    private Long dstHostSrvDiffHostRate;
    private Long dstHostSerrorRate;
    private Long dstHostSrvSerrorRate;
    private Long dstHostRerrorRate;
    private Long dstHostSrvRerrorRate;
    private String type;
    private String typePredicted;
}

package rs.gov.mup.networkintrusiondetection.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import rs.gov.mup.networkintrusiondetection.model.Train;

import java.util.List;

@Repository
public interface TrainRepository extends CrudRepository<Train, Long> {

    @Query(value = "select t from Train t")
    List<Train> getAll();
}

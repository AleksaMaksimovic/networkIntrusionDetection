package rs.gov.mup.networkintrusiondetection.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import rs.gov.mup.networkintrusiondetection.model.Test;

import java.util.List;

@Repository
public interface TestRepository extends CrudRepository<Test, Long> {

    @Query(value = "select t from Test t")
    List<Test> getAll();
}

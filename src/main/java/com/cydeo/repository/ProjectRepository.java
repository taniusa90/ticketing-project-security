package com.cydeo.repository;

import com.cydeo.entity.Project;
import com.cydeo.entity.User;
import com.cydeo.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProjectRepository extends JpaRepository<Project,Long> {

    Project findByProjectCode(String code);//returning entity from db
    List<Project> findAllByAssignedManager(User manager);
    List<Project> findAllByProjectStatusIsNotAndAssignedManager(Status status, User assignedManager);

}

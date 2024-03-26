package com.bem.security.book;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@EntityListeners(AuditingEntityListener.class)
public class Book {

    @Id
    @GeneratedValue
    private Integer id;

    private String author;

    private String isbn;

//    @CreatedDate
//    @Column(nullable = false, updatable = false)
    private Date createDate;

//    @LastModifiedDate
//    @Column(insertable = false)
    private Date lastModified;

//    @CreatedBy
//    @Column(nullable = false, updatable = false)
    private Integer createdBy;

//    @LastModifiedBy
//    @Column(insertable = false)
    private Date lastModifiedBy;
}
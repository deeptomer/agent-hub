CREATE SEQUENCE seq_emp_id START WITH 1000 INCREMENT BY 1 NOCACHE;

CREATE TABLE employees (
  emp_id      NUMBER(10)    PRIMARY KEY,
  full_name   VARCHAR2(120) NOT NULL,
  department  VARCHAR2(40),
  salary      NUMBER(10,2),
  hire_date   DATE DEFAULT SYSDATE,
  manager_id  NUMBER(10)
);

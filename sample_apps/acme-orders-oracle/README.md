# Acme Orders (synthetic Oracle sample)

A fictional, SQL-heavy Java application used as the demo source system for the
Oracle to PostgreSQL migration flow. Nothing here is client code.

It deliberately packs in the constructs that make real Oracle migrations hard:

| Area | Where | Oracle features |
|------|-------|-----------------|
| JDBC DAOs | `dao/OrderDao.java`, `EmployeeDao.java`, `ReportDao.java` | ROWNUM, DECODE, NVL, NVL2, `(+)` joins, CONNECT BY, KEEP DENSE_RANK, MINUS, MERGE, PIVOT, LISTAGG, REGEXP_LIKE, hints, FOR UPDATE SKIP LOCKED, sequences, DUAL |
| MyBatis mapper | `resources/mappers/CustomerMapper.xml` | selectKey with sequence, ROWNUM paging, `(+)` joins |
| Spring Data JPA | `repository/ProductRepository.java` | native queries mixed with portable JPQL |
| PL/SQL | `plsql/pkg_order_mgmt.sql` | package spec and body, autonomous transaction, BULK COLLECT, FORALL, `%TYPE`, `RAISE_APPLICATION_ERROR` |
| Schema | `schema/oracle_schema.sql` | NUMBER, VARCHAR2, DATE vs TIMESTAMP, CLOB, sequences |

It also contains a few semantic traps that run on Postgres but behave differently:
empty string vs NULL (`NOTES = ''`), ROWNUM applied before ORDER BY in `topSpenders`,
DATE columns that carry a time part, and `INTERVAL '90' DAY` literals.

package com.acme.orders.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/**
 * Org-chart and payroll style queries. Heavy on Oracle hierarchical and analytic SQL.
 */
public class EmployeeDao {

    private final DataSource dataSource;

    public EmployeeDao(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    // Oracle hierarchical query: CONNECT BY PRIOR / START WITH / LEVEL / SYS_CONNECT_BY_PATH
    private static final String ORG_TREE =
        "SELECT LEVEL AS DEPTH, " +
        "       LPAD(' ', 2 * (LEVEL - 1)) || e.FULL_NAME AS INDENTED_NAME, " +
        "       SYS_CONNECT_BY_PATH(e.FULL_NAME, ' > ') AS PATH, " +
        "       e.EMPLOYEE_ID " +
        "FROM EMPLOYEES e " +
        "START WITH e.MANAGER_ID IS NULL " +
        "CONNECT BY PRIOR e.EMPLOYEE_ID = e.MANAGER_ID " +
        "ORDER SIBLINGS BY e.FULL_NAME";

    // Oracle analytic functions with KEEP DENSE_RANK (Oracle-specific aggregate form)
    private static final String TOP_PAID_PER_DEPT =
        "SELECT DEPARTMENT, " +
        "       MAX(FULL_NAME) KEEP (DENSE_RANK FIRST ORDER BY SALARY DESC) AS TOP_EARNER, " +
        "       MAX(SALARY) AS TOP_SALARY " +
        "FROM EMPLOYEES " +
        "GROUP BY DEPARTMENT";

    // Oracle: DUAL table, sequence, NVL2, TRUNC dates, string concat with NULLs
    private static final String TENURE_REPORT =
        "SELECT e.EMPLOYEE_ID, " +
        "       e.FULL_NAME, " +
        "       TRUNC(MONTHS_BETWEEN(SYSDATE, e.HIRE_DATE) / 12) AS YEARS_SERVICE, " +
        "       NVL2(e.MANAGER_ID, 'Reports', 'Top') AS ROLE_TYPE, " +
        "       e.FULL_NAME || ' (' || e.DEPARTMENT || ')' AS LABEL " +
        "FROM EMPLOYEES e " +
        "WHERE e.HIRE_DATE < SYSDATE - 365";

    // Oracle: MINUS set operator
    private static final String EMPLOYEES_WITHOUT_REPORTS =
        "SELECT EMPLOYEE_ID FROM EMPLOYEES " +
        "MINUS " +
        "SELECT MANAGER_ID FROM EMPLOYEES WHERE MANAGER_ID IS NOT NULL";

    public List<String> loadOrgTree() throws SQLException {
        List<String> lines = new ArrayList<>();
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(ORG_TREE);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                lines.add(rs.getString("INDENTED_NAME"));
            }
        }
        return lines;
    }

    public long nextEmployeeCheck() throws SQLException {
        // Oracle: SELECT ... FROM DUAL
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT SEQ_AUDIT_ID.NEXTVAL FROM DUAL");
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getLong(1) : 0L;
        }
    }
}

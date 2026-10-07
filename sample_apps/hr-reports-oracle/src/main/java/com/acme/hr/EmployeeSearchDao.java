package com.acme.hr;

import java.sql.*;
import java.util.*;

/** Second demo project: SQL that is assembled at runtime instead of written as one string literal. */
public class EmployeeSearchDao {
    private static final String TABLE = "employees";
    private static final String BASE = "SELECT emp_id, full_name FROM employees ";

    private final Connection conn;

    public EmployeeSearchDao(Connection conn) { this.conn = conn; }

    /** Optional filters appended with StringBuilder; the sort column is chosen by the caller. */
    public List<String> search(String dept, Double minSalary, String sortColumn) throws SQLException {
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT emp_id, full_name, salary ");
        sb.append("FROM employees e ");
        sb.append("WHERE e.full_name IS NOT NULL ");
        if (dept != null) {
            sb.append("AND e.department = ? ");
        }
        if (minSalary != null) {
            sb.append("AND e.salary >= ? ");
        }
        sb.append("AND ROWNUM <= 100 ");
        sb.append("ORDER BY ").append(sortColumn);
        List<String> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sb.toString())) {
            int i = 1;
            if (dept != null) ps.setString(i++, dept);
            if (minSalary != null) ps.setDouble(i++, minSalary);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(rs.getString("full_name"));
            }
        }
        return out;
    }

    /** SQL built with String.format from a constant table name. */
    public Map<String, Integer> headcountByDepartment() throws SQLException {
        String sql = String.format("SELECT NVL(department, 'n/a') AS dept, COUNT(*) AS cnt FROM %s GROUP BY NVL(department, 'n/a')", TABLE);
        Map<String, Integer> out = new LinkedHashMap<>();
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) out.put(rs.getString("dept"), rs.getInt("cnt"));
        }
        return out;
    }

    /** A shared base string plus a second literal that completes it. */
    public List<String> recentHires() throws SQLException {
        String sql = BASE + "WHERE hire_date > SYSDATE - 30 ORDER BY hire_date DESC";
        List<String> out = new ArrayList<>();
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) out.add(rs.getString(2));
        }
        return out;
    }
}

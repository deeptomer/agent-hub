package com.acme.orders.dao;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

import com.acme.orders.model.Order;

/**
 * JDBC data access for orders. Written for Oracle 12c.
 */
public class OrderDao {

    private final DataSource dataSource;

    public OrderDao(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    // Oracle: sequence NEXTVAL, SYSDATE, NVL
    private static final String INSERT_ORDER =
        "INSERT INTO ORDERS (ORDER_ID, CUSTOMER_ID, ORDER_DATE, STATUS, TOTAL_AMOUNT, DISCOUNT_PCT, NOTES) " +
        "VALUES (SEQ_ORDER_ID.NEXTVAL, ?, SYSDATE, 'NEW', ?, NVL(?, 0), ?)";

    // Oracle: ROWNUM pagination (classic top-N pattern)
    private static final String RECENT_ORDERS =
        "SELECT * FROM ( " +
        "  SELECT o.ORDER_ID, o.CUSTOMER_ID, o.ORDER_DATE, o.STATUS, o.TOTAL_AMOUNT " +
        "  FROM ORDERS o " +
        "  WHERE o.CUSTOMER_ID = ? " +
        "  ORDER BY o.ORDER_DATE DESC " +
        ") WHERE ROWNUM <= 10";

    // Oracle: DECODE, NVL, TO_CHAR date formatting, optimizer hint
    private static final String ORDER_SUMMARY =
        "SELECT /*+ INDEX(o IDX_ORDERS_CUST_DATE) */ " +
        "  o.ORDER_ID, " +
        "  TO_CHAR(o.ORDER_DATE, 'YYYY-MM-DD HH24:MI:SS') AS ORDER_TS, " +
        "  DECODE(o.STATUS, 'NEW', 'Pending', 'SHP', 'Shipped', 'DLV', 'Delivered', 'Unknown') AS STATUS_TEXT, " +
        "  NVL(o.DISCOUNT_PCT, 0) AS DISCOUNT_PCT, " +
        "  o.TOTAL_AMOUNT * (1 - NVL(o.DISCOUNT_PCT, 0) / 100) AS NET_AMOUNT " +
        "FROM ORDERS o " +
        "WHERE o.ORDER_DATE >= TRUNC(SYSDATE) - 30";

    // Oracle: old-style outer join using (+)
    private static final String ORDERS_WITH_ITEMS =
        "SELECT o.ORDER_ID, i.LINE_NO, p.PRODUCT_NAME, i.QUANTITY " +
        "FROM ORDERS o, ORDER_ITEMS i, PRODUCTS p " +
        "WHERE o.ORDER_ID = i.ORDER_ID(+) " +
        "AND i.PRODUCT_ID = p.PRODUCT_ID(+) " +
        "AND o.CUSTOMER_ID = ?";

    // Oracle: ADD_MONTHS, MONTHS_BETWEEN, TRUNC on dates
    private static final String STALE_ORDERS =
        "SELECT ORDER_ID, ORDER_DATE FROM ORDERS " +
        "WHERE STATUS = 'NEW' " +
        "AND MONTHS_BETWEEN(SYSDATE, ORDER_DATE) > 3 " +
        "AND ORDER_DATE < ADD_MONTHS(TRUNC(SYSDATE, 'MM'), -1)";

    // Oracle: empty string is NULL; this predicate behaves differently in Postgres
    private static final String ORDERS_WITHOUT_NOTES =
        "SELECT ORDER_ID FROM ORDERS WHERE NOTES IS NULL OR NOTES = ''";

    public long createOrder(long customerId, double total, Double discount, String notes) throws SQLException {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(INSERT_ORDER, new String[] {"ORDER_ID"})) {
            ps.setLong(1, customerId);
            ps.setDouble(2, total);
            if (discount == null) ps.setNull(3, java.sql.Types.NUMERIC); else ps.setDouble(3, discount);
            ps.setString(4, notes);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                return rs.next() ? rs.getLong(1) : -1L;
            }
        }
    }

    public List<Order> findRecentOrders(long customerId) throws SQLException {
        List<Order> out = new ArrayList<>();
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(RECENT_ORDERS)) {
            ps.setLong(1, customerId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(Order.fromResultSet(rs));
                }
            }
        }
        return out;
    }

    public void shipOrder(long orderId) throws SQLException {
        // Calls a PL/SQL package procedure
        try (Connection c = dataSource.getConnection();
             CallableStatement cs = c.prepareCall("{call PKG_ORDER_MGMT.SHIP_ORDER(?, ?)}")) {
            cs.setLong(1, orderId);
            cs.registerOutParameter(2, java.sql.Types.VARCHAR);
            cs.execute();
        }
    }

    public int bumpStockAfterCancel(long orderId) throws SQLException {
        // Oracle: UPDATE with correlated subquery + RETURNING INTO handled via PL/SQL block
        String sql =
            "UPDATE PRODUCTS p SET p.STOCK_QTY = p.STOCK_QTY + " +
            "(SELECT NVL(SUM(i.QUANTITY), 0) FROM ORDER_ITEMS i " +
            " WHERE i.PRODUCT_ID = p.PRODUCT_ID AND i.ORDER_ID = ?) " +
            "WHERE EXISTS (SELECT 1 FROM ORDER_ITEMS i2 WHERE i2.PRODUCT_ID = p.PRODUCT_ID AND i2.ORDER_ID = ?)";
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, orderId);
            ps.setLong(2, orderId);
            return ps.executeUpdate();
        }
    }
}

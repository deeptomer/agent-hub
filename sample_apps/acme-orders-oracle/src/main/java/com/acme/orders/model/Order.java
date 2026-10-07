package com.acme.orders.model;

import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

public class Order {
    private long orderId;
    private long customerId;
    private Timestamp orderDate;
    private String status;
    private BigDecimal totalAmount;

    public static Order fromResultSet(ResultSet rs) throws SQLException {
        Order o = new Order();
        o.orderId = rs.getLong("ORDER_ID");
        o.customerId = rs.getLong("CUSTOMER_ID");
        o.orderDate = rs.getTimestamp("ORDER_DATE");
        o.status = rs.getString("STATUS");
        o.totalAmount = rs.getBigDecimal("TOTAL_AMOUNT");
        return o;
    }

    public long getOrderId() { return orderId; }
    public long getCustomerId() { return customerId; }
    public Timestamp getOrderDate() { return orderDate; }
    public String getStatus() { return status; }
    public BigDecimal getTotalAmount() { return totalAmount; }
}
